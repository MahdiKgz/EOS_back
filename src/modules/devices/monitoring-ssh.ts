import { collectFortiInventory } from "./fortigate-collector";
import { collectCiscoInventory } from "./cisco-collector";
import { collectEsxiSshInventory } from "./esxi-ssh-collector";
import type { Device } from "./device.entity";
import { runLinuxSsh, type SshCredentials } from "./linux-ssh";
import { runSshCommand } from "./ssh-transport";
import { addMeasurement, routerOsUptime, apiMeasurements } from "./monitoring-measurements";
import type { Measurement } from "./monitoring.types";

// The script and every CLI command below are fixed, read-only server code.
export const LINUX_MONITOR_SCRIPT = `test "$(uname -s)" = Linux || exit 1
export LC_ALL=C
printf 'EOSNET_STAT_A\\n'; head -n 1 /proc/stat
sleep 0.2
printf 'EOSNET_STAT_B\\n'; head -n 1 /proc/stat
printf 'EOSNET_MEMORY\\n'; cat /proc/meminfo
printf 'EOSNET_UPTIME\\n'; cat /proc/uptime
printf 'EOSNET_CORES\\n'; getconf _NPROCESSORS_ONLN
printf 'EOSNET_DISK\\n'; df -P -B1 /
printf 'EOSNET_NETWORK\\n'; cat /proc/net/dev
printf 'EOSNET_END\\n'`;
function number(value: string | undefined): number | null {
  if (!value?.trim()) return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
}
function section(output: string, name: string) {
  return (
    new RegExp(`^EOSNET_${name}\\r?\\n([\\s\\S]*?)(?=^EOSNET_|$(?![\\s\\S]))`, "m").exec(
      output,
    )?.[1] ?? ""
  );
}
export function parseLinuxMonitoring(output: string): Measurement[] {
  if (!/^EOSNET_END\r?$/m.test(output)) throw new Error("MONITOR_INVALID_RESPONSE");
  const values: Measurement[] = [];
  const cpu = (name: string) => section(output, name).trim().split(/\s+/).slice(1, 9).map(Number);
  const a = cpu("STAT_A"),
    b = cpu("STAT_B");
  if (a.length === 8 && b.length === 8 && [...a, ...b].every(Number.isSafeInteger)) {
    const delta = b.map((v, i) => v - a[i]),
      total = delta.reduce((sum, v) => sum + v, 0);
    if (total > 0 && delta.every((v) => v >= 0))
      addMeasurement(
        values,
        "cpu.usage_percent",
        (1 - (delta[3] + delta[4]) / total) * 100,
        "percent",
      );
  }
  const memory = Object.fromEntries(
    [...section(output, "MEMORY").matchAll(/^(\w+):\s+(\d+) kB$/gm)].map((m) => [
      m[1],
      Number(m[2]) * 1024,
    ]),
  );
  const free =
    memory.MemAvailable ??
    (memory.MemFree !== undefined && memory.Buffers !== undefined && memory.Cached !== undefined
      ? memory.MemFree + memory.Buffers + memory.Cached
      : null);
  if (memory.MemTotal > 0 && free !== null && free <= memory.MemTotal) {
    addMeasurement(values, "memory.usage_percent", (1 - free / memory.MemTotal) * 100, "percent");
    addMeasurement(values, "memory.total_bytes", memory.MemTotal, "bytes");
    addMeasurement(values, "memory.used_bytes", memory.MemTotal - free, "bytes");
  }
  addMeasurement(
    values,
    "system.uptime_seconds",
    number(section(output, "UPTIME").trim().split(/\s+/)[0]),
    "seconds",
  );
  addMeasurement(values, "cpu.total_cores", number(section(output, "CORES")), "count");
  const disk = section(output, "DISK").trim().split(/\n/).at(-1)?.trim().split(/\s+/);
  if (disk && disk.length >= 6) {
    const total = number(disk[1]),
      used = number(disk[2]);
    if (total && used !== null && used <= total) {
      addMeasurement(values, "disk.usage_percent", (used / total) * 100, "percent", "/");
      addMeasurement(values, "disk.total_bytes", total, "bytes", "/");
      addMeasurement(values, "disk.used_bytes", used, "bytes", "/");
    }
  }
  for (const line of section(output, "NETWORK")
    .split(/\n/)
    .filter((line) => line.includes(":"))
    .slice(0, 32)) {
    const [name, data] = line.split(":");
    const parts = data.trim().split(/\s+/);
    if (name.trim() === "lo" || parts.length !== 16) continue;
    addMeasurement(values, "network.rx_bytes", number(parts[0]), "bytes", name.trim(), "counter");
    addMeasurement(values, "network.tx_bytes", number(parts[8]), "bytes", name.trim(), "counter");
  }
  return values;
}
function routerSize(value: string | undefined) {
  const match = value?.match(/^(\d+(?:\.\d+)?)\s*(B|KiB|MiB|GiB)?$/i);
  return match
    ? Number(match[1]) *
        ({ b: 1, kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3 }[match[2]?.toLowerCase() ?? "b"] ?? 1)
    : null;
}
export function parseCliMonitoring(type: Device["type"], output: string): Measurement[] {
  const values: Measurement[] = [];
  if (type === "mikrotik") {
    const fields = Object.fromEntries(
      [...output.matchAll(/^\s*([\w-]+):\s*(.*?)\s*$/gm)].map((m) => [m[1], m[2]]),
    );
    addMeasurement(
      values,
      "cpu.usage_percent",
      number(fields["cpu-load"]?.replace(/%$/, "")),
      "percent",
    );
    addMeasurement(values, "cpu.total_cores", number(fields["cpu-count"]), "count");
    addMeasurement(values, "system.uptime_seconds", routerOsUptime(fields.uptime ?? ""), "seconds");
    for (const [prefix, freeKey, totalKey] of [
      ["memory", "free-memory", "total-memory"],
      ["disk", "free-hdd-space", "total-hdd-space"],
    ]) {
      const free = routerSize(fields[freeKey]),
        total = routerSize(fields[totalKey]);
      if (total && free !== null && free <= total) {
        addMeasurement(values, prefix + ".usage_percent", (1 - free / total) * 100, "percent");
        addMeasurement(values, prefix + ".total_bytes", total, "bytes");
        addMeasurement(values, prefix + ".used_bytes", total - free, "bytes");
      }
    }
  } else if (type === "cisco") {
    addMeasurement(
      values,
      "cpu.usage_percent",
      number(output.match(/CPU utilization for five seconds:\s*([\d.]+)%/i)?.[1]),
      "percent",
    );
  } else if (type === "fortigate") {
    const idle = number(output.match(/CPU states:[^\r\n]*?([\d.]+)%?\s*idle/i)?.[1]);
    addMeasurement(values, "cpu.usage_percent", idle === null ? null : 100 - idle, "percent");
    addMeasurement(
      values,
      "memory.usage_percent",
      number(output.match(/^Memory:.*?\(([\d.]+)%\)\s*used/im)?.[1]),
      "percent",
    );
    addMeasurement(
      values,
      "sessions.count",
      number(output.match(/^Average sessions:\s*(\d+)/im)?.[1]),
      "count",
    );
  } else if (type === "esxi") {
    addMeasurement(
      values,
      "memory.total_bytes",
      number(output.match(/^\s*Physical Memory:\s*(\d+)\s*Bytes/im)?.[1]),
      "bytes",
    );
  }
  return values;
}
export async function collectSshMonitoring(device: Device, credentials: SshCredentials) {
  if (device.type === "cisco") {
    const report = await collectCiscoInventory(device, credentials),
      values: Measurement[] = [];
    if (!report.collection) return { measurements: values, warnings: report.warnings };
    addMeasurement(
      values,
      "cpu.usage_percent",
      report.collection.health.cpu?.fiveSeconds,
      "percent",
    );
    for (const pool of report.collection.health.memory) {
      addMeasurement(
        values,
        "memory.usage_percent",
        (pool.usedBytes / pool.totalBytes) * 100,
        "percent",
        pool.name,
      );
      addMeasurement(values, "memory.total_bytes", pool.totalBytes, "bytes", pool.name);
      addMeasurement(values, "memory.used_bytes", pool.usedBytes, "bytes", pool.name);
    }
    for (const counter of report.collection.interfaceCounters) {
      addMeasurement(values, "network.rx_bytes", counter.rxBytes, "bytes", counter.name, "counter");
      addMeasurement(values, "network.tx_bytes", counter.txBytes, "bytes", counter.name, "counter");
    }
    return { measurements: values, warnings: report.warnings };
  }
  if (device.type === "fortigate") {
    const report = await collectFortiInventory(device, credentials),
      measurements: Measurement[] = [];
    if (!report.collection) return { measurements, warnings: report.warnings };
    const { health, interfaceCounters } = report.collection;
    addMeasurement(measurements, "cpu.usage_percent", health.cpuUsagePercent, "percent");
    addMeasurement(measurements, "memory.usage_percent", health.memoryUsagePercent, "percent");
    addMeasurement(measurements, "memory.total_bytes", health.memoryTotalBytes, "bytes");
    addMeasurement(measurements, "memory.used_bytes", health.memoryUsedBytes, "bytes");
    addMeasurement(measurements, "sessions.count", health.sessionCount, "count");
    addMeasurement(measurements, "system.uptime_seconds", health.uptimeSeconds, "seconds");
    for (const row of interfaceCounters) {
      addMeasurement(measurements, "network.rx_bytes", row.rxBytes, "bytes", row.name, "counter");
      addMeasurement(measurements, "network.tx_bytes", row.txBytes, "bytes", row.name, "counter");
    }
    return { measurements, warnings: report.warnings };
  }
  if (device.type === "esxi") {
    const inventory = await collectEsxiSshInventory(device, credentials);
    return {
      measurements: apiMeasurements({ ...inventory, kind: "esxi" }),
      warnings: [
        "SSH_PARTIAL_METRICS",
        ...(inventory.coverage?.filter((c) => c.status === "unavailable").length
          ? ["ESXI_SSH_PARTIAL_INVENTORY"]
          : []),
      ],
    };
  }
  if (device.type === "linux_edge") {
    const output = await runSshCommand(device, credentials, LINUX_MONITOR_SCRIPT, {
      timeout: 15000,
    });
    return {
      measurements: parseLinuxMonitoring(output.toString("utf8")),
      warnings: [] as string[],
    };
  }
  // Validate the real platform before parsing vendor-specific output.
  await runLinuxSsh(device, { ...credentials, operation: "verify" });
  const result = await runLinuxSsh(device, { ...credentials, operation: "monitoring" });
  return {
    measurements: parseCliMonitoring(device.type, result.output),
    warnings: ["SSH_PARTIAL_METRICS"],
  };
}
