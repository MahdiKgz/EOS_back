import * as snmp from "net-snmp";
import { isIP } from "node:net";
import { pollSnmpv3, type SnmpSecret } from "./snmpv3";
import { addMeasurement } from "./monitoring-measurements";
import type { Measurement } from "./monitoring.types";
const roots = {
  cpu: "1.3.6.1.2.1.25.3.3.1.2",
  storage: "1.3.6.1.2.1.25.2.3.1",
  interfaces: "1.3.6.1.2.1.31.1.1.1",
};
export function snmpNumber(value: snmp.VarbindValue): number | null {
  if (Buffer.isBuffer(value)) {
    if (value.length > 8 || !value.length) return null;
    let result = 0n;
    for (const byte of value) result = (result << 8n) | BigInt(byte);
    return result <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(result) : null;
  }
  if (typeof value === "bigint")
    return value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
export function snmpMeasurements(
  tables: Record<keyof typeof roots, snmp.Varbind[]>,
): Measurement[] {
  const measurements: Measurement[] = [],
    loads = tables.cpu
      .map((v) => snmpNumber(v.value))
      .filter((v): v is number => v !== null && v <= 100);
  if (loads.length)
    addMeasurement(
      measurements,
      "cpu.usage_percent",
      loads.reduce((s, v) => s + v, 0) / loads.length,
      "percent",
    );
  const table = (name: "storage" | "interfaces") => {
    const result = new Map<string, Map<number, snmp.VarbindValue>>();
    for (const item of tables[name]) {
      if (!item.oid.startsWith(roots[name] + ".")) continue;
      const parts = item.oid.slice(roots[name].length + 1).split(".");
      if (parts.length !== 2 || !/^\d+$/.test(parts[1])) continue;
      const row = result.get(parts[1]) ?? new Map<number, snmp.VarbindValue>();
      row.set(Number(parts[0]), item.value);
      result.set(parts[1], row);
    }
    return [...result.entries()];
  };
  const text = (value: snmp.VarbindValue) =>
    typeof value === "string" || Buffer.isBuffer(value)
      ? String(value)
          .split("")
          .filter((char) => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127)
          .join("")
          .slice(0, 100)
      : "";
  for (const [index, row] of table("storage").slice(0, 16)) {
    const type = text(row.get(2)),
      label = (text(row.get(3)) || "storage") + " #" + index,
      allocation = snmpNumber(row.get(4)),
      size = snmpNumber(row.get(5)),
      used = snmpNumber(row.get(6));
    const key =
      type === "1.3.6.1.2.1.25.2.1.2" ? "memory" : type === "1.3.6.1.2.1.25.2.1.4" ? "disk" : null;
    if (
      !key ||
      !allocation ||
      !size ||
      used === null ||
      used > size ||
      !Number.isSafeInteger(size * allocation)
    )
      continue;
    addMeasurement(measurements, key + ".usage_percent", (used / size) * 100, "percent", label);
    addMeasurement(measurements, key + ".total_bytes", size * allocation, "bytes", label);
    addMeasurement(measurements, key + ".used_bytes", used * allocation, "bytes", label);
  }
  for (const [index, row] of table("interfaces").slice(0, 32)) {
    // Include ifIndex so equal/truncated names cannot merge different interfaces.
    const label = (text(row.get(1)) || "if") + " #" + index;
    addMeasurement(
      measurements,
      "network.rx_bytes",
      snmpNumber(row.get(6)),
      "bytes",
      label,
      "counter",
    );
    addMeasurement(
      measurements,
      "network.tx_bytes",
      snmpNumber(row.get(10)),
      "bytes",
      label,
      "counter",
    );
  }
  return measurements;
}
export async function collectSnmpMonitoring(host: string, port: number, secret: SnmpSecret) {
  const base = await pollSnmpv3(host, port, secret),
    measurements: Measurement[] = [],
    warnings: string[] = [];
  addMeasurement(measurements, "system.uptime_seconds", base.uptimeSeconds, "seconds");
  addMeasurement(measurements, "interfaces.count", base.interfaceCount, "count");
  const session = snmp.createV3Session(
    host,
    {
      name: secret.username,
      level: snmp.SecurityLevel.authPriv,
      authProtocol:
        secret.authProtocol === "SHA256" ? snmp.AuthProtocols.sha256 : snmp.AuthProtocols.sha,
      authKey: secret.authPassword,
      privProtocol: snmp.PrivProtocols.aes,
      privKey: secret.privacyPassword,
    },
    { port, retries: 0, timeout: 3500, transport: isIP(host) === 6 ? "udp6" : "udp4" },
  );
  const walk = (name: keyof typeof roots) =>
    new Promise<snmp.Varbind[]>((resolve) => {
      const values: snmp.Varbind[] = [];
      let finished = false;
      const finish = (partial = false) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        if (partial) warnings.push("SNMP_" + name.toUpperCase() + "_PARTIAL");
        resolve(values);
      };
      const timer = setTimeout(() => finish(true), 12000);
      session.subtree(
        roots[name],
        10,
        (bindings) => {
          if (finished) return true;
          for (const binding of bindings)
            if (
              !snmp.isVarbindError(binding) &&
              binding.oid.startsWith(roots[name] + ".") &&
              values.length < 512
            )
              values.push(binding);
          if (values.length >= 512) {
            finish(true);
            return true;
          }
          return false;
        },
        (error) => finish(!!error),
      );
    });
  try {
    const [cpu, storage, interfaces] = await Promise.all([
      walk("cpu"),
      walk("storage"),
      walk("interfaces"),
    ]);
    measurements.push(...snmpMeasurements({ cpu, storage, interfaces }));
    if (measurements.length <= 2) warnings.push("SNMP_BASIC_METRICS");
    return { measurements, warnings };
  } finally {
    session.close();
  }
}
