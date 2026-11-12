import type { ApiInventory } from "./vendor-api-collector";
import type { Measurement } from "./monitoring.types";
export function addMeasurement(
  target: Measurement[],
  key: string,
  value: number | null | undefined,
  unit: string,
  label = "",
  kind: Measurement["kind"] = "gauge",
) {
  if (value === null || value === undefined || !Number.isFinite(value)) return;
  if (key.endsWith("_percent") && (value < 0 || value > 100)) return;
  if (kind === "counter" && (!Number.isSafeInteger(value) || value < 0)) return;
  target.push({ key, value, unit, label: label.slice(0, 128), kind });
}
function capacity(
  target: Measurement[],
  key: string,
  free: number | null,
  total: number | null,
  label = "",
) {
  if (free === null || total === null || total <= 0 || free < 0 || free > total) return;
  addMeasurement(target, key + ".usage_percent", (1 - free / total) * 100, "percent", label);
  addMeasurement(target, key + ".total_bytes", total, "bytes", label);
  addMeasurement(target, key + ".used_bytes", total - free, "bytes", label);
}
export function apiMeasurements(report: ApiInventory): Measurement[] {
  const values: Measurement[] = [];
  if (report.kind === "esxi") {
    addMeasurement(values, "cpu.usage_percent", report.cpuPercent, "percent");
    addMeasurement(values, "memory.usage_percent", report.memoryPercent, "percent");
    addMeasurement(values, "cpu.total_cores", report.cpuCores, "count");
    addMeasurement(values, "memory.total_bytes", report.memoryBytes, "bytes");
    addMeasurement(values, "vm.count", report.vmCount, "count");
    if (report.bootTime && Number.isFinite(Date.parse(report.bootTime)))
      addMeasurement(
        values,
        "system.uptime_seconds",
        Math.max(0, (Date.parse(report.collectedAt) - Date.parse(report.bootTime)) / 1000),
        "seconds",
      );
    for (const datastore of report.datastores.slice(0, 16))
      capacity(values, "datastore", datastore.freeBytes, datastore.capacityBytes, datastore.name);
    for (const counter of report.interfaceCounters?.slice(0, 32) ?? []) {
      addMeasurement(values, "network.rx_bytes", counter.rxBytes, "bytes", counter.name, "counter");
      addMeasurement(values, "network.tx_bytes", counter.txBytes, "bytes", counter.name, "counter");
    }
    for (const sensor of report.sensors.slice(0, 16))
      addMeasurement(
        values,
        "sensor.reading",
        sensor.reading,
        sensor.unit.slice(0, 16),
        sensor.name,
      );
  } else if (report.kind === "mikrotik") {
    addMeasurement(values, "cpu.usage_percent", report.cpuLoad, "percent");
    addMeasurement(values, "cpu.total_cores", report.cpuCount, "count");
    capacity(values, "memory", report.memoryFree, report.memoryTotal);
    capacity(values, "disk", report.storageFree, report.storageTotal);
    const uptime = routerOsUptime(report.uptime);
    addMeasurement(values, "system.uptime_seconds", uptime, "seconds");
    for (const counter of report.interfaceCounters.slice(0, 32)) {
      addMeasurement(values, "network.rx_bytes", counter.rxBytes, "bytes", counter.name, "counter");
      addMeasurement(values, "network.tx_bytes", counter.txBytes, "bytes", counter.name, "counter");
    }
  } else {
    if (report.collectedModules?.includes("Interface")) {
      addMeasurement(
        values,
        "interfaces.up_count",
        report.interfaces.filter((item) => item.operationalStatus === "up").length,
        "count",
      );
      addMeasurement(
        values,
        "interfaces.down_count",
        report.interfaces.filter((item) => item.operationalStatus === "down").length,
        "count",
      );
    }
  }
  return values;
}
export function routerOsUptime(value: string): number | null {
  if (!value) return null;
  const units: Record<string, number> = { w: 604800, d: 86400, h: 3600, m: 60, s: 1 };
  const matches = [...value.matchAll(/(\d+)([wdhms])/g)];
  if (matches.map((item) => item[0]).join("") !== value) return null;
  return matches.reduce((sum, item) => sum + Number(item[1]) * units[item[2]], 0);
}
