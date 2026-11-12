import type { Device } from "./device.entity";
import type { EsxiDiscovery } from "./esxi-inventory";
import { EsxiSoapError } from "./esxi-soap";

// Fixed read-only commands: neither user input nor AI text becomes shell code.
export const ESXI_SSH_READ_COMMANDS = {
  identity: "vmware -v",
  summary: "vim-cmd hostsvc/hostsummary",
  hostname: "esxcli system hostname get",
  hardware: "esxcli hardware platform get",
  memory: "esxcli hardware memory get",
  cpu: "esxcli hardware cpu global get",
  maintenance: "esxcli system maintenanceMode get",
  datastores: "esxcli --formatter=csv storage filesystem list",
  nics: "esxcli --formatter=csv network nic list",
  vmkernel: "esxcli --formatter=csv network ip interface ipv4 get",
  portgroups: "esxcli --formatter=csv network vswitch standard portgroup list",
  switches: "esxcli --formatter=csv network vswitch standard list",
  dns: "esxcli network ip dns server list",
  ntp: "esxcli system ntp get",
  services: "vim-cmd hostsvc/service_info",
  adapters: "esxcli --formatter=csv storage core adapter list",
  firewall: "esxcli --formatter=csv network firewall ruleset list",
} as const;
export type EsxiSshOutputs = Partial<Record<keyof typeof ESXI_SSH_READ_COMMANDS, string>>;
const numeric = (v: string | undefined) => {
  if (!v?.trim()) return null;
  const n = Number(v.trim());
  return Number.isFinite(n) && n >= 0 && n <= Number.MAX_SAFE_INTEGER ? n : null;
};
const percentage = (used: number | null, total: number | null) =>
  used !== null && total !== null && total > 0 && used <= total
    ? Math.round((used / total) * 1000) / 10
    : null;
// Extract typed VIM blocks without eval or interpreting any host output as code.
export function vimBlocks(text: string, type: string): string[] {
  const result: string[] = [];
  const marker = `(${type}) {`;
  let cursor = 0;
  while (result.length < 100) {
    const start = text.indexOf(marker, cursor);
    if (start < 0) break;
    let depth = 1,
      quoted = false,
      escaped = false,
      i = start + marker.length;
    const contentStart = i;
    for (; i < text.length; i++) {
      const c = text[i];
      if (quoted) {
        if (escaped) escaped = false;
        else if (c === "\\") escaped = true;
        else if (c === '"') quoted = false;
      } else if (c === '"') quoted = true;
      else if (c === "{") depth++;
      else if (c === "}" && --depth === 0) break;
    }
    if (depth !== 0) break;
    result.push(text.slice(contentStart, i));
    cursor = i + 1;
  }
  return result;
}
function vimNumber(text: string, key: string) {
  return numeric(new RegExp(String.raw`^\s*${key}\s*=\s*(-?\d+)\s*,?\s*$`, "m").exec(text)?.[1]);
}
function vimString(text: string, key: string) {
  const raw = new RegExp(String.raw`^\s*${key}\s*=\s*("(?:[^"\\]|\\.)*")\s*,?\s*$`, "m").exec(
    text,
  )?.[1];
  try {
    return raw ? String(JSON.parse(raw)).slice(0, 512) : "";
  } catch {
    return "";
  }
}
function vimBoolean(text: string, key: string): boolean | null {
  const raw = new RegExp(String.raw`^\s*${key}\s*=\s*(true|false)\s*,?\s*$`, "m").exec(text)?.[1];
  return raw === "true" ? true : raw === "false" ? false : null;
}
export function esxiNicStatsCommand(name: string) {
  if (!/^vmnic\d{1,4}$/.test(name))
    throw new EsxiSoapError(
      "ESXI_NIC_INVALID",
      "Only discovered physical NIC names are supported.",
    );
  return `esxcli network nic stats get -n ${name}`;
}
export function parseEsxiNicStats(name: string, text: string) {
  esxiNicStatsCommand(name);
  const data = labels(text);
  return { name, rxBytes: numeric(data["Bytes received"]), txBytes: numeric(data["Bytes sent"]) };
}
function labels(text: string) {
  return Object.fromEntries(
    text.split(/\r?\n/).flatMap((line) => {
      const m = /^\s*([^:]+):\s*(.*?)\s*$/.exec(line);
      return m ? [[m[1]!.trim(), m[2]!.slice(0, 512)]] : [];
    }),
  );
}
// ESXCLI CSV supports quoted values, escaped quotes, CRLF and trailing commas.
export function esxiCsv(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let row: string[] = [],
    cell = "",
    quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '"') {
      if (quoted && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else quoted = !quoted;
    } else if (!quoted && (c === "," || c === "\n")) {
      row.push(cell.replace(/\r$/, ""));
      cell = "";
      if (c === "\n") {
        if (row.some((v) => v.trim())) rows.push(row);
        row = [];
      }
    } else cell += c;
  }
  if (quoted) throw new EsxiSoapError("ESXI_SSH_CSV_INVALID", "ESXi returned incomplete CSV.");
  if (cell || row.length) {
    row.push(cell.replace(/\r$/, ""));
    rows.push(row);
  }
  const headers =
    rows.shift()?.map((v) =>
      v
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]/g, ""),
    ) ?? [];
  return rows.map((values) =>
    Object.fromEntries(
      headers
        .filter(Boolean)
        .map((key) => [key, values[headers.indexOf(key)]?.trim().slice(0, 512) ?? ""]),
    ),
  );
}
export function parseEsxiSshInventory(
  outputs: EsxiSshOutputs,
  device: Pick<Device, "id" | "host">,
): EsxiDiscovery {
  const identity = /^\s*VMware ESXi\s+([\d.]+)\s+build-([\d]+)\s*$/m.exec(outputs.identity ?? "");
  if (!identity)
    throw new EsxiSoapError(
      "ESXI_SSH_PLATFORM_MISMATCH",
      "SSH is reachable but the target did not identify itself as VMware ESXi.",
    );
  const host = labels(outputs.hostname ?? ""),
    hardware = labels(outputs.hardware ?? "");
  const memory = labels(outputs.memory ?? ""),
    cpu = labels(outputs.cpu ?? "");
  const coverage = Object.keys(ESXI_SSH_READ_COMMANDS).map((key) => ({
    key,
    status:
      outputs[key as keyof EsxiSshOutputs] === undefined
        ? ("unavailable" as const)
        : ("available" as const),
  }));
  const csv = (key: keyof EsxiSshOutputs) => {
    try {
      const text = outputs[key] ?? "";
      const headers = text
        .split(/\r?\n/, 1)[0]!
        .toLowerCase()
        .replace(/[^a-z0-9,]/g, "")
        .split(",");
      const required: Partial<Record<keyof EsxiSshOutputs, string>> = {
        datastores: "type",
        nics: "name",
        vmkernel: "name",
        portgroups: "name",
        switches: "name",
        adapters: "driver",
        firewall: "enabled",
      };
      if (!headers.includes(required[key] ?? "name")) throw new Error("Unknown ESXCLI schema");
      const items = esxiCsv(text);
      if (items.length > 100) coverage.find((item) => item.key === key)!.status = "unavailable";
      return items.slice(0, 100);
    } catch {
      coverage.find((item) => item.key === key)!.status = "unavailable";
      return [];
    }
  };
  const summary = outputs.summary ?? "";
  const quick = vimBlocks(summary, "vim.host.Summary.QuickStats")[0] ?? "";
  const capacities = vimBlocks(summary, "vim.host.Summary.HardwareSummary")[0] ?? "";
  const memoryBytes =
    numeric(memory["Physical Memory"]?.replace(/\s+Bytes$/i, "")) ??
    vimNumber(capacities, "memorySize");
  const cpuCores = numeric(cpu["CPU Cores"]) ?? vimNumber(capacities, "numCpuCores");
  const cpuMhz = vimNumber(capacities, "cpuMhz");
  const cpuPercent = percentage(
    vimNumber(quick, "overallCpuUsage"),
    cpuMhz !== null && cpuCores !== null ? cpuMhz * cpuCores : null,
  );
  const memoryPercent = percentage(
    vimNumber(quick, "overallMemoryUsage"),
    memoryBytes !== null ? memoryBytes / 1024 ** 2 : null,
  );
  if (!quick) coverage.find((item) => item.key === "summary")!.status = "unavailable";
  const filesystems = csv("datastores");
  const datastores = filesystems.filter((v) =>
    /^(VMFS(?:-?\d+)?|NFS(?:-?[\d.]+)?|vsan)$/i.test(v.type ?? ""),
  );
  const nics = csv("nics"),
    vmkernel = csv("vmkernel");
  const portgroups = csv("portgroups")
    .map((v) => ({
      name: v.name ?? "",
      vlanId: numeric(v.vlanid),
      vSwitch: v.virtualswitch ?? v.vswitch ?? "",
    }))
    .filter((v) => v.name);
  const services = vimBlocks(outputs.services ?? "", "vim.host.Service")
    .map((block) => ({
      key: vimString(block, "key"),
      label: vimString(block, "label"),
      running: vimBoolean(block, "running"),
      required: vimBoolean(block, "required"),
      policy: vimString(block, "policy"),
    }))
    .filter((item) => item.key);
  if (
    outputs.services !== undefined &&
    !services.length &&
    !/service\s*=\s*\(vim.host.Service\)\s*\[\s*\]/.test(outputs.services)
  )
    coverage.find((item) => item.key === "services")!.status = "unavailable";
  const ntp = labels(outputs.ntp ?? "");
  const dns = labels(outputs.dns ?? "");
  if (dns["DNSServers"] === undefined && dns["DNS Servers"] === undefined)
    coverage.find((item) => item.key === "dns")!.status = "unavailable";
  if (ntp["NTP Servers"] === undefined)
    coverage.find((item) => item.key === "ntp")!.status = "unavailable";
  const list = (text: string) =>
    text
      .split(/[,\s]+/)
      .filter((item) => item && item !== "<unset>")
      .slice(0, 16);
  return {
    transport: "ssh",
    hostId: device.id,
    hostname: host["Fully Qualified Domain Name"] || host["Host Name"] || "",
    version: identity[1]!,
    build: identity[2]!,
    model: hardware["Product Name"] || "",
    hardwareVendor: hardware["Vendor Name"] || "",
    serialNumber: hardware["Serial Number"] || "",
    biosVersion: "",
    lockdownMode: "",
    connectionState: "connected",
    overallStatus: "unknown",
    maintenanceMode: /^Enabled\s*$/i.test(outputs.maintenance?.trim() ?? "")
      ? true
      : /^Disabled\s*$/i.test(outputs.maintenance?.trim() ?? "")
        ? false
        : null,
    bootTime: null,
    cpuPercent,
    memoryPercent,
    cpuCores,
    memoryBytes,
    vmCount: null,
    vms: [],
    vmsTruncated: false,
    datastores: datastores.map((v) => ({
      id: v.uuid || v.mountpoint || v.volumename || "",
      name: v.volumename || v.mountpoint || "",
      capacityBytes: numeric(v.size),
      freeBytes: numeric(v.free),
      accessible: v.mounted === "true" ? true : v.mounted === "false" ? false : null,
    })),
    datastoreCount:
      coverage.find((item) => item.key === "datastores")!.status === "unavailable"
        ? null
        : datastores.length,
    networks: portgroups.map((v) => v.name),
    sensors: [],
    services,
    storageAdapters: csv("adapters")
      .map((v) => ({
        name: v.hbaname ?? v.name ?? "",
        model: v.description ?? "",
        driver: v.driver ?? "",
        status: v.linkstate ?? "",
      }))
      .filter((v) => v.name),
    storageDevices: [],
    firewallRulesets: csv("firewall")
      .map((v) => ({
        key: v.name ?? v.ruleset ?? "",
        label: v.name ?? v.ruleset ?? "",
        enabled: /^true$/i.test(v.enabled ?? "")
          ? true
          : /^false$/i.test(v.enabled ?? "")
            ? false
            : null,
        required: null,
      }))
      .filter((v) => v.key),
    physicalNics: nics
      .filter((v) => v.name)
      .map((v) => ({
        name: v.name!,
        linkUp: /^Up$/i.test(v.linkstatus ?? "")
          ? true
          : /^Down$/i.test(v.linkstatus ?? "")
            ? false
            : null,
        speedMb: numeric(v.speed),
      })),
    vmkernelNics: vmkernel
      .filter((v) => v.name)
      .map((v) => ({ name: v.name!, ip: v.ipv4address ?? "" })),
    virtualSwitches: csv("switches")
      .map((v) => ({ name: v.name ?? "", ports: numeric(v.numports ?? v.ports) }))
      .filter((v) => v.name),
    portGroups: portgroups,
    dns: {
      hostName: host["Host Name"] || "",
      domainName: host["Domain Name"] || "",
      servers: list(dns["DNSServers"] ?? dns["DNS Servers"] ?? ""),
    },
    time: {
      ntpServers: list(ntp["NTP Servers"] ?? ""),
      lastSyncTime: null,
      protocol: outputs.ntp === undefined ? "" : "ntp",
    },
    coverage,
    interfaceCounters: [],
    serviceSystemId: null,
    dateTimeSystemId: null,
    collectedAt: new Date().toISOString(),
  };
}
