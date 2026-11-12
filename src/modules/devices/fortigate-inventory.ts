import { parseFortiSdwan } from "./fortigate-cluster";
import { parseFortiLogs } from "./fortigate-logs";
export const FORTIGATE_READ_COMMANDS = {
  system: "get system status",
  performance: "get system performance status",
  interfaces: "show system interface",
  physical: "get system interface physical",
  counters: "diagnose netlink interface list",
  processes: "diagnose sys top-summary",
  routes: "get router info routing-table all",
  staticRoutes: "show router static",
  centralSnat: "show firewall central-snat-map",
  dns: "get system dns",
  dnsConfig: "show system dns",
  fortiguard: "show system fortiguard",
  admins: "show system admin",
  zones: "show system zone",
  policies: "show firewall policy",
  addresses: "show firewall address",
  addressGroups: "show firewall addrgrp",
  services: "show firewall service custom",
  serviceGroups: "show firewall service group",
  schedules: "show firewall schedule recurring",
  vips: "show firewall vip",
  vipGroups: "show firewall vipgrp",
  ipPools: "show firewall ippool",
  ipsecSummary: "get vpn ipsec tunnel summary",
  ipsecStatus: "diagnose vpn tunnel list",
  sslMonitor: "get vpn ssl monitor",
  phase1: "show vpn ipsec phase1-interface",
  phase2: "show vpn ipsec phase2-interface",
  sslSettings: "show vpn ssl settings",
  ha: "get system ha status",
  haConfig: "show system ha",
  sdwan: "show system sdwan",
  vdoms: "show system vdom",
  vdomProperties: "show system vdom-property",
  arp: "get system arp",
  arpDiagnostic: "diagnose ip arp list",
  neighbors: "diagnose user device list",
  logs: "execute log display",
} as const;
export type FortiCommandId = keyof typeof FORTIGATE_READ_COMMANDS;
export type FortiCommandState =
  | "collected"
  | "partial"
  | "not_supported"
  | "requires_privilege"
  | "command_failed"
  | "not_collected";
export type FortiEvidence = {
  commandId: FortiCommandId;
  state: FortiCommandState;
  lineCount: number;
  errorCode?: string;
  evidence: string[];
};
export type FortiTable = {
  key: string;
  title: string;
  columns: string[];
  rows: Record<string, string | number | boolean | null>[];
  sources: FortiCommandId[];
  state: FortiCommandState;
};
export type FortiBlock = { name: string; settings: Record<string, string[]> };
// Only top-level edit blocks and their own settings are projected. Nested dashboards/users are not assets.
export function parseFortiBlocks(text: string, maxRows = 256): FortiBlock[] {
  const rows: FortiBlock[] = [];
  let depth = 0,
    row: FortiBlock | undefined,
    rowDepth = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^config\s/.test(line)) {
      depth++;
      continue;
    }
    if (line === "end") {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (/^edit\s/.test(line) && depth <= 1 && !row) {
      const name = fortiTokens(line.slice(5))[0];
      if (name) {
        row = { name, settings: {} };
        rowDepth = depth;
      }
      continue;
    }
    if (line === "next" && row && depth === rowDepth) {
      rows.push(row);
      row = undefined;
      if (rows.length >= Math.min(4097, Math.max(1, maxRows))) break;
      continue;
    }
    const match = line.match(/^set\s+([\w-]+)\s+(.+)$/);
    if (row && depth === rowDepth && match) row.settings[match[1]] = fortiTokens(match[2]);
  }
  return rows;
}
export function fortiTokens(text: string) {
  return [...text.matchAll(/"((?:\\.|[^"\\])*)"|(\S+)/g)]
    .slice(0, 64)
    .map((m) => (m[1] ?? m[2]).replace(/\\(["\\])/g, "$1").slice(0, 512));
}
const setting = (row: FortiBlock, key: string) => row.settings[key]?.join(", ") ?? null;
const label = (text: string, key: string) =>
  text
    .split(/\r?\n/)
    .find((line) => line.toLowerCase().startsWith(key.toLowerCase() + ":"))
    ?.slice(key.length + 1)
    .trim()
    .slice(0, 512) ?? null;
function finite(raw: string | undefined, max = Number.MAX_SAFE_INTEGER) {
  if (raw === undefined || raw.trim() === "") return null;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 && n <= max ? n : null;
}
export function fortiIdentity(text: string) {
  const match = text.match(
    /^Version:\s*(FortiGate[^\s,]{0,80})\s+v?(\d+\.\d+(?:\.\d+)?),?\s*build(\d+)/im,
  );
  return {
    vendor: "fortigate" as const,
    platform: match ? "fortios" : "unknown",
    version: match?.[2] ?? null,
    model: match?.[1] ?? null,
    hostname: label(text, "Hostname"),
    confidence: match ? 1 : 0,
    evidence: text
      .split(/\r?\n/)
      .filter((line) => /^(?:Version|Hostname|Serial-Number):/i.test(line))
      .slice(0, 3),
    supported: !!match,
  };
}
export function fortiHealth(performance: string) {
  const cpuLine = performance.match(/^CPU states:(.*)$/im)?.[1] ?? "",
    idle = finite(cpuLine.match(/([\d.]+)%\s*idle/i)?.[1], 100);
  const cpu = idle === null ? null : 100 - idle;
  const memory = finite(
    performance.match(/^Memory:.*?used\s*\(([\d.]+)%\)/im)?.[1] ??
      performance.match(/^Memory:.*?\(([\d.]+)%\)\s*used/im)?.[1] ??
      performance.match(/^Memory:\s*([\d.]+)%/im)?.[1],
    100,
  );
  const totalKB = finite(performance.match(/^Memory:\s*(\d+)k\s*total/im)?.[1]),
    usedKB = finite(performance.match(/^Memory:.*?,\s*(\d+)k\s*used/im)?.[1]);
  const uptime = performance.match(
    /^Uptime:\s*(?:(\d+)\s*days?,?\s*)?(?:(\d+)\s*hours?,?\s*)?(?:(\d+)\s*minutes?,?\s*)?/im,
  );
  const seconds =
    uptime && uptime.slice(1).some((v) => v !== undefined)
      ? Number(uptime[1] ?? 0) * 86400 + Number(uptime[2] ?? 0) * 3600 + Number(uptime[3] ?? 0) * 60
      : null;
  return {
    cpuUsagePercent: cpu,
    memoryUsagePercent: memory,
    memoryTotalBytes: totalKB === null ? null : totalKB * 1024,
    memoryUsedBytes: usedKB === null || totalKB === null || usedKB > totalKB ? null : usedKB * 1024,
    sessionCount: finite(performance.match(/^Average sessions:\s*(\d+)/im)?.[1]),
    uptimeSeconds: seconds,
  };
}
export function fortiCounters(text: string) {
  return text
    .split(/(?:^|\n)(?=if=)/)
    .slice(0, 256)
    .flatMap((block) => {
      const name = block.match(/^if=([^\s]+)/)?.[1],
        rxBytes = finite(block.match(/\brxb=(\d+)/)?.[1]),
        txBytes = finite(block.match(/\btxb=(\d+)/)?.[1]);
      return name && rxBytes !== null && txBytes !== null ? [{ name, rxBytes, txBytes }] : [];
    });
}
export function buildFortiInventory(
  outputs: Partial<Record<FortiCommandId, string>>,
  commandEvidence: FortiEvidence[],
  warnings: string[],
) {
  const read = (id: FortiCommandId) => outputs[id] ?? "",
    blocks = (id: FortiCommandId) => parseFortiBlocks(read(id));
  const state = (sources: FortiCommandId[]): FortiCommandState => {
    const found = sources.map(
      (id) => commandEvidence.find((e) => e.commandId === id)?.state ?? "not_collected",
    );
    return found.every((s) => s === "collected")
      ? "collected"
      : found.some((s) => s === "collected" || s === "partial")
        ? "partial"
        : found.includes("requires_privilege")
          ? "requires_privilege"
          : found.every((s) => s === "not_supported")
            ? "not_supported"
            : "not_collected";
  };
  const table = (
    key: string,
    title: string,
    columns: string[],
    rows: FortiTable["rows"],
    sources: FortiCommandId[],
  ): FortiTable => ({
    key,
    title,
    columns,
    rows: rows.slice(0, 256),
    sources,
    state: state(sources),
  });
  const objectTable = (id: FortiCommandId, title: string, keys: string[]) => {
    const identifier = keys.includes("name") ? "id" : "name";
    return table(
      id,
      title,
      [identifier, ...keys],
      blocks(id).map((row) =>
        Object.fromEntries([
          [identifier, row.name],
          ...keys.map((key) => [key, setting(row, key)]),
        ]),
      ),
      [id],
    );
  };
  const sdwan = parseFortiSdwan(read("sdwan"));
  const sdwanTable = (key: string, title: string, section: string, fields: string[]) =>
    table(
      key,
      title,
      ["id", "name", ...fields],
      sdwan
        .filter((r) => r.settings.__section?.[0] === section)
        .slice(0, 256)
        .map((row) => ({
          id: row.name,
          name: row.settings.name?.join(" ") ?? row.name,
          ...Object.fromEntries(
            fields.map((field) => [field, row.settings[field]?.join(", ") ?? null]),
          ),
        })),
      ["sdwan"],
    );
  const interfaces = blocks("interfaces").map((row) => ({
    name: row.name,
    ip: setting(row, "ip"),
    vdom: setting(row, "vdom"),
    mode: setting(row, "mode"),
    type: setting(row, "type"),
    role: setting(row, "role"),
    allowaccess: setting(row, "allowaccess"),
    administrativeStatus: setting(row, "status"),
    vlanid: setting(row, "vlanid"),
    parent: setting(row, "interface"),
    alias: setting(row, "alias"),
  }));
  const summary = read("ipsecSummary").split(/\r?\n/),
    status = read("ipsecStatus").split(/\r?\n/),
    phase1 = blocks("phase1"),
    phase2 = blocks("phase2");
  const tunnelNames = new Set([
    ...phase1.map((row) => row.name),
    ...summary.flatMap((line) => {
      const name = line.match(/^\s*'([^']+)'/)?.[1];
      return name ? [name] : [];
    }),
  ]);
  const vpn = [...tunnelNames].slice(0, 256).map((name) => {
    const line = summary.find((line) => line.trimStart().startsWith("'" + name + "'")),
      selectors = line?.match(/selectors\(total,up\):\s*(\d+)\/(\d+)/i),
      diagnostic = status.find(
        (line) => line.startsWith("name=" + name + " ") || line.startsWith("name=" + name + "\t"),
      );
    const up = selectors
      ? Number(selectors[2]) > 0
      : diagnostic
        ? /\bstatus=up\b/.test(diagnostic)
        : null;
    return {
      name,
      status: up === null ? "unknown" : up ? "up" : "down",
      phase1: phase1.some((row) => row.name === name),
      phase2:
        phase2
          .filter((row) => row.settings["phase1name"]?.[0] === name)
          .map((row) => row.name)
          .join(", ") || null,
    };
  });
  const health = fortiHealth(read("performance"));
  const tables: FortiTable[] = [
    table(
      "interfaces",
      "رابط‌ها و دسترسی مدیریتی",
      [
        "name",
        "ip",
        "vdom",
        "mode",
        "type",
        "role",
        "allowaccess",
        "administrativeStatus",
        "vlanid",
        "parent",
        "alias",
      ],
      interfaces,
      ["interfaces"],
    ),
    table(
      "physical",
      "وضعیت فیزیکی رابط‌ها",
      ["name", "status", "speed", "duplex"],
      read("physical")
        .split(/==\s*\[/)
        .slice(1, 257)
        .map((block) => ({
          name: block.match(/^([^\]]+)/)?.[1]?.trim() ?? "",
          status: block.match(/\bstatus:\s*(up|down)/i)?.[1] ?? null,
          speed: block.match(/\bspeed:\s*([^\r\n]+)/i)?.[1]?.trim() ?? null,
          duplex: block.match(/\bduplex:\s*([^\r\n]+)/i)?.[1]?.trim() ?? null,
        })),
      ["physical"],
    ),
    sdwanTable("sdwanZones", "Zoneهای SD-WAN", "zone", ["service-sla-tie-break"]),
    sdwanTable("sdwanMembers", "اعضای SD-WAN", "members", [
      "interface",
      "zone",
      "gateway",
      "status",
    ]),
    sdwanTable("sdwanHealth", "بررسی سلامت SD-WAN", "health-check", [
      "server",
      "protocol",
      "members",
    ]),
    sdwanTable("sdwanRules", "قوانین SD-WAN", "service", [
      "mode",
      "priority-members",
      "src",
      "dst",
      "status",
    ]),
    table(
      "admins",
      "مدیران و محدودیت مبدا",
      ["name", "profile", "trustHosts"],
      blocks("admins").map((row) => ({
        name: row.name,
        profile: setting(row, "accprofile"),
        trustHosts:
          Object.entries(row.settings)
            .filter(([key]) => /^trusthost\d+$/.test(key))
            .map(([, value]) => value.join(" "))
            .join(", ") || null,
      })),
      ["admins"],
    ),
    objectTable("policies", "سیاست‌های فایروال", [
      "name",
      "srcintf",
      "dstintf",
      "srcaddr",
      "dstaddr",
      "service",
      "action",
      "nat",
      "status",
      "logtraffic",
    ]),
    objectTable("staticRoutes", "پیکربندی مسیرهای ثابت", [
      "dst",
      "gateway",
      "device",
      "status",
      "distance",
      "priority",
    ]),
    objectTable("centralSnat", "قوانین Central SNAT", [
      "srcintf",
      "dstintf",
      "orig-addr",
      "dst-addr",
      "nat",
      "status",
    ]),
    objectTable("addresses", "اشیای آدرس", ["type", "subnet", "fqdn", "associated-interface"]),
    objectTable("addressGroups", "گروه آدرس", ["member"]),
    objectTable("services", "سرویس‌ها", ["protocol", "tcp-portrange", "udp-portrange"]),
    objectTable("serviceGroups", "گروه سرویس", ["member"]),
    objectTable("schedules", "زمان‌بندی‌ها", ["day", "start", "end"]),
    objectTable("vips", "VIP و نگاشت مقصد", [
      "extip",
      "mappedip",
      "extintf",
      "portforward",
      "extport",
      "mappedport",
    ]),
    objectTable("vipGroups", "گروه VIP", ["interface", "member"]),
    objectTable("ipPools", "مخزن IP", ["type", "startip", "endip"]),
    table("vpn", "تونل‌های IPsec", ["name", "status", "phase1", "phase2"], vpn, [
      "phase1",
      "phase2",
      "ipsecSummary",
      "ipsecStatus",
    ]),
    objectTable("zones", "Zone", ["interface"]),
    objectTable("vdoms", "VDOM", ["short-name", "vcluster-id"]),
    objectTable("vdomProperties", "توضیحات VDOM", ["description"]),
  ];
  const rawSections: {
    key: FortiCommandId;
    title: string;
    state: FortiCommandState;
    lines: string[];
  }[] = [
    ["routes", "جدول مسیر"],
    ["dns", "DNS جاری"],
    ["dnsConfig", "پیکربندی DNS"],
    ["ha", "وضعیت HA"],
    ["haConfig", "پیکربندی HA"],
    ["sslMonitor", "کاربران فعال SSL-VPN"],
    ["sslSettings", "پیکربندی SSL-VPN"],
    ["fortiguard", "FortiGuard"],
    ["processes", "پردازش‌ها"],
    ["arp", "ARP"],
    ["arpDiagnostic", "ARP تشخیصی"],
    ["neighbors", "همسایه‌های شناسایی‌شده"],
  ].map(([key, title]) => ({
    key: key as FortiCommandId,
    title,
    state: state([key as FortiCommandId]),
    lines: read(key as FortiCommandId)
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(0, 256),
  }));
  const systemText = read("system");
  return {
    vendor: "fortigate" as const,
    collectedAt: new Date().toISOString(),
    inventoryStatus: commandEvidence.every((e) => e.state === "collected")
      ? "collected"
      : "partial",
    system: {
      ...fortiIdentity(systemText),
      serial: label(systemText, "Serial-Number"),
      operationMode: label(systemText, "Operation Mode"),
      haMode: label(systemText, "Current HA mode"),
      systemTime: label(systemText, "System time"),
      license:
        label(systemText, "License Status") ?? label(systemText, "License Status Validation"),
      vdomMode: label(systemText, "Virtual domain configuration"),
      currentVdom: label(systemText, "Current virtual domain"),
    },
    health,
    interfaceCounters: fortiCounters(read("counters")),
    logs: { ...parseFortiLogs(read("logs")), state: state(["logs"]) },
    tables,
    rawSections,
    commandEvidence,
    warnings,
  };
}
export type FortiCollection = ReturnType<typeof buildFortiInventory>;

export function isFortiConfigComplete(text: string, expected: string) {
  const lines = text
    .trim()
    .split(/\r?\n/)
    .map((line) => line.trim());
  if (lines[0] !== expected || lines.at(-1) !== "end") return false;
  let depth = 0;
  const active = new Map<number, boolean>();
  for (const line of lines) {
    if (/^config /.test(line)) {
      depth++;
      active.set(depth, false);
      continue;
    }
    if (line === "end") {
      if (active.get(depth)) return false;
      active.delete(depth);
      depth--;
      if (depth < 0) return false;
      continue;
    }
    if (/^edit /.test(line)) {
      if (depth < 1 || active.get(depth)) return false;
      active.set(depth, true);
    } else if (line === "next") {
      if (!active.get(depth)) return false;
      active.set(depth, false);
    }
  }
  return depth === 0;
}
