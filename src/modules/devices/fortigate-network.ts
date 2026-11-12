import { BadRequestException } from "@nestjs/common";
import { isIP } from "node:net";
import { fortiIpMask } from "./fortigate-action-compiler";
import { fortiTokens, type FortiBlock } from "./fortigate-inventory";
import {
  fortiManagedSource,
  type FortiDependencyTables,
  type FortiPreparedInput,
} from "./fortigate-policy";
export const fortiNetworkActions = [
  "snat.create",
  "route.create",
  "route.update",
  "route.delete",
  "dns.update",
  "ntp.update",
] as const;
export const isFortiNetworkAction = (action: string) =>
  (fortiNetworkActions as readonly string[]).includes(action);
export const isFortiNetworkCreate = (action: string) =>
  action === "snat.create" || action === "route.create";
export function fortiNetworkResource(action: string) {
  if (action.startsWith("snat."))
    return {
      context: "firewall central-snat-map",
      table: "centralSnat",
      dependencies: [
        "system interface",
        "system zone",
        "firewall address",
        "firewall addrgrp",
        "system settings",
      ],
      global: false,
    };
  if (action.startsWith("route."))
    return {
      context: "router static",
      table: "staticRoutes",
      dependencies: ["system interface"],
      global: false,
    };
  return {
    context: action === "dns.update" ? "system dns" : "system ntp",
    table: action === "dns.update" ? "dnsConfig" : "ntp",
    dependencies: [] as string[],
    global: true,
  };
}
const bad = (message: string): never => {
  throw new BadRequestException(message);
};
const quote = (value: string) => '"' + value + '"';
const name = (value: string) =>
  /^[A-Za-z0-9_.:-]{1,79}$/.test(value) ? value : bad("نام مرجع شبکه معتبر نیست.");
const numericId = (value: string) =>
  /^[1-9]\d{0,9}$/.test(value) && +value <= 4294967294 ? value : bad("شناسهٔ مسیر معتبر نیست.");
const ipv4 = (value: string) => (isIP(value) === 4 ? value : bad("آدرس IPv4 معتبر لازم است."));
const subnet = (value: string) => fortiIpMask(value.includes("/") ? value : value + "/32");
const members = (value: string) => {
  const result = [
    ...new Set(
      value
        .split(/[,،\s]+/)
        .filter(Boolean)
        .map(name),
    ),
  ];
  if (!result.length || result.length > 64) bad("بین ۱ تا ۶۴ مرجع معتبر وارد کنید.");
  return result;
};
export function parseFortiSystemConfig(context: string, text: string): FortiBlock[] | null {
  if (
    !["system settings", "system dns", "system ntp", "system global", "system ha"].includes(context)
  )
    return null;
  const settings: Record<string, string[]> = Object.create(null);
  let depth = 0,
    inNtpServers = false,
    ntpId: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("config ")) {
      depth++;
      if (depth === 2 && line === "config ntpserver") inNtpServers = true;
    } else if (line === "end") {
      if (depth === 2) {
        inNtpServers = false;
        ntpId = undefined;
      }
      depth--;
    } else if (line.startsWith("edit ") && inNtpServers && depth === 2)
      ntpId = fortiTokens(line.slice(5))[0];
    else if (line === "next" && depth === 2) ntpId = undefined;
    else {
      const match = line.match(/^set\s+([\w-]+)\s+(.+)$/);
      if (match && depth === 1) settings[match[1]] = fortiTokens(match[2]);
      if (match && depth === 2 && inNtpServers && ntpId === "1" && match[1] === "server")
        settings.server = fortiTokens(match[2]);
    }
  }
  return [{ name: "system", settings }];
}
export function compileFortiNetwork(input: FortiPreparedInput, tables: FortiDependencyTables = {}) {
  if (!isFortiNetworkAction(input.action)) bad("عملیات شبکه ثبت نشده است.");
  const { context } = fortiNetworkResource(input.action),
    assignments: Record<string, string> = {},
    commands: string[] = [];
  if (input.vdom) name(input.vdom);
  const marker =
    "firewall-log-analyzer " +
    input.name +
    (input.executionTag ? " invocation=" + input.executionTag : "");
  if (input.action.startsWith("route.")) {
    if (input.action === "route.create") name(input.name);
    else numericId(input.name);
    if (input.action === "route.delete")
      return {
        commands: [`config ${context}`, `delete ${input.name}`, "end"],
        assignments: { exists: "absent" } as Record<string, string>,
        memberNames: [] as string[],
      };
    const create = input.action === "route.create";
    if (create || input.destinationCidr !== undefined)
      assignments.dst = subnet(input.destinationCidr ?? "");
    if (create || input.gateway !== undefined) assignments.gateway = ipv4(input.gateway ?? "");
    if (input.dstInterface !== undefined) assignments.device = name(input.dstInterface);
    if (create) assignments.comment = marker;
    if (!Object.keys(assignments).length) bad("حداقل یک فیلد مسیر را وارد کنید.");
    commands.push(`config ${context}`, create ? "edit 0" : `edit ${input.name}`);
    for (const [key, value] of Object.entries(assignments))
      commands.push(`set ${key} ${["device", "comment"].includes(key) ? quote(value) : value}`);
    commands.push("next", "end");
  } else if (input.action === "snat.create") {
    name(input.name);
    assignments.srcintf = members(input.srcInterface ?? "").join(" ");
    assignments.dstintf = members(input.dstInterface ?? "").join(" ");
    if (input.sourceCidr && input.srcAddresses !== undefined)
      bad("مرجع مبدأ یا IP/CIDR جدید را وارد کنید؛ هر دو هم‌زمان مجاز نیستند.");
    if (input.sourceCidr) {
      const source = fortiManagedSource(input.sourceCidr, tables);
      commands.push(...source.commands);
      assignments["__sourceName"] = source.name;
      assignments["__sourceSubnet"] = source.subnet;
      assignments["orig-addr"] = source.name;
    } else assignments["orig-addr"] = members(input.srcAddresses ?? "all").join(" ");
    assignments["dst-addr"] = members(input.dstAddresses ?? "all").join(" ");
    assignments.nat = "enable";
    assignments.status = input.policyStatus ?? "enable";
    if (!["enable", "disable"].includes(assignments.status)) bad("وضعیت SNAT معتبر نیست.");
    assignments.comments = marker;
    commands.push(`config ${context}`, "edit 0");
    for (const [key, value] of Object.entries(assignments))
      if (!key.startsWith("__"))
        commands.push(
          `set ${key} ${["srcintf", "dstintf", "orig-addr", "dst-addr"].includes(key) ? value.split(" ").map(quote).join(" ") : key === "comments" ? quote(value) : value}`,
        );
    commands.push("next", "end");
  } else {
    if (input.name !== "system") bad("هدف تنظیمات عمومی باید system باشد.");
    if (input.action === "dns.update") {
      assignments.primary = ipv4(input.primaryDns ?? "");
      assignments.secondary = ipv4(input.secondaryDns ?? "");
      commands.push(
        "config system dns",
        `set primary ${assignments.primary}`,
        `set secondary ${assignments.secondary}`,
        "end",
      );
    } else {
      const server = input.ntpServer?.trim() ?? "";
      if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$/.test(server))
        bad("نام میزبان یا آدرس سرور NTP معتبر نیست.");
      assignments.ntpsync = "enable";
      assignments.type = "custom";
      assignments.server = server;
      commands.push(
        "config system ntp",
        "set ntpsync enable",
        "set type custom",
        "config ntpserver",
        "edit 1",
        `set server ${quote(server)}`,
        "next",
        "end",
        "end",
      );
    }
  }
  return { commands, assignments, memberNames: [] as string[] };
}
export function assertFortiNetwork(
  input: FortiPreparedInput,
  plan: ReturnType<typeof compileFortiNetwork>,
  rows: FortiBlock[],
  tables: FortiDependencyTables,
) {
  if (!isFortiNetworkCreate(input.action) && !rows.some((r) => r.name === input.name))
    bad("هدف در پیکربندی زنده پیدا نشد.");
  const has = (contexts: string[], value: string) =>
    contexts.some((context) => (tables[context] ?? []).some((r) => r.name === value));
  if (
    input.action.startsWith("route.") &&
    plan.assignments.device &&
    !has(["system interface"], plan.assignments.device)
  )
    bad("رابط مسیر پیدا نشد.");
  if (input.action === "snat.create") {
    for (const field of ["srcintf", "dstintf"])
      for (const value of plan.assignments[field]?.split(" ") ?? [])
        if (value !== "any" && !has(["system interface", "system zone"], value))
          bad(`رابط یا Zone ${value} پیدا نشد.`);
    for (const field of ["orig-addr", "dst-addr"])
      for (const value of plan.assignments[field]?.split(" ") ?? [])
        if (
          value !== "all" &&
          value !== plan.assignments.__sourceName &&
          !has(["firewall address", "firewall addrgrp"], value)
        )
          bad(`مرجع آدرس ${value} پیدا نشد.`);
  }
}
export function fortiNetworkTarget(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
) {
  if (!isFortiNetworkCreate(input.action)) return rows.find((r) => r.name === input.name);
  const field = input.action === "route.create" ? "comment" : "comments";
  const matching = rows.filter((r) => r.settings[field]?.join(" ") === expected[field]);
  return matching.length === 1 ? matching[0] : undefined;
}
export function fortiNetworkMatches(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
  tables: FortiDependencyTables,
) {
  const row = fortiNetworkTarget(rows, input, expected);
  if (input.action === "route.delete") return !row;
  if (!row) return false;
  if (
    expected.__sourceName &&
    !(tables["firewall address"] ?? []).some(
      (r) =>
        r.name === expected.__sourceName &&
        r.settings.subnet?.join(" ") === expected.__sourceSubnet,
    )
  )
    return false;
  return Object.entries(expected)
    .filter(([key]) => !key.startsWith("__"))
    .every(([key, value]) => {
      const actual = row.settings[key]?.join(" ") ?? "";
      return ["srcintf", "dstintf", "orig-addr", "dst-addr"].includes(key)
        ? actual.split(" ").sort().join(" ") === value.split(" ").sort().join(" ")
        : actual === value;
    });
}
export function fortiNetworkMessage(input: FortiPreparedInput, tables: FortiDependencyTables) {
  if (input.action === "dns.update" || input.action === "ntp.update")
    return "این تنظیم در محدودهٔ کل تجهیز اعمال می‌شود؛ پیش‌نمایش و نتیجه از تنظیمات عمومی خوانده می‌شوند.";
  if (input.action === "snat.create") {
    const settings = tables["system settings"]?.[0]?.settings;
    const enabled =
      settings?.["central-nat"]?.[0] === "enable" ||
      settings?.["ngfw-mode"]?.[0] === "policy-based";
    if (enabled)
      return "Central NAT در تنظیم فعلی فعال است؛ این قانون SNAT با شناسهٔ خودکار ثبت و خوانده می‌شود.";
    if (settings?.["central-nat"]?.[0] === "disable")
      return "Central NAT در تنظیم فعلی غیرفعال است؛ قانون ذخیره می‌شود اما تا فعال‌شدن این حالت در ترجمهٔ ترافیک اعمال نمی‌شود. حالت NAT با این عملیات تغییر نمی‌کند.";
    return "حالت Central NAT از تنظیم فعلی مشخص نیست؛ ذخیرهٔ قانون، عبور یا ترجمهٔ ترافیک را تأیید نمی‌کند. حالت NAT با این عملیات تغییر نمی‌کند.";
  }
  return "تغییر مسیر می‌تواند بر مسیر دسترسی اثر بگذارد؛ شناسه و تنظیم نهایی از تجهیز خوانده می‌شوند.";
}

export function fortiNetworkBefore(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
  tables: FortiDependencyTables,
) {
  const row = isFortiNetworkCreate(input.action)
    ? undefined
    : rows.find((r) => r.name === input.name);
  const source = (tables["firewall address"] ?? []).find((r) => r.name === expected.__sourceName);
  return Object.fromEntries(
    Object.keys(expected).map((key) => [
      key,
      key === "__sourceName"
        ? (source?.name ?? null)
        : key === "__sourceSubnet"
          ? (source?.settings.subnet?.join(" ") ?? null)
          : (row?.settings[key]?.join(" ") ?? null),
    ]),
  );
}
