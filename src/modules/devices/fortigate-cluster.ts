import { BadRequestException } from "@nestjs/common";
import { isIP } from "node:net";
import { fortiTokens, type FortiBlock } from "./fortigate-inventory";
import type { FortiDependencyTables, FortiPreparedInput } from "./fortigate-policy";
export const fortiClusterActions = [
  "ha.configure",
  "ha.priority",
  "sdwanZone.create",
  "sdwanMember.create",
  "sdwanHealth.create",
  "sdwanRule.create",
] as const;
export const isFortiClusterAction = (action: string) =>
  (fortiClusterActions as readonly string[]).includes(action);
export const isFortiClusterAuto = (action: string) =>
  action === "sdwanMember.create" || action === "sdwanRule.create";
const section = (action: string) =>
  ({
    sdwanZone: "zone",
    sdwanMember: "members",
    sdwanHealth: "health-check",
    sdwanRule: "service",
  })[action.split(".")[0]];
export function fortiClusterResource(action: string) {
  return action.startsWith("ha.")
    ? { context: "system ha", table: "haConfig", global: true, dependencies: [] as string[] }
    : {
        context: "system sdwan",
        table: (
          {
            zone: "sdwanZones",
            members: "sdwanMembers",
            "health-check": "sdwanHealth",
            service: "sdwanRules",
          } as Record<string, string>
        )[section(action)!],
        global: false,
        dependencies: action.startsWith("sdwanMember.")
          ? ["system interface"]
          : action.startsWith("sdwanRule.")
            ? ["firewall address", "firewall addrgrp"]
            : ([] as string[]),
      };
}
const bad = (message: string): never => {
  throw new BadRequestException(message);
};
const name = (value: string, max = 35) =>
  new RegExp(`^[A-Za-z0-9_.:-]{1,${max}}$`).test(value)
    ? value
    : bad("نام تنظیم کلاستر معتبر نیست.");
const quote = (value: string) => JSON.stringify(value);
const members = (value: string, all = false) => {
  const raw = value.split(/[,،\s]+/).filter(Boolean);
  if (
    !raw.length ||
    raw.length > 64 ||
    raw.some((v) => !/^\d{1,10}$/.test(v) || +v > 4294967294 || (!all && +v === 0))
  )
    bad("شناسه‌های عضو معتبر وارد کنید.");
  const ids = [...new Set(raw.map((v) => String(+v)))];
  if (ids.includes("0") && ids.length !== 1) bad("صفر فقط به‌تنهایی و برای همهٔ اعضا مجاز است.");
  return ids.join(" ");
};
const addresses = (value: string) => {
  const values = [
    ...new Set(
      value
        .split(/[,،\s]+/)
        .filter(Boolean)
        .map((v) => name(v, 79)),
    ),
  ];
  if (!values.length || values.length > 64) bad("بین ۱ تا ۶۴ مرجع آدرس لازم است.");
  return values.join(" ");
};
export function parseFortiSdwan(text: string): FortiBlock[] {
  const rows: FortiBlock[] = [],
    system: FortiBlock = { name: "system", settings: { __section: ["settings"] } };
  let depth = 0,
    currentSection: string | undefined,
    row: FortiBlock | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("config ")) {
      depth++;
      if (depth === 2) currentSection = line.slice(7);
      continue;
    }
    if (line === "end") {
      if (depth === 2) {
        currentSection = undefined;
        row = undefined;
      }
      depth--;
      continue;
    }
    if (
      depth === 2 &&
      currentSection &&
      ["zone", "members", "health-check", "service"].includes(currentSection)
    ) {
      if (line.startsWith("edit ")) {
        row = {
          name: fortiTokens(line.slice(5))[0] ?? "",
          settings: { __section: [currentSection] },
        };
        continue;
      }
      if (line === "next" && row) {
        rows.push(row);
        row = undefined;
        if (rows.length >= 4097) break;
        continue;
      }
    }
    const match = line.match(/^set\s+([\w-]+)(?:\s+(.*))?$/);
    if (match && depth === 1) system.settings[match[1]] = fortiTokens(match[2] ?? "");
    if (match && depth === 2 && row) row.settings[match[1]] = fortiTokens(match[2] ?? "");
  }
  return [system, ...rows];
}
export const fortiClusterReadCommands = (action: string) =>
  action.startsWith("ha.") ? ["get system ha status"] : [];
export function fortiClusterReadMetadata(action: string, outputs: string[]): FortiDependencyTables {
  if (!action.startsWith("ha.")) return {};
  const text = outputs[0] ?? "",
    match = text.match(/^Mode:\s*(?:HA\s+)?(A-P|A-A|Standalone)\b/im);
  if (!match) bad("وضعیت HA کامل و قابل تشخیص دریافت نشد.");
  const mode = match![1].toLowerCase(),
    health = /^HA Health Status:\s*OK\s*$/im.test(text) ? "ok" : "unknown_or_degraded";
  return { __haStatus: [{ name: "ha", settings: { mode: [mode], health: [health] } }] };
}
export function fortiClusterPrecheck(action: string, tables: FortiDependencyTables) {
  if (!action.startsWith("ha.")) return undefined;
  return {
    "حالت فعلی HA": tables.__haStatus?.[0]?.settings.mode?.[0] ?? "نامشخص",
    "سلامت فعلی HA":
      tables.__haStatus?.[0]?.settings.health?.[0] === "ok" ? "OK" : "نامشخص یا نیازمند بررسی",
  };
}
export function compileFortiCluster(input: FortiPreparedInput) {
  if (!isFortiClusterAction(input.action)) bad("عملیات کلاستر ثبت نشده است.");
  const assignments: Record<string, string> = {},
    commands: string[] = [];
  if (input.action.startsWith("ha.")) {
    if (input.name !== "system") bad("هدف تنظیم HA باید system باشد.");
    if (input.action === "ha.configure") {
      if (!["standalone", "a-a", "a-p"].includes(input.haMode ?? "")) bad("حالت HA معتبر نیست.");
      assignments.mode = input.haMode!;
      const group = input.haGroup ?? "";
      if (!group.trim() || group.length > 32 || /\p{Cc}/u.test(group))
        bad("نام گروه HA باید بین ۱ تا ۳۲ نویسه و بدون نویسهٔ کنترلی باشد.");
      assignments["group-name"] = group;
    }
    if (input.action === "ha.priority" || input.haPriority !== undefined) {
      if (!/^\d{1,3}$/.test(input.haPriority ?? "") || +input.haPriority! > 255)
        bad("Priority باید بین صفر و ۲۵۵ باشد.");
      assignments.priority = String(+input.haPriority!);
    }
    commands.push(
      "config system ha",
      ...Object.entries(assignments).map(
        ([key, value]) => `set ${key} ${key === "group-name" ? quote(value) : value}`,
      ),
      "end",
    );
  } else {
    name(input.name, input.action === "sdwanRule.create" ? 127 : 35);
    const part = section(input.action)!;
    if (part === "zone") assignments["service-sla-tie-break"] = "cfg-order";
    if (part === "members") {
      assignments.interface = name(input.dstInterface ?? "", 15);
      assignments.zone = name(input.sdwanZone || "virtual-wan-link");
      if (input.gateway !== undefined) {
        if (isIP(input.gateway) !== 4) bad("Gateway باید IPv4 باشد.");
        assignments.gateway = input.gateway;
      }
      assignments.status = "enable";
    }
    if (part === "health-check") {
      const server = input.probeServer ?? "";
      if (
        !(
          isIP(server) === 4 ||
          (server.length <= 253 &&
            server
              .split(".")
              .every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label)))
        ) ||
        (/^[\d.]+$/.test(server) && isIP(server) !== 4)
      )
        bad("سرور بررسی باید IPv4 یا نام میزبان معتبر باشد.");
      assignments.server = server;
      assignments.protocol = "ping";
      assignments.members = members(input.sdwanMembers || "0", true);
    }
    if (part === "service") {
      assignments.name = input.name;
      assignments.mode = "manual";
      assignments["priority-members"] = members(input.sdwanMembers ?? "");
      assignments.src = addresses(input.srcAddresses || "all");
      assignments.dst = addresses(input.dstAddresses || "all");
      assignments.status = "enable";
    }
    if (isFortiClusterAuto(input.action))
      assignments.comment = "EOSNet invocation=" + (input.executionTag ?? "preview");
    commands.push(
      "config system sdwan",
      `config ${part}`,
      isFortiClusterAuto(input.action) ? "edit 0" : `edit ${quote(input.name)}`,
    );
    for (const [key, value] of Object.entries(assignments))
      commands.push(
        `set ${key} ${["src", "dst"].includes(key) ? value.split(" ").map(quote).join(" ") : ["interface", "zone", "server", "name", "comment"].includes(key) ? quote(value) : value}`,
      );
    commands.push("next", "end", "end");
  }
  return { commands, assignments, memberNames: [] as string[] };
}
const rowsFor = (rows: FortiBlock[], action: string) =>
  rows.filter((r) => r.settings.__section?.[0] === section(action));
export function fortiClusterTarget(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
) {
  if (input.action.startsWith("ha.")) return rows.find((r) => r.name === "system");
  const candidates = rowsFor(rows, input.action).filter((r) =>
    isFortiClusterAuto(input.action)
      ? /^[1-9]\d{0,9}$/.test(r.name) &&
        +r.name <= 4294967294 &&
        r.settings.comment?.join(" ") === expected.comment
      : r.name === input.name,
  );
  return candidates.length === 1 ? candidates[0] : undefined;
}
export function assertFortiCluster(
  input: FortiPreparedInput,
  rows: FortiBlock[],
  tables: FortiDependencyTables,
) {
  if (input.action.startsWith("ha.")) {
    if (!rows.some((r) => r.name === "system") || !tables.__haStatus?.[0]?.settings.mode?.[0])
      bad("پیش‌بررسی HA کامل نیست.");
    return;
  }
  const part = section(input.action),
    own = rowsFor(rows, input.action);
  if (!isFortiClusterAuto(input.action) && own.some((r) => r.name === input.name))
    bad("تنظیم هم‌نام موجود است؛ ساخت جدید آن را بازنویسی نمی‌کند.");
  if (part === "members") {
    const iface = (tables["system interface"] ?? []).find((r) => r.name === input.dstInterface);
    if (!iface || (input.vdom && iface.settings.vdom?.[0] && iface.settings.vdom[0] !== input.vdom))
      bad("رابط انتخاب‌شده در VDOM جاری پیدا نشد.");
    if (
      !rowsFor(rows, "sdwanZone.create").some(
        (r) => r.name === (input.sdwanZone || "virtual-wan-link"),
      )
    )
      bad("Zone موجود SD-WAN را انتخاب کنید.");
    if (own.some((r) => r.settings.interface?.[0] === input.dstInterface))
      bad("این رابط قبلاً عضو SD-WAN است.");
  }
  if (part === "service" || part === "health-check") {
    const selected = members(
      input.sdwanMembers || (part === "health-check" ? "0" : ""),
      part === "health-check",
    ).split(" ");
    const known = rowsFor(rows, "sdwanMember.create");
    if (!known.length || selected.some((v) => v !== "0" && !known.some((r) => r.name === v)))
      bad("حداقل یک عضو موجود SD-WAN لازم است.");
    if (part === "service")
      for (const field of ["srcAddresses", "dstAddresses"] as const)
        for (const ref of addresses(input[field] || "all").split(" "))
          if (
            ref !== "all" &&
            ![...(tables["firewall address"] ?? []), ...(tables["firewall addrgrp"] ?? [])].some(
              (r) => r.name === ref,
            )
          )
            bad("مرجع آدرس قانون SD-WAN پیدا نشد.");
  }
}
export function fortiClusterMatches(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
  tables: FortiDependencyTables,
) {
  const row = fortiClusterTarget(rows, input, expected);
  if (!row) return false;
  if (
    input.action === "ha.configure" &&
    tables.__haStatus?.[0]?.settings.mode?.[0] !== expected.mode
  )
    return false;
  return Object.entries(expected).every(([key, value]) => {
    const actual = row.settings[key]?.join(" ") ?? "";
    return ["src", "dst", "members"].includes(key)
      ? actual.split(" ").sort().join(" ") === value.split(" ").sort().join(" ")
      : actual === value;
  });
}
export function fortiClusterBefore(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
) {
  const row = fortiClusterTarget(rows, input, expected);
  return Object.fromEntries(
    Object.keys(expected).map((key) => [key, row?.settings[key]?.join(" ") ?? null]),
  );
}
export function fortiClusterMessage(input: FortiPreparedInput, tables: FortiDependencyTables) {
  if (input.action.startsWith("ha."))
    return "تنظیم HA عمومی تجهیز تغییر می‌کند و ممکن است انتخاب عضو اصلی یا اتصال مدیریت تغییر کند. heartbeat، گذرواژه و سایر تنظیمات فعلی حفظ می‌شوند؛ تأیید پیکربندی به معنی تشکیل سالم کلاستر نیست.";
  const enabled = rowsSettings(tables)["status"]?.[0];
  return (
    (enabled === "enable"
      ? "SD-WAN فعال است. "
      : enabled === "disable"
        ? "SD-WAN غیرفعال است؛ ساخت تنظیم آن را خودکار فعال نمی‌کند. "
        : "وضعیت فعال‌بودن SD-WAN مشخص نیست. ") +
    (input.action === "sdwanHealth.create"
      ? "بررسی ping برای اعضای انتخاب‌شده تنظیم می‌شود و در سلامت اعضا و انتخاب مسیر به کار می‌رود؛ ذخیرهٔ موفق به معنی سالم‌بودن مسیر نیست."
      : "تنظیم جدید با حفظ سایر بخش‌ها ساخته و شناسه و مقادیر آن از دستگاه خوانده می‌شوند.")
  );
}
const rowsSettings = (tables: FortiDependencyTables) =>
  tables["system sdwan"]?.find((r) => r.settings.__section?.[0] === "settings")?.settings ?? {};
