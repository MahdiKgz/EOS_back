import { isFortiVdomAction, fortiVdomResource, fortiVdomMatches } from "./fortigate-vdom";
import {
  isFortiClusterAction,
  fortiClusterResource,
  fortiClusterMatches,
} from "./fortigate-cluster";
import { isFortiAdminAction, fortiAdminResource, fortiAdminMatches } from "./fortigate-admin";
import {
  isFortiNetworkAction,
  fortiNetworkResource,
  fortiNetworkMatches,
} from "./fortigate-network";
import {
  fortiPolicyMatches,
  fortiPolicyDependencies,
  isFortiPolicyCreate,
  type FortiPreparedInput,
  type FortiDependencyTables,
} from "./fortigate-policy";
import { BadRequestException } from "@nestjs/common";
import { isIP } from "node:net";
import type { FortiBlock } from "./fortigate-inventory";
import type { PreviewFortiActionDto } from "./fortigate-actions.dto";
import { fortiIpMask } from "./fortigate-action-compiler";
export const fortiObjectActions = [
  "address.create",
  "address.update",
  "address.delete",
  "addressGroup.create",
  "addressGroup.add",
  "addressGroup.remove",
  "service.create",
  "service.update",
  "service.delete",
  "serviceGroup.create",
  "serviceGroup.add",
  "serviceGroup.remove",
  "schedule.create",
  "schedule.update",
  "zone.create",
  "zone.update",
  "zone.add",
  "zone.remove",
  "zone.delete",
  "vip.create",
  "vip.update",
  "vip.delete",
  "vipGroup.create",
  "ipPool.create",
  "ipPool.update",
  "ipPool.delete",
] as const;
export const fortiResources = {
  vip: { context: "firewall vip", table: "vips", dependency: "system interface" },
  vipGroup: { context: "firewall vipgrp", table: "vipGroups", dependency: "firewall vip" },
  ipPool: { context: "firewall ippool", table: "ipPools" },
  address: { context: "firewall address", table: "addresses" },
  addressGroup: {
    context: "firewall addrgrp",
    dependency: "firewall address",
    table: "addressGroups",
  },
  service: { context: "firewall service custom", table: "services" },
  serviceGroup: {
    context: "firewall service group",
    dependency: "firewall service custom",
    table: "serviceGroups",
  },
  schedule: { context: "firewall schedule recurring", table: "schedules" },
  zone: { context: "system zone", dependency: "system interface", table: "zones" },
} as const;
export const builtinServices = new Set([
  "ALL",
  "HTTP",
  "HTTPS",
  "SSH",
  "DNS",
  "PING",
  "FTP",
  "SMTP",
  "POP3",
  "IMAP",
  "LDAP",
  "RDP",
  "TELNET",
  "SNMP",
]);
const bad = (message: string): never => {
  throw new BadRequestException(message);
};
const name = (value: string) =>
  /^[A-Za-z0-9_.:-]{1,79}$/.test(value) ? value : bad("نام شیء معتبر نیست.");
const quote = (value: string) => '"' + value + '"';
export function fortiResource(action: string): {
  context: string;
  table: string;
  dependency?: string;
  dependencies?: string[];
  global?: boolean;
} {
  if (isFortiVdomAction(action)) return fortiVdomResource(action);
  if (isFortiClusterAction(action)) return fortiClusterResource(action);
  if (isFortiAdminAction(action)) return fortiAdminResource(action);
  if (isFortiNetworkAction(action)) return fortiNetworkResource(action);
  if (action.startsWith("policy."))
    return {
      context: "firewall policy",
      table: "policies",
      dependencies:
        isFortiPolicyCreate(action) || action === "policy.update" ? fortiPolicyDependencies : [],
    };
  if (action.startsWith("interface.")) return { context: "system interface", table: "interfaces" };
  const key = action.split(".")[0] as keyof typeof fortiResources;
  return fortiResources[key] ?? bad("نوع عملیات ثبت نشده است.");
}
function members(value: string, allowEmpty = false) {
  const entries = [
    ...new Set(
      value
        .split(/[,،\s]+/)
        .filter(Boolean)
        .map(name),
    ),
  ];
  if ((!entries.length && !allowEmpty) || entries.length > 64) bad("بین ۱ تا ۶۴ عضو انتخاب کنید.");
  return entries;
}
function ports(value: string) {
  const values = value.split(/[,،\s]+/).filter(Boolean);
  if (!values.length || values.length > 64) bad("فهرست پورت معتبر نیست.");
  return values
    .map((value) => {
      if (!/^\d{1,5}(?:-\d{1,5})?$/.test(value)) return bad("پورت یا بازهٔ پورت معتبر نیست.");
      const [a, b = a] = value.split("-").map(Number);
      if (a < 1 || b > 65535 || a > b) return bad("پورت باید بین ۱ و ۶۵۵۳۵ باشد.");
      return a === b ? String(a) : `${a}-${b}`;
    })
    .join(" ");
}
export function normalizedFortiField(field: string, value: string) {
  if (field === "member" || field === "interface" || field === "day" || field === "allowaccess")
    return value.split(/\s+/).filter(Boolean).sort().join(" ");
  if (/^(?:tcp|udp|sctp)-portrange$/.test(field)) {
    if (!value.trim()) return "";
    const ranges = value
      .split(/[\s,]+/)
      .map((v) => {
        const [a, b = a] = v.split("-").map(Number);
        return [a, b];
      })
      .sort((a, b) => a[0] - b[0]);
    const merged: number[][] = [];
    for (const [a, b] of ranges) {
      if (!Number.isInteger(a) || !Number.isInteger(b) || a < 1 || b < a || b > 65535) return value;
      const last = merged.at(-1);
      if (last && a <= last[1] + 1) last[1] = Math.max(last[1], b);
      else merged.push([a, b]);
    }
    return merged.map(([a, b]) => (a === b ? String(a) : `${a}-${b}`)).join(" ");
  }
  return value;
}
export function fortiActionMatches(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
  tables: FortiDependencyTables = {},
) {
  if (isFortiVdomAction(input.action)) return fortiVdomMatches(rows, input, expected, tables);
  if (isFortiClusterAction(input.action)) return fortiClusterMatches(rows, input, expected, tables);
  if (isFortiAdminAction(input.action)) return fortiAdminMatches(rows, input, expected);
  if (isFortiNetworkAction(input.action)) return fortiNetworkMatches(rows, input, expected, tables);
  if (input.action.startsWith("policy.")) return fortiPolicyMatches(rows, input, expected, tables);
  const row = rows.find((row) => row.name === input.name);
  if (input.action.endsWith(".delete")) return !row;
  if (!row) return false;
  return Object.entries(expected).every(
    ([field, value]) =>
      normalizedFortiField(field, row.settings[field]?.join(" ") ?? "") ===
      normalizedFortiField(field, value),
  );
}
export function compileFortiObject(input: PreviewFortiActionDto, row?: FortiBlock) {
  if (!(fortiObjectActions as readonly string[]).includes(input.action))
    bad("عملیات ثبت نشده است.");
  name(input.name);
  if (input.vdom) name(input.vdom);
  const [resource, verb] = input.action.split("."),
    context = fortiResource(input.action).context;
  const managed = "firewall-log-analyzer managed " + resource,
    assignments: Record<string, string> = {},
    quoted = new Set<string>(),
    unset: string[] = [],
    memberNames: string[] = [];
  if (resource === "service" && builtinServices.has(input.name.toUpperCase()))
    bad("سرویس داخلی FortiGate قابل تغییر از این مسیر نیست.");
  if (verb === "delete")
    return {
      context,
      commands: [`config ${context}`, `delete ${quote(input.name)}`, "end"],
      assignments: { exists: "absent" },
      memberNames,
    };
  if (resource === "address") {
    const type = input.addressType ?? "subnet";
    assignments.type = type === "subnet" ? "ipmask" : type === "wildcard-fqdn" ? "fqdn" : type;
    if (type === "subnet") assignments.subnet = fortiIpMask(input.value);
    else if (type === "iprange") {
      if (isIP(input.value) !== 4 || isIP(input.endIp ?? "") !== 4)
        bad("آدرس شروع و پایان IPv4 لازم است.");
      const n = (ip: string) => ip.split(".").reduce((sum, p) => sum * 256 + Number(p), 0);
      if (n(input.value) > n(input.endIp!)) bad("پایان بازه نباید از شروع کوچک‌تر باشد.");
      assignments["start-ip"] = input.value;
      assignments["end-ip"] = input.endIp!;
    } else if (type === "geography") {
      if (!/^[A-Za-z]{2}$/.test(input.value)) bad("کد دوحرفی کشور لازم است.");
      assignments.country = input.value.toUpperCase();
      quoted.add("country");
    } else if (type === "fqdn" || type === "wildcard-fqdn") {
      const fqdn = type === "wildcard-fqdn" ? input.value.replace(/^\*\./, "") : input.value;
      if (
        !/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/.test(
          fqdn,
        )
      )
        bad("نام دامنه معتبر نیست.");
      assignments.fqdn = input.value;
      quoted.add("fqdn");
    } else bad("نوع آدرس معتبر نیست.");
    assignments.comment = managed;
    quoted.add("comment");
  } else if (resource === "vip") {
    for (const [parameter, field] of [
      ["externalIp", "extip"],
      ["mappedIp", "mappedip"],
    ] as const) {
      const value = input[parameter];
      if (verb === "create" || value !== undefined) {
        if (isIP(value ?? "") !== 4) bad("آدرس خارجی و مقصد باید IPv4 باشند.");
        assignments[field] = value!;
        if (field === "mappedip") quoted.add(field);
      }
    }
    for (const [parameter, field] of [
      ["externalPort", "extport"],
      ["mappedPort", "mappedport"],
    ] as const) {
      const value = input[parameter];
      if (verb === "create" || value !== undefined) {
        if (!value || !/^\d{1,5}$/.test(value) || +value < 1 || +value > 65535)
          bad("پورت نگاشت باید بین ۱ تا ۶۵۵۳۵ باشد.");
        assignments[field] = String(Number(value));
      }
    }
    if (verb === "create") assignments.portforward = "enable";
    if (verb === "create" || input.parent !== undefined) {
      const iface = name(input.parent ?? "any");
      assignments.extintf = iface;
      quoted.add("extintf");
      if (iface !== "any") memberNames.push(iface);
    }
    if (!Object.keys(assignments).length) bad("حداقل یک فیلد VIP را وارد کنید.");
  } else if (resource === "ipPool") {
    const first = input.value || row?.settings.startip?.[0],
      last = input.endIp ?? row?.settings.endip?.[0];
    if (verb === "create" && (!input.value || !input.endIp)) bad("شروع و پایان مخزن IP لازم است.");
    if (input.value) {
      if (isIP(input.value) !== 4) bad("شروع مخزن IPv4 معتبر نیست.");
      assignments.startip = input.value;
    }
    if (input.endIp !== undefined) {
      if (isIP(input.endIp) !== 4) bad("پایان مخزن IPv4 معتبر نیست.");
      assignments.endip = input.endIp;
    }
    if (first && last) {
      const numeric = (ip: string) => ip.split(".").reduce((n, part) => n * 256 + +part, 0);
      if (numeric(first) > numeric(last)) bad("پایان مخزن نباید از شروع کوچک‌تر باشد.");
    }
    if (!Object.keys(assignments).length) bad("حداقل یک فیلد مخزن IP را وارد کنید.");
  } else if (resource === "service") {
    const protocol = input.serviceProtocol ?? "TCP";
    if (!["TCP", "UDP", "TCP-UDP"].includes(protocol)) bad("پروتکل سرویس معتبر نیست.");
    assignments.protocol = "TCP/UDP/SCTP";
    for (const field of ["tcp-portrange", "udp-portrange", "sctp-portrange"]) {
      const enabled =
        field === "tcp-portrange"
          ? protocol !== "UDP"
          : field === "udp-portrange"
            ? protocol !== "TCP"
            : false;
      if (enabled)
        assignments[field] = ports(
          field === "udp-portrange" && protocol === "TCP-UDP"
            ? (input.udpPorts ?? "")
            : input.value,
        );
      else {
        assignments[field] = "";
        unset.push(field);
      }
    }
    assignments.comment = managed;
    quoted.add("comment");
  } else if (resource === "schedule") {
    const days = members(input.value);
    if (
      days.some(
        (d) =>
          !["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"].includes(
            d,
          ),
      )
    )
      bad("روزهای هفته معتبر نیستند.");
    for (const key of ["start", "end"] as const) {
      const value = input[key];
      if (!value || !/^([01]\d|2[0-3]):[0-5]\d$/.test(value)) bad("زمان باید به صورت HH:MM باشد.");
      assignments[key] = value!;
    }
    assignments.day = days.join(" ");
  } else {
    const field = resource === "zone" ? "interface" : "member",
      requested = members(
        input.value,
        resource === "zone" && (verb === "create" || verb === "update"),
      );
    memberNames.push(...requested);
    if (requested.includes(input.name)) bad("شیء نمی‌تواند عضو خودش باشد.");
    const before = row?.settings[field] ?? [];
    assignments[field] =
      verb === "add"
        ? [...new Set([...before, ...requested])].join(" ")
        : verb === "remove"
          ? before.filter((member) => !requested.includes(member)).join(" ")
          : requested.join(" ");
    if (!assignments[field]) unset.push(field);
    if (resource === "zone") {
      assignments.intrazone = input.intrazone ?? row?.settings.intrazone?.[0] ?? "deny";
      if (!["deny", "allow"].includes(assignments.intrazone))
        bad("وضعیت ترافیک داخل Zone معتبر نیست.");
      assignments.description = managed;
      quoted.add("description");
    } else if (resource === "addressGroup") {
      assignments.comment = managed;
      quoted.add("comment");
    }
  }
  const lines = Object.entries(assignments).map(([field, value]) =>
    unset.includes(field)
      ? `unset ${field}`
      : `set ${field} ${field === "member" || field === "interface" ? value.split(" ").map(quote).join(" ") : quoted.has(field) ? quote(value) : value}`,
  );
  return {
    context,
    commands: [`config ${context}`, `edit ${quote(input.name)}`, ...lines, "next", "end"],
    assignments,
    memberNames,
  };
}
