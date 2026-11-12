import { BadRequestException } from "@nestjs/common";
import { fortiIpMask } from "./fortigate-action-compiler";
import type { PreviewFortiActionDto } from "./fortigate-actions.dto";
import type { FortiBlock } from "./fortigate-inventory";
export const fortiPolicyActions = [
  "policy.create",
  "policy.egress",
  "policy.deny",
  "policy.dnat",
  "policy.zone",
  "policy.update",
  "policy.enable",
  "policy.disable",
  "policy.delete",
  "policy.move",
  "policy.comment",
] as const;
export type FortiPreparedInput = PreviewFortiActionDto & {
  executionTag?: string;
  secretFingerprint?: string;
};
export type FortiDependencyTables = Record<string, FortiBlock[]>;
const fail = (text: string): never => {
  throw new BadRequestException(text);
};
const quote = (value: string) => '"' + value + '"';
const safeName = (value: string) =>
  /^[A-Za-z0-9_.:-]{1,79}$/.test(value) ? value : fail("نام مرجع Policy معتبر نیست.");
const id = (value: string) =>
  /^[1-9]\d{0,9}$/.test(value) && +value <= 4294967294
    ? value
    : fail("شناسهٔ عددی Policy معتبر نیست.");
const list = (value: string) => {
  const result = [
    ...new Set(
      value
        .split(/[,،\s]+/)
        .filter(Boolean)
        .map(safeName),
    ),
  ];
  if (!result.length || result.length > 64) fail("بین ۱ تا ۶۴ مرجع انتخاب کنید.");
  return result;
};
const comment = (value: string) => {
  if (!/^[\p{L}\p{N}_.:/,@#() +*\-\u200c]{1,150}$/u.test(value))
    fail("توضیح باید حداکثر ۱۵۰ نویسهٔ مجاز باشد.");
  return "firewall-log-analyzer " + value;
};
export function isFortiPolicyCreate(action: string) {
  return ["policy.create", "policy.egress", "policy.deny", "policy.dnat", "policy.zone"].includes(
    action,
  );
}
export const fortiPolicyDependencies = [
  "system interface",
  "system zone",
  "firewall address",
  "firewall addrgrp",
  "firewall service custom",
  "firewall service group",
  "firewall schedule recurring",
  "firewall vip",
  "firewall vipgrp",
];
export function compileFortiPolicy(input: FortiPreparedInput, tables: FortiDependencyTables = {}) {
  if (!(fortiPolicyActions as readonly string[]).includes(input.action))
    fail("عملیات Policy ثبت نشده است.");
  const create = isFortiPolicyCreate(input.action),
    assignments: Record<string, string> = {},
    commands: string[] = [];
  if (create) {
    safeName(input.name);
    if (input.name.length > 35) fail("نام Policy حداکثر ۳۵ نویسه است.");
  } else id(input.name);
  if (input.vdom) safeName(input.vdom);
  if (input.action === "policy.delete")
    return {
      commands: ["config firewall policy", `delete ${id(input.name)}`, "end"],
      assignments: { exists: "absent" } as Record<string, string>,
      memberNames: [] as string[],
    };
  if (input.action === "policy.move") {
    if (!input.relativeTo || input.relativeTo === input.name)
      fail("یک Policy دیگر را برای ترتیب انتخاب کنید.");
    const relative = id(input.relativeTo ?? "");
    if (!["before", "after"].includes(input.position ?? "")) fail("قبل یا بعد را انتخاب کنید.");
    assignments[input.position === "before" ? "__before" : "__after"] = relative;
    return {
      commands: [
        "config firewall policy",
        `move ${input.name} ${input.position} ${input.relativeTo}`,
        "end",
      ],
      assignments,
      memberNames: [] as string[],
    };
  }
  const quoted = new Set<string>([
    "name",
    "srcintf",
    "dstintf",
    "srcaddr",
    "dstaddr",
    "service",
    "schedule",
    "comments",
  ]);
  if (input.action === "policy.enable" || input.action === "policy.disable")
    assignments.status = input.action === "policy.enable" ? "enable" : "disable";
  else if (input.action === "policy.comment") assignments.comments = comment(input.value);
  else {
    if (create) {
      assignments.name = input.name;
      assignments.comments =
        comment(input.value || "managed policy") +
        (input.executionTag ? " invocation=" + input.executionTag : "");
    }
    for (const [parameter, field] of [
      ["srcInterface", "srcintf"],
      ["dstInterface", "dstintf"],
      ["srcAddresses", "srcaddr"],
      ["dstAddresses", "dstaddr"],
      ["services", "service"],
    ] as const) {
      const value = input[parameter];
      if (value !== undefined || create) {
        const generated =
          parameter === "srcAddresses" && input.sourceCidr
            ? generatedSourceName(input.sourceCidr)
            : undefined;
        const defaults =
          parameter === "services"
            ? "ALL"
            : parameter === "srcAddresses" || parameter === "dstAddresses"
              ? "all"
              : "";
        assignments[field] = list(value ?? generated ?? defaults).join(" ");
      }
    }
    if (create || input.schedule !== undefined)
      assignments.schedule = safeName(input.schedule ?? "always");
    if (create || input.policyAction !== undefined) {
      const action = input.action === "policy.deny" ? "deny" : (input.policyAction ?? "accept");
      if (!["accept", "deny"].includes(action)) fail("رفتار Policy معتبر نیست.");
      assignments.action = action;
    }
    if (create || input.nat !== undefined)
      assignments.nat = (input.nat ?? input.action === "policy.egress") ? "enable" : "disable";
    if (create || input.logTraffic !== undefined)
      assignments.logtraffic = input.logTraffic ?? "all";
    if (create || input.policyStatus !== undefined)
      assignments.status = input.policyStatus ?? "disable";
    if (assignments.logtraffic && !["all", "utm", "disable"].includes(assignments.logtraffic))
      fail("ثبت رویداد Policy معتبر نیست.");
    if (assignments.status && !["enable", "disable"].includes(assignments.status))
      fail("وضعیت Policy معتبر نیست.");
    if (!create && input.value) assignments.comments = comment(input.value);
    if (input.sourceCidr) {
      if (!create) fail("ساخت آدرس مبدأ فقط هنگام ایجاد Policy انجام می‌شود.");
      if (input.srcAddresses !== undefined)
        fail("آدرس موجود یا CIDR جدید را انتخاب کنید؛ هر دو هم‌زمان مجاز نیستند.");
      const {
        name: sourceName,
        subnet,
        commands: sourceCommands,
      } = fortiManagedSource(input.sourceCidr, tables);
      commands.push(...sourceCommands);
      assignments["__sourceName"] = sourceName;
      assignments["__sourceSubnet"] = subnet;
    }
    if (!Object.keys(assignments).length) fail("حداقل یک فیلد Policy را وارد کنید.");
  }
  commands.push("config firewall policy", create ? "edit 0" : `edit ${input.name}`);
  for (const [field, value] of Object.entries(assignments)) {
    if (field.startsWith("__")) continue;
    commands.push(
      `set ${field} ${["srcintf", "dstintf", "srcaddr", "dstaddr", "service"].includes(field) ? value.split(" ").map(quote).join(" ") : quoted.has(field) ? quote(value) : value}`,
    );
  }
  commands.push("next", "end");
  return { commands, assignments, memberNames: [] as string[] };
}
function normalizedSourceCidr(value: string) {
  const trimmed = value.trim();
  const cidr = trimmed.includes("/") ? trimmed : trimmed + "/32";
  fortiIpMask(cidr);
  return cidr;
}
function sourceSubnet(value: string) {
  return fortiIpMask(normalizedSourceCidr(value));
}
function generatedSourceName(cidr: string) {
  return "firewall-log-analyzer-src-" + normalizedSourceCidr(cidr).replace(/[^A-Za-z0-9]/g, "_");
}
export function fortiManagedSource(value: string, tables: FortiDependencyTables) {
  const name = generatedSourceName(value),
    subnet = sourceSubnet(value);
  const existing = (tables["firewall address"] ?? []).find((row) => row.name === name);
  if (
    existing &&
    (existing.settings.subnet?.join(" ") !== subnet ||
      !existing.settings.comment?.join(" ").startsWith("firewall-log-analyzer"))
  )
    fail("نام آدرس خودکار با شیء موجود ناسازگار است؛ مرجع موجود را صریح انتخاب کنید.");
  return {
    name,
    subnet,
    commands: existing
      ? []
      : [
          "config firewall address",
          `edit ${quote(name)}`,
          "set type ipmask",
          `set subnet ${subnet}`,
          'set comment "firewall-log-analyzer policy source"',
          "next",
          "end",
        ],
  };
}
export function assertFortiPolicy(
  input: FortiPreparedInput,
  plan: ReturnType<typeof compileFortiPolicy>,
  rows: FortiBlock[],
  tables: FortiDependencyTables,
) {
  const create = isFortiPolicyCreate(input.action),
    row = rows.find((r) => r.name === input.name);
  if (create ? rows.some((r) => r.settings.name?.[0] === input.name) : !row)
    fail(
      create
        ? "Policy هم‌نام موجود است؛ قانون جدید آن را بازنویسی نمی‌کند."
        : "Policy با این شناسه در تجهیز پیدا نشد.",
    );
  if (
    input.action === "policy.delete" &&
    !row?.settings.comments?.join(" ").startsWith("firewall-log-analyzer")
  )
    fail("این مسیر فقط Policy مدیریت‌شدهٔ سامانه را حذف می‌کند.");
  if (input.action === "policy.move" && !rows.some((r) => r.name === input.relativeTo))
    fail("Policy مقصد ترتیب پیدا نشد.");
  const has = (contexts: string[], name: string) =>
    contexts.some((context) => (tables[context] ?? []).some((r) => r.name === name));
  for (const field of ["srcintf", "dstintf"])
    for (const member of plan.assignments[field]?.split(" ") ?? []) {
      if (member !== "any" && !has(["system interface", "system zone"], member))
        fail(`رابط یا Zone ${member} پیدا نشد.`);
    }
  for (const field of ["srcaddr", "dstaddr"])
    for (const member of plan.assignments[field]?.split(" ") ?? []) {
      if (
        member !== "all" &&
        member !== plan.assignments.__sourceName &&
        !has(
          [
            "firewall address",
            "firewall addrgrp",
            ...(field === "dstaddr" ? ["firewall vip", "firewall vipgrp"] : []),
          ],
          member,
        )
      )
        fail(`مرجع آدرس ${member} پیدا نشد.`);
    }
  for (const service of plan.assignments.service?.split(" ") ?? [])
    if (service !== "ALL" && !has(["firewall service custom", "firewall service group"], service))
      fail(`سرویس ${service} پیدا نشد.`);
  if (
    plan.assignments.schedule &&
    plan.assignments.schedule !== "always" &&
    !has(["firewall schedule recurring"], plan.assignments.schedule)
  )
    fail("زمان‌بندی انتخاب‌شده پیدا نشد.");
  if (
    input.action === "policy.dnat" &&
    !plan.assignments.dstaddr
      ?.split(" ")
      .some((name) => has(["firewall vip", "firewall vipgrp"], name))
  )
    fail("Policy مقصد NAT باید به VIP یا گروه VIP موجود اشاره کند.");
}
export function fortiPolicyTarget(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
) {
  if (!isFortiPolicyCreate(input.action)) return rows.find((r) => r.name === input.name);
  const matches = rows.filter(
    (r) =>
      r.settings.name?.[0] === input.name && r.settings.comments?.join(" ") === expected.comments,
  );
  return matches.length === 1 ? matches[0] : undefined;
}
export function fortiPolicyMatches(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
  tables: FortiDependencyTables,
) {
  const row = fortiPolicyTarget(rows, input, expected);
  if (input.action === "policy.delete") return !row;
  if (!row) return false;
  if (input.action === "policy.move") {
    const offset = rows.indexOf(row),
      direction = expected.__before ? 1 : -1;
    return rows[offset + direction]?.name === (expected.__before ?? expected.__after);
  }
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
      return ["srcintf", "dstintf", "srcaddr", "dstaddr", "service"].includes(key)
        ? actual.split(" ").sort().join(" ") === value.split(" ").sort().join(" ")
        : actual === value;
    });
}
export function fortiPolicyBefore(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
  tables: FortiDependencyTables,
) {
  const row = isFortiPolicyCreate(input.action)
    ? undefined
    : rows.find((r) => r.name === input.name);
  return Object.fromEntries(
    Object.keys(expected).map((key) => {
      if (key === "__before" || key === "__after")
        return [
          key,
          row ? (rows[rows.indexOf(row) + (key === "__before" ? 1 : -1)]?.name ?? null) : null,
        ];
      const source = (tables["firewall address"] ?? []).find(
        (r) => r.name === expected.__sourceName,
      );
      if (key === "__sourceName") return [key, source?.name ?? null];
      if (key === "__sourceSubnet") return [key, source?.settings.subnet?.join(" ") ?? null];
      return [key, row?.settings[key]?.join(" ") ?? null];
    }),
  );
}
