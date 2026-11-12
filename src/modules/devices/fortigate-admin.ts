import { BadRequestException } from "@nestjs/common";
import { fortiIpMask } from "./fortigate-action-compiler";
import type { FortiBlock } from "./fortigate-inventory";
import type { FortiDependencyTables, FortiPreparedInput } from "./fortigate-policy";
export const fortiAdminActions = [
  "admin.create",
  "admin.trusthost",
  "admin.disable",
  "admin.delete",
  "apiUser.create",
  "management.httpsPort",
  "management.disableService",
] as const;
export const isFortiAdminAction = (action: string) =>
  (fortiAdminActions as readonly string[]).includes(action);
export const fortiAdminPasswordPlaceholder = "set password __EOS_PRIVATE_ADMIN_PASSWORD__";
export function fortiAdminResource(action: string) {
  if (action.startsWith("management."))
    return {
      context: "system global",
      table: "managementSettings",
      dependencies: [] as string[],
      global: true,
    };
  return {
    context: action === "apiUser.create" ? "system api-user" : "system admin",
    table: action === "apiUser.create" ? "apiUsers" : "admins",
    dependencies: action.endsWith(".create")
      ? ["system accprofile", "system vdom"]
      : ([] as string[]),
    global: true,
  };
}
const bad = (message: string): never => {
  throw new BadRequestException(message);
};
const name = (value: string, max = 35) =>
  new RegExp(`^[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,${max - 1}}$`).test(value)
    ? value
    : bad("نام حساب یا پروفایل معتبر نیست.");
const quote = (value: string) => JSON.stringify(value);
export function fortiAdminPasswordLine(password: string) {
  if (!password || /\p{Cc}/u.test(password) || Buffer.byteLength(password, "utf8") > 4096)
    bad("گذرواژهٔ انتخاب‌شده برای CLI معتبر نیست؛ از گذرواژهٔ بدون نویسهٔ کنترلی استفاده کنید.");
  return "set password " + quote(password);
}
export function compileFortiAdmin(input: FortiPreparedInput) {
  if (!isFortiAdminAction(input.action)) bad("عملیات مدیریت ثبت نشده است.");
  const resource = fortiAdminResource(input.action),
    assignments: Record<string, string> = {},
    commands: string[] = [];
  if (input.action.startsWith("management.")) {
    if (input.name !== "system") bad("هدف تنظیم عمومی باید system باشد.");
    if (input.action === "management.httpsPort") {
      if (!/^\d{1,5}$/.test(input.value) || +input.value < 1 || +input.value > 65535)
        bad("پورت HTTPS باید بین ۱ تا ۶۵۵۳۵ باشد.");
      assignments["admin-sport"] = String(+input.value);
    } else {
      if (!["telnet", "ssh-v1", "ssh-password", "scp"].includes(input.value))
        bad(
          "این سرویس کلید عمومی معتبر ندارد؛ برای HTTP/HTTPS/SSH از دسترسی مدیریتی رابط استفاده کنید.",
        );
      assignments["admin-" + input.value] = "disable";
    }
    commands.push(
      "config system global",
      ...Object.entries(assignments).map(([key, value]) => `set ${key} ${value}`),
      "end",
    );
  } else {
    name(input.name);
    if (input.action === "admin.delete")
      return {
        commands: [`config ${resource.context}`, `delete ${quote(input.name)}`, "end"],
        assignments: { exists: "absent" } as Record<string, string>,
        memberNames: [] as string[],
      };
    if (input.action.endsWith(".create")) {
      assignments.accprofile = name(input.adminProfile ?? "");
      const vdoms = [
        ...new Set(
          (input.accountVdoms ?? "root")
            .split(/[,،\s]+/)
            .filter(Boolean)
            .map((v) => name(v, 79)),
        ),
      ];
      if (!vdoms.length || vdoms.length > 64) bad("فهرست VDOM حساب معتبر نیست.");
      assignments.vdom = vdoms.join(" ");
      if (input.action === "admin.create") {
        if (!input.adminSecretId) bad("اعتبارنامهٔ گذرواژه برای ساخت ادمین لازم است.");
        assignments["remote-auth"] = "disable";
        assignments.wildcard = "disable";
        assignments.__password = "configured";
      }
    } else if (input.action === "admin.trusthost")
      assignments.trusthost1 = fortiIpMask(
        input.value.includes("/") ? input.value : input.value + "/32",
      );
    else assignments["disallowed-login-methods"] = "console gui ssh telnet";
    commands.push(`config ${resource.context}`, `edit ${quote(input.name)}`);
    for (const [field, value] of Object.entries(assignments))
      if (!field.startsWith("__"))
        commands.push(
          `set ${field} ${field === "vdom" ? value.split(" ").map(quote).join(" ") : field === "accprofile" ? quote(value) : value}`,
        );
    if (input.action === "admin.create") commands.push(fortiAdminPasswordPlaceholder);
    commands.push("next", "end");
  }
  return { commands, assignments, memberNames: [] as string[] };
}
export function assertFortiAdmin(
  input: FortiPreparedInput,
  rows: FortiBlock[],
  tables: FortiDependencyTables,
) {
  const row = rows.find((r) => r.name === input.name);
  if (input.action.endsWith(".create") ? !!row : !row)
    bad(
      input.action.endsWith(".create")
        ? "حساب هم‌نام موجود است؛ ساخت جدید آن را بازنویسی نمی‌کند."
        : "هدف در تنظیم زنده پیدا نشد.",
    );
  if (input.action.endsWith(".create")) {
    const profile = input.adminProfile ?? "";
    if (
      !["super_admin", "super_admin_readonly", "prof_admin"].includes(profile) &&
      !(tables["system accprofile"] ?? []).some((r) => r.name === profile)
    )
      bad("پروفایل دسترسی انتخاب‌شده پیدا نشد.");
    const vdoms = (input.accountVdoms ?? "root").split(/[,،\s]+/).filter(Boolean);
    const mode = tables.__fortios?.[0]?.settings.vdomMode?.[0];
    if (
      vdoms.some((vdom) =>
        mode === "disabled"
          ? vdom !== "root"
          : !(tables["system vdom"] ?? []).some((r) => r.name === vdom),
      )
    )
      bad("VDOM انتخاب‌شده برای حساب پیدا نشد.");
  }
  if (input.action === "admin.disable") {
    const major = Number(tables.__fortios?.[0]?.settings.version?.[0]?.split(".")[0] ?? 0);
    if (major < 8)
      bad(
        "غیرفعال‌سازی بومی روش‌های ورود به FortiOS ۸ یا جدیدتر نیاز دارد؛ برای این نسخه برنامهٔ اجرایی ساخته نشد.",
      );
  }
}
export function fortiAdminMatches(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
) {
  const row = rows.find((r) => r.name === input.name);
  if (input.action === "admin.delete") return !row;
  if (!row) return false;
  return Object.entries(expected).every(([field, value]) => {
    if (field === "__password")
      return /^(?:ENC|SH2|PBKDF2)\b/i.test(row.settings.password?.join(" ") ?? "");
    const actual = row.settings[field]?.join(" ") ?? "";
    return field === "vdom" || field === "disallowed-login-methods"
      ? actual.split(" ").sort().join(" ") === value.split(" ").sort().join(" ")
      : actual === value;
  });
}
export function fortiAdminBefore(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
) {
  const row = rows.find((r) => r.name === input.name);
  return Object.fromEntries(
    Object.keys(expected).map((field) => [
      field,
      field === "__password"
        ? row?.settings.password?.length
          ? "configured"
          : null
        : (row?.settings[field]?.join(" ") ?? null),
    ]),
  );
}
export function fortiAdminMessage(input: FortiPreparedInput) {
  if (input.action === "apiUser.create")
    return "فقط پیکربندی حساب API ساخته می‌شود؛ کلید API در این عملیات تولید یا نمایش داده نمی‌شود.";
  if (input.action === "admin.create")
    return "حساب محلی با پروفایل و VDOM مشخص ساخته می‌شود؛ گذرواژه فقط هنگام اجرا از مخزن شخصی خوانده و به CLI ارسال می‌شود.";
  return "این تغییر بر دسترسی مدیریتی کل تجهیز اثر می‌گذارد؛ نتیجه از تنظیم زنده خوانده می‌شود و قطع اتصال موفقیت فرض نمی‌شود.";
}
