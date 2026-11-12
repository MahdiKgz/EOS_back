import { BadRequestException } from "@nestjs/common";
import type { FortiBlock } from "./fortigate-inventory";
import type { FortiDependencyTables, FortiPreparedInput } from "./fortigate-policy";
export const fortiVdomActions = [
  "vdom.create",
  "vdom.update",
  "vdom.moveInterface",
  "vdom.delete",
] as const;
export const isFortiVdomAction = (action: string) =>
  (fortiVdomActions as readonly string[]).includes(action);
const bad = (message: string): never => {
  throw new BadRequestException(message);
};
const name = (value: string, max = 31) =>
  new RegExp(`^[A-Za-z0-9_.:-]{1,${max}}$`).test(value)
    ? value
    : bad("نام VDOM یا رابط معتبر نیست.");
const quote = (value: string) => JSON.stringify(value);
export function fortiVdomResource(action: string) {
  return {
    context: action === "vdom.moveInterface" ? "system interface" : "system vdom",
    table: action === "vdom.moveInterface" ? "interfaces" : "vdoms",
    global: true,
    dependencies:
      action === "vdom.moveInterface"
        ? ["system vdom"]
        : action === "vdom.update"
          ? ["system vdom-property"]
          : action === "vdom.delete"
            ? ["system interface", "system admin", "system global"]
            : ["system global"],
  };
}
export function compileFortiVdom(input: FortiPreparedInput) {
  if (!isFortiVdomAction(input.action)) bad("عملیات VDOM ثبت نشده است.");
  name(input.name, input.action === "vdom.moveInterface" ? 15 : 31);
  const commands: string[] = [],
    assignments: Record<string, string> = {};
  if (input.action === "vdom.create") {
    assignments.exists = "present";
    commands.push("config vdom", `edit ${quote(input.name)}`, "next", "end");
  } else if (input.action === "vdom.delete") {
    assignments.exists = "absent";
    commands.push("config vdom", `delete ${quote(input.name)}`, "end");
  } else if (input.action === "vdom.moveInterface") {
    assignments.vdom = name(input.targetVdom ?? "");
    commands.push(
      "config system interface",
      `edit ${quote(input.name)}`,
      `set vdom ${quote(assignments.vdom)}`,
      "next",
      "end",
    );
  } else {
    if (input.vdomShortName === undefined && input.vdomDescription === undefined)
      bad("حداقل یک فیلد VDOM را برای تغییر انتخاب کنید.");
    if (input.vdomShortName !== undefined) {
      const value = input.vdomShortName;
      if (typeof value !== "string" || value.length > 11 || /\p{Cc}/u.test(value))
        bad("نام کوتاه باید حداکثر ۱۱ نویسه و بدون نویسهٔ کنترلی باشد.");
      assignments["short-name"] = value;
      commands.push(
        "config system vdom",
        `edit ${quote(input.name)}`,
        value ? `set short-name ${quote(value)}` : "unset short-name",
        "next",
        "end",
      );
    }
    if (input.vdomDescription !== undefined) {
      const value = input.vdomDescription;
      if (typeof value !== "string" || value.length > 127 || /\p{Cc}/u.test(value))
        bad("توضیح باید حداکثر ۱۲۷ نویسه و بدون نویسهٔ کنترلی باشد.");
      assignments.description = value;
      commands.push(
        "config system vdom-property",
        `edit ${quote(input.name)}`,
        value ? `set description ${quote(value)}` : "unset description",
        "next",
        "end",
      );
    }
  }
  return { commands, assignments, memberNames: [] as string[] };
}
export function assertFortiVdom(
  input: FortiPreparedInput,
  rows: FortiBlock[],
  tables: FortiDependencyTables,
) {
  if (tables.__fortios?.[0]?.settings.vdomMode?.[0] !== "enabled")
    bad(
      "مدیریت VDOM به حالت چندـVDOM موجود نیاز دارد؛ این عملیات حالت عمومی دستگاه را تغییر نمی‌دهد.",
    );
  const row = rows.find((r) => r.name === input.name);
  if (input.action === "vdom.create") {
    if (row) bad("VDOM هم‌نام موجود است؛ ساخت جدید آن را بازنویسی نمی‌کند.");
    return;
  }
  if (!row) bad("VDOM یا رابط هدف در تنظیم زنده پیدا نشد.");
  if (input.action === "vdom.delete") {
    const management =
      tables["system global"]?.find((r) => r.name === "system")?.settings["management-vdom"]?.[0] ??
      "root";
    if (input.name === "root" || input.name === management)
      bad("VDOM ریشه یا مدیریت قابل حذف نیست.");
  }
  if (input.action === "vdom.moveInterface") {
    if (!(tables["system vdom"] ?? []).some((r) => r.name === input.targetVdom))
      bad("VDOM مقصد باید از قبل وجود داشته باشد.");
    if (row!.settings.vdom?.[0] === input.targetVdom)
      bad("رابط از قبل در VDOM مقصد است؛ تغییری لازم نیست.");
  }
}
export function fortiVdomMatches(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
  tables: FortiDependencyTables,
) {
  if (tables.__fortios?.[0]?.settings.vdomMode?.[0] !== "enabled") return false;
  const row = rows.find((r) => r.name === input.name);
  if (input.action === "vdom.create") return !!row;
  if (input.action === "vdom.delete") return !row;
  if (!row) return false;
  if (input.action === "vdom.moveInterface")
    return (
      row.settings.vdom?.[0] === expected.vdom &&
      (tables["system vdom"] ?? []).some((r) => r.name === expected.vdom)
    );
  return Object.entries(expected).every(
    ([field, value]) =>
      (field === "description"
        ? (tables["system vdom-property"]
            ?.find((r) => r.name === input.name)
            ?.settings.description?.join(" ") ?? "")
        : (row.settings[field]?.join(" ") ?? "")) === value,
  );
}
export function fortiVdomBefore(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
  tables: FortiDependencyTables,
) {
  const row = rows.find((r) => r.name === input.name);
  return Object.fromEntries(
    Object.keys(expected).map((field) => [
      field,
      field === "exists"
        ? row
          ? "present"
          : null
        : field === "description"
          ? (tables["system vdom-property"]
              ?.find((r) => r.name === input.name)
              ?.settings.description?.join(" ") ?? null)
          : (row?.settings[field]?.join(" ") ?? null),
    ]),
  );
}
export function fortiVdomPrecheck(input: FortiPreparedInput, tables: FortiDependencyTables) {
  if (input.action !== "vdom.delete") return undefined;
  return {
    "رابط‌های منتسب به VDOM": String(
      (tables["system interface"] ?? []).filter((r) => r.settings.vdom?.includes(input.name))
        .length,
    ),
    "حساب‌های دارای دسترسی به VDOM": String(
      (tables["system admin"] ?? []).filter((r) => r.settings.vdom?.includes(input.name)).length,
    ),
    "بررسی وابستگی": "دستگاه مرجع‌های مانع را کنترل می‌کند؛ هیچ مرجعی خودکار پاک نمی‌شود.",
  };
}
export function fortiVdomMessage(input: FortiPreparedInput) {
  if (input.action === "vdom.create")
    return "VDOM تازه در حالت چندـVDOM موجود ساخته می‌شود. تأیید داخلی ساخت، در صورت درخواست دستگاه، فقط برای همین نام و پس از تأیید اجرای شما پاسخ داده می‌شود؛ تنظیم عمومی prompt تغییر نمی‌کند.";
  if (input.action === "vdom.update")
    return "فقط نام کوتاه و توضیح انتخاب‌شده تغییر می‌کنند؛ فیلد انتخاب‌نشده حفظ و فیلد انتخاب‌شده با مقدار خالی پاک می‌شود. این عملیات VDOM موجود را ویرایش می‌کند و VDOM تازه نمی‌سازد.";
  if (input.action === "vdom.moveInterface")
    return "رابط به VDOM موجود مقصد منتقل می‌شود. اگر رابط در پیکربندی استفاده شده باشد، دستگاه انتقال را رد می‌کند. مرجع‌ها خودکار پاک نمی‌شوند؛ ممکن است دسترسی مدیریت تغییر کند.";
  return "VDOM هدف حذف می‌شود؛ وجود مرجع مانع، ممکن است باعث رد فرمان توسط دستگاه شود. مرجع‌ها، رابط‌ها یا تنظیمات حساب‌ها خودکار حذف نمی‌شوند. نتیجه با خواندن دوباره بررسی می‌شود.";
}
