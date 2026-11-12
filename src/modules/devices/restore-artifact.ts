import { gunzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { validateBackup } from "./backup-validation";
import { deviceBackupProfile } from "./device-backup";
import { BadRequestException, ConflictException } from "@nestjs/common";

export const RESTORE_TEMPLATES = {
  linux: { id: "linux_restore_etc_files", method: "etc_overlay", connector: "linux-ssh" },
  cisco: {
    id: "cisco_restore_configuration",
    method: "replace_running",
    connector: "cisco-ios-xe-ssh",
  },
  mikrotik: {
    id: "mikrotik_restore_configuration",
    method: "import_merge",
    connector: "mikrotik-ssh",
  },
  fortigate: {
    id: "fortigate_restore_configuration",
    method: "native_scp",
    connector: "fortigate-ssh",
  },
} as const;
export type RestoreVendor = keyof typeof RESTORE_TEMPLATES;
export function restoreVendor(vendor: string): RestoreVendor {
  const key = deviceBackupProfile(vendor)?.key ?? vendor;
  if (!Object.hasOwn(RESTORE_TEMPLATES, key))
    throw new BadRequestException("بازیابی برای این نوع تجهیز پشتیبانی نمی‌شود.");
  return key as RestoreVendor;
}
export const digest = (data: Buffer) => createHash("sha256").update(data).digest("hex");
export function configIdentity(vendor: RestoreVendor, content: Buffer) {
  const text = content.toString("utf8");
  if (vendor === "cisco") return { version: text.match(/^version\s+(\S+)/m)?.[1] ?? "", model: "" };
  if (vendor === "mikrotik")
    return {
      version: text.match(/#.* by RouterOS\s+(\S+)/)?.[1] ?? "",
      model: text.match(/^#\s*model\s*=\s*(.+)$/m)?.[1]?.trim() ?? "",
      serial: text.match(/^#\s*serial number\s*=\s*(.+)$/m)?.[1]?.trim() ?? "",
    };
  if (vendor === "fortigate")
    return {
      version: text.match(/^#config-version=([^\r\n]+)/m)?.[1]?.split(":")[0] ?? "",
      model: "",
    };
  return { version: "", model: "" };
}
export function validateRestoreArtifact(vendor: RestoreVendor, data: Buffer) {
  try {
    validateBackup({ key: vendor }, data);
  } catch {
    throw new BadRequestException("فایل بازیابی معتبر نیست یا کامل دریافت نشده است.");
  }
  if (vendor !== "linux" && (data.includes(0) || !Buffer.from(data.toString("utf8")).equals(data)))
    throw new BadRequestException("فایل تنظیمات باید متن UTF-8 معتبر باشد.");
  if (vendor !== "linux" && !configIdentity(vendor, data).version)
    throw new BadRequestException("نسخهٔ سیستم‌عامل در فایل بازیابی مشخص نیست.");
  if (Object.values(configIdentity(vendor, data)).some((value) => value.length > 160))
    throw new BadRequestException("مشخصات هویتی فایل بازیابی معتبر نیست.");
  if (vendor === "fortigate" && data.includes(Buffer.from("FortinetPasswordMask")))
    throw new BadRequestException("فایل شامل رمزهای پوشانده‌شده است و برای بازیابی مناسب نیست.");
  if (vendor === "linux") linuxServiceFiles(data, true);
}
export function assertCompatible(vendor: RestoreVendor, uploaded: Buffer, current: Buffer) {
  validateRestoreArtifact(vendor, uploaded);
  if (vendor === "linux") return;
  const source = configIdentity(vendor, uploaded),
    target = configIdentity(vendor, current);
  if (
    !target.version ||
    source.version !== target.version ||
    (source.model && source.model !== target.model) ||
    ("serial" in source &&
      source.serial &&
      source.serial !== ("serial" in target ? target.serial : ""))
  ) {
    throw new ConflictException("نسخه، مدل یا شناسهٔ تجهیز با فایل بازیابی تطابق ندارد.");
  }
}
export type ServiceFile = {
  path: string;
  bytes: number;
  sha256: string;
  content: Buffer;
  kind: "file" | "directory" | "symlink";
  link: string;
  mode: number;
  uid: number;
  gid: number;
};
const SERVICE_PATH =
  /^etc\/(?:nginx|apache2|httpd|redis|mysql|postgresql|fail2ban)\/[A-Za-z0-9_./-]+$/;
export function linuxServiceFiles(data: Buffer, all = false): ServiceFile[] {
  const archive = gunzipSync(data, { maxOutputLength: 128 * 1024 * 1024 });
  const files: ServiceFile[] = [],
    seen = new Set<string>();
  let offset = 0,
    longName = "";
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const value = (start: number, end: number) =>
      header.subarray(start, end).toString("utf8").split("\0")[0];
    const size = parseInt(value(124, 136).trim(), 8);
    if (!Number.isSafeInteger(size) || size < 0 || offset + 512 + size > archive.length)
      throw new BadRequestException("فایل بازیابی معتبر نیست یا کامل دریافت نشده است.");
    const type = value(156, 157);
    const prefix = value(345, 500);
    let path = longName || (prefix ? prefix + "/" : "") + value(0, 100);
    longName = "";
    const content = archive.subarray(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;
    if (type === "L") {
      if (size > 4096) throw new BadRequestException("فایل بازیابی مسیر نامعتبر یا ناامن دارد.");
      longName = content.toString("utf8").split("\0")[0];
      continue;
    }
    // Extended headers/sparse records can override names or sizes; never extract them.
    if (["x", "g", "K", "S"].includes(type))
      throw new BadRequestException("قالب داخلی این آرشیو برای بازیابی پشتیبانی نمی‌شود.");
    path = path.replace(/^\.\//, "");
    if (
      path.startsWith("/") ||
      path.split("/").includes("..") ||
      path.includes("\\") ||
      path.includes("\0")
    )
      throw new BadRequestException("فایل بازیابی مسیر نامعتبر یا ناامن دارد.");
    path = path.replace(/\/$/, "");
    if (path.split("/").some((part) => !part || part === "." || part === ".."))
      throw new BadRequestException("فایل بازیابی مسیر نامعتبر یا ناامن دارد.");
    if (path === "etc" && type !== "5")
      throw new BadRequestException("فایل بازیابی مسیر نامعتبر یا ناامن دارد.");
    if (all && path !== "etc" && !path.startsWith("etc/"))
      throw new BadRequestException("فایل بازیابی مسیر نامعتبر یا ناامن دارد.");
    if (all && !["0", "", "2", "5"].includes(type))
      throw new BadRequestException("قالب داخلی این آرشیو برای بازیابی پشتیبانی نمی‌شود.");
    if ((all || SERVICE_PATH.test(path)) && ["0", "", "2", "5"].includes(type)) {
      if (seen.has(path) || size > 8 * 1024 * 1024 || files.length >= 10000)
        throw new BadRequestException("فایل بازیابی معتبر نیست یا کامل دریافت نشده است.");
      const kind = type === "2" ? "symlink" : type === "5" ? "directory" : "file";
      const link = kind === "symlink" ? value(157, 257) : "";
      if (kind === "symlink" && (!link || link.includes("\0")))
        throw new BadRequestException("فایل بازیابی مسیر نامعتبر یا ناامن دارد.");
      const number = (start: number, end: number) => {
        const text = value(start, end).trim();
        if (!/^[0-7]+$/.test(text))
          throw new BadRequestException("فایل بازیابی معتبر نیست یا کامل دریافت نشده است.");
        const result = parseInt(text, 8);
        if (!Number.isSafeInteger(result) || result > 2147483647)
          throw new BadRequestException("فایل بازیابی معتبر نیست یا کامل دریافت نشده است.");
        return result;
      };
      seen.add(path);
      files.push({
        path,
        bytes: size,
        sha256: digest(content),
        content,
        kind,
        link,
        mode: number(100, 108) & 0o777,
        uid: number(108, 116),
        gid: number(116, 124),
      });
    }
  }
  if (longName) throw new BadRequestException("فایل بازیابی معتبر نیست یا کامل دریافت نشده است.");
  const links = new Set(files.filter((file) => file.kind === "symlink").map((file) => file.path));
  if (
    files.some((file) =>
      file.path
        .split("/")
        .slice(0, -1)
        .some((_, i, parts) => links.has(parts.slice(0, i + 1).join("/"))),
    )
  )
    throw new BadRequestException("فایل بازیابی مسیر نامعتبر یا ناامن دارد.");
  if (files.reduce((sum, file) => sum + file.bytes, 0) > 64 * 1024 * 1024)
    throw new BadRequestException("فایل بازیابی معتبر نیست یا کامل دریافت نشده است.");
  return files;
}
