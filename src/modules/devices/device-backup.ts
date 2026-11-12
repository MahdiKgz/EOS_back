import { BadGatewayException, BadRequestException } from "@nestjs/common";
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";
import type { Device } from "./device.entity";
import type { SshCredentials } from "./linux-ssh";
import { runSshCommand } from "./ssh-transport";
import { sshVaultKey } from "./ssh-credential-vault";
import { validateBackup, backupFilename } from "./backup-validation";

const profiles = {
  linux_edge: {
    key: "linux",
    extension: "tar.gz",
    scope: "آرشیو /etc؛ شامل دیتابیس، فایل کاربران و دیسک کامل نیست.",
  },
  cisco: {
    key: "cisco",
    extension: "cfg",
    scope: "تنظیمات جاری running-config؛ شامل startup-config و سیستم‌عامل نیست.",
  },
  mikrotik: {
    key: "mikrotik",
    extension: "rsc",
    scope: "خروجی متنی تنظیمات حساس؛ شامل فایل‌ها، گواهی‌ها و گذرواژه کاربران نیست.",
  },
  fortigate: {
    key: "fortigate",
    extension: "conf",
    scope: "فایل sys_config از SCP؛ دسترسی admin-scp لازم است. شامل Firmware نیست.",
  },
  pfsense: {
    key: "pfsense",
    extension: "xml",
    scope: "فایل config.xml؛ شامل سیستم‌عامل و فایل مستقل افزونه‌ها نیست.",
  },
} as const;

export function deviceBackupProfile(type: string) {
  return profiles[type as keyof typeof profiles] ?? null;
}

export async function collectBackup(device: Device, credentials: SshCredentials) {
  const profile = deviceBackupProfile(device.type);
  if (!profile || device.protocol !== "ssh")
    throw new BadRequestException("بک‌آپ برای این نوع تجهیز و مسیر اتصال آماده نیست.");
  const deadline = Date.now() + 65000;
  const options = { timeout: 60000, maxBuffer: 20 * 1024 * 1024, strictStderr: true };
  const read = (command: string, interactive = false) =>
    runSshCommand(device, credentials, command, {
      ...options,
      interactive,
      timeout: Math.max(1, Math.min(options.timeout, deadline - Date.now())),
    });
  let bytes: Buffer;
  try {
    switch (device.type) {
      case "linux_edge":
        try {
          bytes = await read('test "$(uname -s)" = Linux && tar -czf - -C / etc');
        } catch (error) {
          const stderr = String((error as { stderr?: Buffer }).stderr ?? "");
          if (!/permission denied|operation not permitted/i.test(stderr)) throw error;
          bytes = await read('test "$(uname -s)" = Linux && sudo -n tar -czf - -C / etc');
        }
        break;
      case "cisco":
        bytes = await read("show running-config", true);
        // CLI session framing is excluded from the downloadable configuration.
        {
          const output = bytes.toString("utf8").replace(/\r/g, "");
          const start = output.search(/^(?:!|version\s|hostname\s)/m);
          const ending = /^end\s*$/m.exec(output);
          if (start < 0 || !ending) throw new Error("Incomplete Cisco configuration");
          bytes = Buffer.from(output.slice(start, ending.index + 3) + "\n");
        }
        break;
      case "mikrotik": {
        const version = (await read(":put [/system resource get version]")).toString("utf8").trim();
        if (!/^[67]\./.test(version)) throw new Error("Unsupported RouterOS version");
        bytes = await read(
          version.startsWith("7.")
            ? "/export terse show-sensitive"
            : "/export terse hide-sensitive=no",
        );
        break;
      }
      case "fortigate":
        bytes = await runSshCommand(device, credentials, "scp -f sys_config", {
          ...options,
          scp: true,
          timeout: Math.max(1, deadline - Date.now()),
        });
        break;
      case "pfsense":
        bytes = await read(
          'test "$(uname -s)" = FreeBSD && test "$(/usr/local/bin/php -n /usr/local/sbin/read_global_var product_name)" = pfSense && cat /conf/config.xml',
        );
        break;
      default:
        throw new Error("Unsupported backup");
    }
    validateBackup(profile, bytes);
  } catch {
    throw new BadGatewayException(
      "دریافت بک‌آپ کامل انجام نشد. مجوز خواندن تنظیمات، کلید میزبان و اتصال SSH را بررسی کنید.",
    );
  }
  return {
    bytes,
    filename: backupFilename(device.name, profile.extension),
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

function backupKey() {
  return createHmac("sha256", sshVaultKey()).update("eos-device-backup").digest();
}

function backupContext(id: string, deviceId: string, workspaceOwnerId: string) {
  return Buffer.from(JSON.stringify(["eos-device-backup", id, deviceId, workspaceOwnerId]));
}

export function sealBackup(bytes: Buffer, id: string, deviceId: string, workspaceOwnerId: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", backupKey(), iv);
  cipher.setAAD(backupContext(id, deviceId, workspaceOwnerId));
  const data = Buffer.concat([cipher.update(bytes), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]);
}

export function unsealBackup(
  sealed: Buffer,
  id: string,
  deviceId: string,
  workspaceOwnerId: string,
) {
  const decipher = createDecipheriv("aes-256-gcm", backupKey(), sealed.subarray(0, 12));
  decipher.setAuthTag(sealed.subarray(12, 28));
  decipher.setAAD(backupContext(id, deviceId, workspaceOwnerId));
  return Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]);
}
