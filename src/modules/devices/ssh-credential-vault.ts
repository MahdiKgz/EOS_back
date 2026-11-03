import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { ConflictException, ServiceUnavailableException } from "@nestjs/common";
import type { Device } from "./device.entity";
import type { SshCredentials } from "./linux-ssh";

export function sshVaultKey(): Buffer {
  const key = process.env.DEVICE_CREDENTIAL_KEY;
  if (!key || !/^[a-f0-9]{64}$/i.test(key))
    throw new ServiceUnavailableException(
      "مخزن رمزنگاری اعتبارنامه تجهیزات روی سرور تنظیم نشده است.",
    );
  return Buffer.from(key, "hex");
}

type CredentialContext = Pick<Device, "id" | "workspaceOwnerId" | "host" | "managementPort">;

function context(device: CredentialContext) {
  return Buffer.from(
    JSON.stringify([
      "eos-linux-ssh",
      device.id,
      device.workspaceOwnerId,
      device.host,
      device.managementPort,
    ]),
  );
}

export function sealSshCredentials(
  device: CredentialContext,
  credentials: SshCredentials,
  key: Buffer,
) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(context(device));
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(credentials), "utf8"),
    cipher.final(),
  ]);
  return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString("base64")).join(".");
}

export function unsealSshCredentials(
  device: CredentialContext,
  sealed: string,
  key: Buffer,
): SshCredentials {
  try {
    const [iv, tag, encrypted] = sealed.split(".").map((part) => Buffer.from(part, "base64"));
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(context(device));
    decipher.setAuthTag(tag);
    return JSON.parse(
      Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8"),
    ) as SshCredentials;
  } catch {
    throw new ConflictException(
      "اعتبارنامه ذخیره‌شده برای این آدرس قابل استفاده نیست. اتصال را دوباره ثبت کنید.",
    );
  }
}
