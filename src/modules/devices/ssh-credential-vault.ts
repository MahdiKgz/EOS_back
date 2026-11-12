import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import { ConflictException, ServiceUnavailableException } from "@nestjs/common";
import type { Device } from "./device.entity";
import type { RecorderConnectionDto } from "./device.dto";
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

function sealCredentials(device: CredentialContext, credentials: object, key: Buffer) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(context(device));
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(credentials), "utf8"),
    cipher.final(),
  ]);
  return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString("base64")).join(".");
}

function unsealCredentials<T>(device: CredentialContext, sealed: string, key: Buffer): T {
  try {
    const [iv, tag, encrypted] = sealed.split(".").map((part) => Buffer.from(part, "base64"));
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(context(device));
    decipher.setAuthTag(tag);
    return JSON.parse(
      Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8"),
    ) as T;
  } catch {
    throw new ConflictException(
      "اعتبارنامه ذخیره‌شده برای این آدرس قابل استفاده نیست. اتصال را دوباره ثبت کنید.",
    );
  }
}

export function sealSshCredentials(
  device: CredentialContext,
  credentials: SshCredentials,
  key: Buffer,
) {
  const auth =
    credentials.password !== undefined
      ? {
          username: credentials.username,
          hostKey: credentials.hostKey,
          password: credentials.password,
        }
      : {
          username: credentials.username,
          hostKey: credentials.hostKey,
          privateKey: credentials.privateKey,
        };
  return sealCredentials(device, auth, key);
}

export function unsealSshCredentials(device: CredentialContext, sealed: string, key: Buffer) {
  return unsealCredentials<SshCredentials>(device, sealed, key);
}

export function recorderVaultKey() {
  return createHmac("sha256", sshVaultKey()).update("eos-onvif").digest();
}

export function sealRecorderCredentials(
  device: CredentialContext,
  credentials: RecorderConnectionDto,
  key: Buffer,
) {
  return sealCredentials(device, credentials, key);
}

export function unsealRecorderCredentials(device: CredentialContext, sealed: string, key: Buffer) {
  return unsealCredentials<RecorderConnectionDto>(device, sealed, key);
}

export function sealSnmpCredentials(
  ownerId: string,
  id: string,
  secret: import("./snmpv3").SnmpSecret,
) {
  return sealCredentials(
    { id, workspaceOwnerId: ownerId, host: "snmp-credential-library", managementPort: 0 },
    secret,
    createHmac("sha256", sshVaultKey()).update("eos-snmpv3").digest(),
  );
}
export function unsealSnmpCredentials(ownerId: string, id: string, sealed: string) {
  return unsealCredentials<import("./snmpv3").SnmpSecret>(
    { id, workspaceOwnerId: ownerId, host: "snmp-credential-library", managementPort: 0 },
    sealed,
    createHmac("sha256", sshVaultKey()).update("eos-snmpv3").digest(),
  );
}

export type ApiSecret = {
  username: string;
  password: string;
  caCertificate?: string;
  tlsFingerprint?: string;
};
export function sealApiCredentials(ownerId: string, id: string, secret: ApiSecret) {
  return sealCredentials(
    { id, workspaceOwnerId: ownerId, host: "vendor-api-library", managementPort: 0 },
    secret,
    createHmac("sha256", sshVaultKey()).update("eos-vendor-api").digest(),
  );
}
export function unsealApiCredentials(ownerId: string, id: string, sealed: string) {
  return unsealCredentials<ApiSecret>(
    { id, workspaceOwnerId: ownerId, host: "vendor-api-library", managementPort: 0 },
    sealed,
    createHmac("sha256", sshVaultKey()).update("eos-vendor-api").digest(),
  );
}

export function sealCiscoEnable(ownerId: string, id: string, password: string) {
  return sealCredentials(
    { id, workspaceOwnerId: ownerId, host: "cisco-enable-credential-library", managementPort: 0 },
    { password },
    createHmac("sha256", sshVaultKey()).update("eos-cisco-enable").digest(),
  );
}
export function unsealCiscoEnable(ownerId: string, id: string, sealed: string) {
  return unsealCredentials<{ password: string }>(
    { id, workspaceOwnerId: ownerId, host: "cisco-enable-credential-library", managementPort: 0 },
    sealed,
    createHmac("sha256", sshVaultKey()).update("eos-cisco-enable").digest(),
  ).password;
}
