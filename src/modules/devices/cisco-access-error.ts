import type { ConnectConfig } from "ssh2";
// Compatibility is explicitly selected per Cisco device; defaults remain unchanged.
export const legacyCiscoOptions = [
  "-o",
  "KexAlgorithms=+diffie-hellman-group14-sha1",
  "-o",
  "HostKeyAlgorithms=+ssh-rsa",
  "-o",
  "PubkeyAcceptedAlgorithms=+ssh-rsa",
  "-o",
  "Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc",
  "-o",
  "MACs=+hmac-sha1,hmac-sha1-96",
];
export const legacyCiscoAlgorithms: NonNullable<ConnectConfig["algorithms"]> = {
  kex: { remove: [], prepend: [], append: ["diffie-hellman-group14-sha1"] },
  serverHostKey: { remove: [], prepend: [], append: ["ssh-rsa"] },
  cipher: {
    remove: [],
    prepend: [],
    append: ["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"],
  },
  hmac: { remove: [], prepend: [], append: ["hmac-sha1", "hmac-sha1-96"] },
};
export const ciscoAccessMessages: Record<string, string> = {
  CISCO_ENABLE_REQUIRED:
    "اتصال در سطح کاربر است. اعتبارنامهٔ جداگانهٔ enable را انتخاب و دوباره تست کنید.",
  CISCO_ENABLE_FAILED: "ورود به سطح enable انجام نشد. گذرواژه و مجوز این اعتبارنامه را بررسی کنید.",
  CISCO_HOST_KEY_MISMATCH: "کلید میزبان Cisco مطابقت ندارد. کلید ثبت‌شده را بررسی کنید.",
  CISCO_AUTH_FAILED: "ورود SSH انجام نشد. نام کاربری و اعتبارنامهٔ اتصال را بررسی کنید.",
  CISCO_NEGOTIATION_FAILED:
    "الگوریتم‌های SSH سازگار نیستند. برای Cisco قدیمی، پروفایل اتصال قدیمی را بررسی کنید.",
  CISCO_OUTPUT_LIMIT: "حجم خروجی Cisco از سقف مجاز بیشتر شد. گردآوری کامل نشد.",
  CISCO_CONNECTION_FAILED: "اتصال SSH به Cisco انجام نشد. آدرس، پورت و دسترسی شبکه را بررسی کنید.",
};
export function ciscoAccessCode(error: unknown) {
  const code = (error as { code?: unknown })?.code;
  return typeof code === "string" && Object.hasOwn(ciscoAccessMessages, code)
    ? code
    : "CISCO_CONNECTION_FAILED";
}
export function ciscoAccessError(code: string) {
  return Object.assign(
    new Error(ciscoAccessMessages[code] ?? ciscoAccessMessages.CISCO_CONNECTION_FAILED),
    { code },
  );
}
export function redactCiscoCredentials(value: string, secrets: (string | undefined)[]) {
  return secrets
    .filter((secret): secret is string => !!secret)
    .sort((a, b) => b.length - a.length)
    .reduce((text, secret) => text.split(secret).join("[REDACTED]"), value);
}
