import { BadGatewayException } from "@nestjs/common";
import type { Device } from "./device.entity";
import type { SshCredentials } from "./linux-ssh";
import { linuxServiceFiles } from "./restore-artifact";
import { linuxReceiverCommand } from "./linux-restore-script";
import { runSshCommand } from "./ssh-transport";

export async function restoreLinuxPhase(
  device: Device,
  credentials: SshCredentials,
  content: Buffer,
  intent: "preflight" | "apply" | "verify",
) {
  const files = linuxServiceFiles(content, true);
  const payload = Buffer.from(
    JSON.stringify({
      intent,
      entries: files.map(({ content: bytes, ...entry }) => ({
        ...entry,
        data: bytes.toString("base64"),
      })),
    }),
  );
  try {
    const result = await runSshCommand(
      device,
      credentials,
      linuxReceiverCommand(credentials.username === "root"),
      {
        stdin: payload,
        timeout: 180000,
        maxBuffer: 256 * 1024,
        strictStderr: true,
      },
    );
    const evidence = JSON.parse(result.toString("utf8"));
    if (
      evidence.receiver !== "SOAR_ETC_RESTORE_V1" ||
      evidence.intent !== intent ||
      evidence.verified !== true ||
      evidence.entries !== files.length
    )
      throw new Error();
  } catch {
    throw new BadGatewayException(
      intent === "preflight"
        ? "پیش‌نیاز بازیابی تأیید نشد. دسترسی root یا sudo بدون گذرواژه و Python 3 لازم است."
        : "نتیجهٔ بازیابی فایل‌ها تأیید نشد. وضعیت تجهیز و بک‌آپ ایمنی را بررسی کنید.",
    );
  }
}
