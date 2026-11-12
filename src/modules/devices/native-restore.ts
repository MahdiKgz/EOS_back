import { BadGatewayException, ConflictException } from "@nestjs/common";
import { randomBytes } from "node:crypto";
import type { Device } from "./device.entity";
import type { SshCredentials } from "./linux-ssh";
import { runSshCommand } from "./ssh-transport";
import { collectBackup } from "./device-backup";
import { type RestoreVendor, assertCompatible } from "./restore-artifact";
import { restoreLinuxPhase } from "./linux-restore";

async function command(
  device: Device,
  credentials: SshCredentials,
  text: string,
  interactive = false,
  allowPromptChange = false,
) {
  const bytes = await runSshCommand(device, credentials, text, {
    interactive,
    allowPromptChange,
    timeout: 180000,
    maxBuffer: 256 * 1024,
    strictStderr: true,
  });
  if (
    /failure:|syntax error|bad command|not enough permissions|error:|Command fail|%\s*(?:Invalid|Error|Authorization|Incomplete)/i.test(
      bytes.toString("utf8"),
    )
  )
    throw new Error("Restore command rejected");
  return bytes;
}

export function normalizedConfiguration(vendor: RestoreVendor, content: Buffer) {
  let text = content.toString("utf8").replace(/\r/g, "");
  if (vendor === "cisco") {
    const lines = text.split("\n");
    const start = lines.findIndex((line) => /^(version|hostname)\s/.test(line));
    const end = lines.reduce((last, line, index) => (/^end\s*$/.test(line) ? index : last), -1);
    if (start < 0 || end < start) throw new Error("Invalid Cisco configuration");
    text = lines.slice(start, end + 1).join("\n");
  }
  return text
    .split("\n")
    .filter((line) => line.trim() && (vendor === "cisco" || !/^\s*#/.test(line)))
    .map((line) => line.trimEnd())
    .join("\n");
}

export async function preflightRestore(
  device: Device,
  credentials: SshCredentials,
  vendor: RestoreVendor,
  content: Buffer,
) {
  if (vendor === "linux") return restoreLinuxPhase(device, credentials, content, "preflight");
  if (vendor === "mikrotik") {
    const version = (await command(device, credentials, ":put [/system resource get version]"))
      .toString("utf8")
      .trim();
    const match = /^(\d+)\.(\d+)/.exec(version);
    if (!match || Number(match[1]) < 7 || (Number(match[1]) === 7 && Number(match[2]) < 16))
      throw new ConflictException(
        "بازیابی MikroTik به RouterOS 7.16 یا جدیدتر برای بررسی dry-run نیاز دارد.",
      );
  }
}

export async function verifyRestoredConfiguration(
  device: Device,
  credentials: SshCredentials,
  vendor: RestoreVendor,
  content: Buffer,
) {
  if (vendor === "linux") {
    await restoreLinuxPhase(device, credentials, content, "verify");
    return true;
  }
  const current = await collectBackup(device, credentials);
  assertCompatible(vendor, content, current.bytes);
  return (
    normalizedConfiguration(vendor, content) === normalizedConfiguration(vendor, current.bytes)
  );
}

export async function applyRestore(
  device: Device,
  credentials: SshCredentials,
  vendor: RestoreVendor,
  content: Buffer,
) {
  if (vendor === "linux") {
    await restoreLinuxPhase(device, credentials, content, "apply");
    return { verified: true, state: "files_verified_activation_required" };
  }
  const filename = "soar-" + randomBytes(16).toString("hex");
  try {
    if (vendor === "fortigate") {
      await runSshCommand(device, credentials, "scp -t fgt-restore-config", {
        scpUpload: { filename: filename + ".conf", content },
        timeout: 120000,
        strictStderr: true,
      });
      return { verified: false, state: "awaiting_verification" };
    }
    if (vendor === "mikrotik") {
      const path = filename + ".rsc";
      try {
        await runSshCommand(device, credentials, "sftp", {
          sftpUpload: { filename: path, content },
          timeout: 120000,
          strictStderr: true,
        });
        await command(device, credentials, `/import file-name="${path}" verbose=yes dry-run`);
        await command(device, credentials, `/import file-name="${path}" verbose=yes`);
      } finally {
        await command(device, credentials, `/file remove [find where name="${path}"]`).catch(
          () => undefined,
        );
      }
      const verified = await verifyRestoredConfiguration(device, credentials, vendor, content);
      return {
        verified,
        state: verified ? "configuration_verified" : "applied_merge_needs_review",
      };
    }
    const path = "flash:/" + filename + ".cfg";
    const lines = content.toString("utf8").replace(/\r/g, "").split("\n");
    const start = lines.findIndex((line) => /^(version|hostname)\s/.test(line));
    const end = lines.reduce((last, line, index) => (/^end\s*$/.test(line) ? index : last), -1);
    const candidate = Buffer.from(lines.slice(start, end + 1).join("\n") + "\n");
    try {
      await runSshCommand(device, credentials, "scp -t " + path, {
        scpUpload: { filename: filename + ".cfg", content: candidate },
        timeout: 120000,
        strictStderr: true,
      });
      await command(device, credentials, "configure replace " + path + " force time 3", true, true);
      if (!(await verifyRestoredConfiguration(device, credentials, vendor, content)))
        throw new Error("Cisco configuration not verified");
      await command(device, credentials, "configure confirm", true);
      return { verified: true, state: "running_configuration_verified" };
    } finally {
      await command(device, credentials, "delete /force " + path, true).catch(() => undefined);
    }
  } catch {
    throw new BadGatewayException(
      "نتیجهٔ اجرای بازیابی تأیید نشد. وضعیت تجهیز و فایل ایمنی را بررسی کنید.",
    );
  }
}
