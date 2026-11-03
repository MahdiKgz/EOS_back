import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { BadGatewayException, BadRequestException } from "@nestjs/common";
import { IsBoolean, IsIn, IsOptional, IsString, Matches, MaxLength } from "class-validator";
import type { Device } from "./device.entity";

const commands = {
  verify: "uname -s",
  interfaces: "ip -br link && ip -br address",
  monitoring: "uptime && free -m && df -h",
  backup:
    'for file in /etc/hostname /etc/hosts /etc/resolv.conf; do printf \'\\n--- %s ---\\n\' "$file"; cat "$file" || exit 1; done',
  diagnostics: "ip route show && ip -6 route show && ss -lntu",
} as const;

const operations = Object.keys(commands);
const execute = promisify(execFile);

export type SshCredentials = { username: string; hostKey: string } & (
  { privateKey: string; password?: never } | { password: string; privateKey?: never }
);

export class LinuxSshDto {
  @IsOptional()
  @IsBoolean()
  useSaved?: boolean;

  @IsOptional()
  @IsBoolean()
  saveConnection?: boolean;

  @IsIn(operations)
  operation!: keyof typeof commands;

  @IsOptional()
  @IsString()
  @Matches(/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/)
  username?: string;

  @IsOptional()
  @IsString()
  @MaxLength(12000)
  @Matches(/^-----BEGIN (?:(?:OPENSSH|RSA|EC) )?PRIVATE KEY-----/)
  privateKey?: string;

  @IsOptional()
  @IsString()
  @MaxLength(1024)
  @Matches(/^[^\r\n\0]+$/)
  password?: string;

  @IsOptional()
  @IsString()
  @MaxLength(2048)
  @Matches(/^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,2}$/)
  hostKey?: string;
}

export function requireSshCredentials(input: Partial<LinuxSshDto>): SshCredentials {
  const { username, hostKey, privateKey, password } = input;
  if (username && hostKey) {
    if (privateKey && !password) return { username, hostKey, privateKey };
    if (password && !privateKey) return { username, hostKey, password };
  }
  throw new BadRequestException(
    "نام کاربری، کلید عمومی میزبان و یکی از گذرواژه یا کلید خصوصی را وارد کنید.",
  );
}

export async function runLinuxSsh(
  device: Device,
  input: SshCredentials & { operation: LinuxSshDto["operation"] },
) {
  const directory = await mkdtemp(join(tmpdir(), "eos-ssh-"));
  const identity = join(directory, "identity");
  const knownHosts = join(directory, "known_hosts");
  try {
    const askpass = join(directory, "askpass");
    const passwordFile = join(directory, "password");
    if (input.password !== undefined) {
      await writeFile(passwordFile, input.password + "\n", { mode: 0o600 });
      await writeFile(askpass, '#!/bin/sh\nexec /bin/cat "$EOS_SSH_PASSWORD_FILE"\n', {
        mode: 0o700,
      });
    } else {
      await writeFile(identity, input.privateKey.trimEnd() + "\n", { mode: 0o600 });
    }
    await writeFile(knownHosts, `eos-device ${input.hostKey}\n`, { mode: 0o600 });
    const { stdout } = await execute(
      "ssh",
      [
        "-F",
        "/dev/null",
        "-o",
        input.password !== undefined ? "BatchMode=no" : "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        input.password !== undefined ? "PasswordAuthentication=yes" : "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        ...(input.password !== undefined
          ? ["-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1"]
          : ["-i", identity]),
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "HostKeyAlias=eos-device",
        "-o",
        `UserKnownHostsFile=${knownHosts}`,
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ClearAllForwardings=yes",
        "-p",
        String(device.managementPort),
        "-l",
        input.username,
        "--",
        device.host,
        `test "$(uname -s)" = Linux && ${commands[input.operation]}`,
      ],
      {
        timeout: 12000,
        maxBuffer: 256 * 1024,
        killSignal: "SIGKILL",
        env:
          input.password !== undefined
            ? {
                ...process.env,
                SSH_ASKPASS: askpass,
                SSH_ASKPASS_REQUIRE: "force",
                EOS_SSH_PASSWORD_FILE: passwordFile,
              }
            : process.env,
      },
    );
    return { output: stdout.trim(), checkedAt: new Date().toISOString() };
  } catch {
    throw new BadGatewayException(
      "عملیات SSH انجام نشد. کلید میزبان، نام کاربری، اعتبارنامه و دسترسی تجهیز را بررسی کنید.",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
