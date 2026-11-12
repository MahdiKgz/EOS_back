import { fortiIdentity } from "./fortigate-inventory";
import { redactFortiOutput } from "./fortigate-output";
import { ciscoAccessCode, ciscoAccessMessages, redactCiscoCredentials } from "./cisco-access-error";
import { runSshCommand } from "./ssh-transport";
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

const routerOsCommands = {
  verify: ':put ("EOSNET_ROUTEROS:" . [/system resource get version])',
  interfaces: "/interface print; /ip address print; /ipv6 address print",
  monitoring: "/system resource print",
  diagnostics: "/ip route print; /ipv6 route print",
  backup: undefined,
} satisfies Record<keyof typeof commands, string | undefined>;

const pfSenseCommands = {
  verify: "/usr/local/bin/php -n /usr/local/sbin/read_global_var product_version",
  interfaces: "ifconfig -a",
  monitoring: "uptime && swapinfo -h && df -h",
  diagnostics: "netstat -rn",
  backup: undefined,
} satisfies Record<keyof typeof commands, string | undefined>;

const esxiCommands = {
  verify: "vmware -v",
  interfaces: "esxcli network nic list && esxcli network ip interface ipv4 get",
  monitoring: "esxcli hardware memory get && esxcli storage filesystem list",
  diagnostics: "esxcli network ip route ipv4 list && esxcli network ip route ipv6 list",
  backup: undefined,
} satisfies Record<keyof typeof commands, string | undefined>;

const ciscoCommands = {
  verify: "show version",
  interfaces: "show ip interface brief",
  monitoring: "show processes cpu",
  diagnostics: "show ip route",
  backup: undefined,
} satisfies Record<keyof typeof commands, string | undefined>;

const fortiGateCommands = {
  verify: "get system status",
  interfaces: "get system interface physical",
  monitoring: "get system performance status",
  diagnostics: "get router info routing-table all",
  backup: undefined,
} satisfies Record<keyof typeof commands, string | undefined>;

const operations = Object.keys(commands);

export type SshCredentials = {
  username: string;
  hostKey: string;
  cisco?: { profile: "modern" | "legacy_cisco"; enableSecret?: string };
} & ({ privateKey: string; password?: never } | { password: string; privateKey?: never });

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
  const routerOs = device.type === "mikrotik";
  const pfSense = device.type === "pfsense";
  const pfSenseCommand = pfSenseCommands[input.operation];
  const esxi = device.type === "esxi";
  const esxiCommand = esxiCommands[input.operation];
  const fortiGate = device.type === "fortigate";
  const cisco = device.type === "cisco";
  const interactive = fortiGate || cisco;
  const command = interactive
    ? (cisco ? ciscoCommands : fortiGateCommands)[input.operation]
    : routerOs
      ? routerOsCommands[input.operation]
      : pfSense
        ? pfSenseCommand &&
          `test "$(uname -s)" = FreeBSD && test "$(/usr/local/bin/php -n /usr/local/sbin/read_global_var product_name)" = pfSense && ${pfSenseCommand}`
        : esxi
          ? esxiCommand &&
            (input.operation === "verify"
              ? esxiCommand
              : `vmware -v | grep -q '^VMware ESXi ' && ${esxiCommand}`)
          : `test "$(uname -s)" = Linux && ${commands[input.operation]}`;
  if (!command) throw new BadRequestException("این عملیات برای نوع تجهیز در دسترس نیست.");
  const verifyRouterOs = routerOs && input.operation === "verify";
  try {
    const output = (await runSshCommand(device, input, command, { interactive }))
      .toString("utf8")
      .trim();
    const verify = input.operation === "verify";
    const ciscoVersion =
      cisco && verify
        ? output.match(
            /^Cisco IOS(?:[- ]XE)? Software[^\r\n]{0,240}?, Version[ \t]+([^\s,]{1,80})/im,
          )?.[1]
        : undefined;
    if (cisco && verify && !ciscoVersion) throw new Error("Cisco IOS identity missing");
    const fortiGateVersion =
      fortiGate && verify && fortiIdentity(output).supported
        ? output.match(/^Version:[ \t]*(FortiGate[^\r\n]{1,160})/im)?.[1]
        : undefined;
    if (fortiGate && verify && !fortiGateVersion) throw new Error("FortiGate identity missing");
    const version = verifyRouterOs
      ? output.match(/^EOSNET_ROUTEROS:([0-9][^\r\n]{0,79})\r?$/m)?.[1]
      : undefined;
    if (verifyRouterOs && !version) throw new Error("RouterOS identity missing");
    const verifyEsxi = esxi && input.operation === "verify";
    const esxiVersion = verifyEsxi
      ? output.match(/^VMware ESXi ([0-9.]+ build-[0-9]+)$/m)?.[1]
      : undefined;
    if (verifyEsxi && !esxiVersion) throw new Error("ESXi identity missing");
    return {
      output: cisco
        ? redactCiscoCredentials(output, [input.password, input.cisco?.enableSecret])
        : fortiGate
          ? redactFortiOutput(output, input.password)
          : output,
      checkedAt: new Date().toISOString(),
      ...(ciscoVersion
        ? { identity: { Manufacturer: "Cisco", FirmwareVersion: ciscoVersion } }
        : {}),
      ...(fortiGateVersion
        ? { identity: { Manufacturer: "Fortinet", FirmwareVersion: fortiGateVersion } }
        : {}),
      ...(version ? { identity: { Manufacturer: "MikroTik", FirmwareVersion: version } } : {}),
      ...(esxiVersion
        ? { identity: { Manufacturer: "VMware", FirmwareVersion: esxiVersion } }
        : {}),
      ...(pfSense && input.operation === "verify"
        ? { identity: { Manufacturer: "pfSense", FirmwareVersion: output.slice(0, 80) } }
        : {}),
    };
  } catch (error) {
    if (cisco) {
      const code = ciscoAccessCode(error);
      throw new BadGatewayException({ message: ciscoAccessMessages[code], code });
    }
    throw new BadGatewayException(
      "عملیات SSH انجام نشد. کلید میزبان، نام کاربری، اعتبارنامه و دسترسی تجهیز را بررسی کنید.",
    );
  }
}
