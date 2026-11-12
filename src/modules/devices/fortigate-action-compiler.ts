import { BadRequestException } from "@nestjs/common";
import { isIP } from "node:net";
import type { PreviewFortiActionDto } from "./fortigate-actions.dto";
export function fortiIpMask(value: string) {
  if (value.trim().split("/").length !== 2) throw new BadRequestException("قالب CIDR معتبر نیست.");
  const [ip, prefix] = value.trim().split("/");
  if (!isIP(ip) || isIP(ip) !== 4 || !/^\d{1,2}$/.test(prefix ?? "") || Number(prefix) > 32)
    throw new BadRequestException("آدرس IPv4 را همراه طول پیشوند CIDR وارد کنید.");
  const mask = 32 - Number(prefix),
    n = (2 ** 32 - 2 ** mask) >>> 0;
  return `${ip} ${[24, 16, 8, 0].map((shift) => (n >>> shift) & 255).join(".")}`;
}
export function compileFortiInterface(input: PreviewFortiActionDto) {
  if (
    !/^[A-Za-z0-9_.:-]{1,79}$/.test(input.name) ||
    (input.vdom && !/^[A-Za-z0-9_.:-]{1,79}$/.test(input.vdom)) ||
    (input.parent && !/^[A-Za-z0-9_.:-]{1,79}$/.test(input.parent))
  )
    throw new BadRequestException("نام رابط یا VDOM معتبر نیست.");
  if (
    ![
      "interface.alias",
      "interface.role",
      "interface.state",
      "interface.ip",
      "interface.vlan",
      "interface.allowaccess",
    ].includes(input.action)
  )
    throw new BadRequestException("عملیات ثبت نشده است.");
  const quote = (s: string) => '"' + s + '"';
  let field: string,
    value: string,
    lines: string[] = [];
  if (input.action === "interface.alias") {
    if (!new RegExp("^[A-Za-z0-9_.:/,@#() +*-]{1,180}$").test(input.value))
      throw new BadRequestException("متن alias دارای نویسهٔ نامعتبر است.");
    field = "alias";
    value = input.value;
  } else if (input.action === "interface.role") {
    if (!["wan", "lan", "dmz", "undefined"].includes(input.value))
      throw new BadRequestException("نقش رابط معتبر نیست.");
    field = "role";
    value = input.value;
  } else if (input.action === "interface.state") {
    if (!["up", "down"].includes(input.value))
      throw new BadRequestException("وضعیت رابط معتبر نیست.");
    field = "status";
    value = input.value;
  } else if (input.action === "interface.allowaccess") {
    const protocols = [
      ...new Set(
        input.value
          .toLowerCase()
          .split(/[,،\s]+/)
          .filter(Boolean),
      ),
    ];
    if (
      protocols.some(
        (p) =>
          ![
            "ping",
            "https",
            "ssh",
            "http",
            "fgfm",
            "snmp",
            "radius-acct",
            "probe-response",
            "fabric",
          ].includes(p),
      )
    )
      throw new BadRequestException("پروتکل دسترسی مدیریتی معتبر نیست.");
    field = "allowaccess";
    value = protocols.join(" ");
  } else if (input.action === "interface.ip") {
    field = "ip";
    value = fortiIpMask(input.value);
  } else {
    if (!input.parent || !input.vlanId || Number(input.vlanId) < 1 || Number(input.vlanId) > 4094)
      throw new BadRequestException("رابط والد و VLAN بین ۱ تا ۴۰۹۴ لازم است.");
    field = "ip";
    value = fortiIpMask(input.value);
    lines = [
      "set type vlan",
      `set interface ${quote(input.parent)}`,
      `set vlanid ${Number(input.vlanId)}`,
      'set alias "firewall-log-analyzer managed vlan interface"',
    ];
  }
  const assignments = {
    ...(input.action === "interface.vlan"
      ? {
          type: "vlan",
          interface: input.parent!,
          vlanid: String(Number(input.vlanId)),
          alias: "firewall-log-analyzer managed vlan interface",
        }
      : {}),
    [field]: value,
  };
  return {
    commands: [
      "config system interface",
      `edit ${quote(input.name)}`,
      ...lines,
      field === "allowaccess" && !value
        ? "unset allowaccess"
        : `set ${field} ${field === "alias" ? quote(value) : value}`,
      "next",
      "end",
    ],
    assignments,
  };
}
