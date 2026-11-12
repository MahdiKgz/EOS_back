import { redactCiscoCredentials } from "./cisco-access-error";
import { CISCO_IOSXE_READ_COMMANDS, type CiscoReadCommandId } from "./cisco-commands";
import {
  buildCiscoIosCollection,
  CISCO_IOS_CLASSIC_DISCOVERY_COMMANDS,
  CISCO_IOS_CLASSIC_INVENTORY_COMMANDS,
} from "./cisco-inventory";
import { detectCiscoPlatform } from "./cisco-parsers";
import type { CiscoFailure } from "./cisco-types";
import type { Device } from "./device.entity";
import type { SshCredentials } from "./linux-ssh";
import { runSshCommand } from "./ssh-transport";
export function redactCiscoOutput(output: string, password?: string) {
  const clean = output
    .replace(/^(\s*enable\s+(?:secret|password)\s+).*$/gim, "$1[REDACTED]")
    .replace(
      /^(\s*username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+).*$/gim,
      "$1[REDACTED]",
    )
    .replace(/^\s*snmp-server\s+(?:user|community)\b.*$/gim, "snmp-server [REDACTED]")
    .replace(/^(\s*(?:tacacs-server|radius-server)\s+key\s+).*$/gim, "$1[REDACTED]")
    .replace(
      /\b(password|passphrase|private[-_ ]?key|secret|community|key-string|key)[ \t]*(?:[=:]|[ \t])[ \t]*\S+(?:[ \t]+\S+)?/gi,
      "$1 [REDACTED]",
    );
  return password ? clean.split(password).join("[REDACTED]") : clean;
}
function transcript(output: string, command: string) {
  const ansi = new RegExp(`${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`, "g");
  const clean = output
    .replace(ansi, "")
    .replace(/\r/g, "")
    .replace(/--More--|<--- More --->/gi, "");
  const lines = clean.split("\n");
  const echo = lines.findIndex(
    (line) =>
      line.trim() === command || line.trim().replace(/^[^\s]{1,120}[#>]\s*/, "") === command,
  );
  return (echo < 0 ? lines : lines.slice(echo + 1))
    .filter(
      (line) => !/^\s*[^\s]{1,120}(?: \([^)]+\))?\s*[#$>]\s*$/.test(line) && line.trim() !== "exit",
    )
    .slice(0, 256)
    .map((line) =>
      Array.from(line)
        .filter((c) => c.charCodeAt(0) >= 32 || c === "\t")
        .join("")
        .slice(0, 1024),
    )
    .join("\n");
}
function sanitize<T>(value: T, ...secrets: (string | undefined)[]): T {
  const controlled = new Set([
    "vendor",
    "platform",
    "platformFamily",
    "collectedAt",
    "state",
    "commandId",
    "errorCode",
    "inventoryStatus",
    "capabilityStatus",
    "diffAvailability",
    "unsavedChangeDetection",
    "safeBackupExport",
    "System",
    "Inventory",
    "Interfaces",
    "Switching",
    "VLAN",
    "Routing",
    "ACL",
    "NAT",
    "DHCP",
    "AAA",
    "Monitoring",
    "Backup",
    "Diagnostics",
    "Security",
    "Services",
  ]);
  return JSON.parse(
    JSON.stringify(value, (key, item: unknown) =>
      typeof item === "string" && !controlled.has(key)
        ? redactCiscoCredentials(item, secrets)
        : item,
    ),
  ) as T;
}
export async function collectCiscoInventory(device: Device, credentials: SshCredentials) {
  const deadline = Date.now() + 60000,
    outputs: Record<string, string> = {},
    failures: Partial<Record<string, CiscoFailure>> = {},
    warnings: string[] = [];
  let bytes = 0;
  const truncated = new Set<string>();
  const read = async (id: CiscoReadCommandId) => {
    const remaining = deadline - Date.now();
    if (remaining < 250) throw Object.assign(new Error("Deadline"), { code: "CISCO_DEADLINE" });
    const command = CISCO_IOSXE_READ_COMMANDS[id];
    const raw = await runSshCommand(device, credentials, command, {
      interactive: true,
      timeout: Math.min(8000, remaining),
      maxBuffer: 128 * 1024,
    });
    const rawText = raw.toString("utf8");
    if (rawText.split("\n").length > 256 || rawText.split("\n").some((line) => line.length > 1024))
      truncated.add(id);
    const value = redactCiscoOutput(transcript(rawText, command));
    bytes += raw.length;
    if (bytes > 2 * 1024 * 1024)
      throw Object.assign(new Error("Output limit"), { code: "CISCO_OUTPUT_LIMIT" });
    return value;
  };
  outputs.platform = await read("platform");
  const detection = detectCiscoPlatform(outputs.platform);
  if (!detection.supported)
    return sanitize(
      {
        detection,
        collection: null,
        warnings: ["CISCO_PLATFORM_UNSUPPORTED"],
        collectedAt: new Date().toISOString(),
      },
      credentials.password,
      credentials.cisco?.enableSecret,
    );
  const ids = [
    ...new Set<CiscoReadCommandId>([
      ...CISCO_IOS_CLASSIC_DISCOVERY_COMMANDS,
      ...CISCO_IOS_CLASSIC_INVENTORY_COMMANDS,
      "etherchannel",
      "spanningTree",
      "licenseSummary",
      "hosts",
    ]),
  ];
  for (const id of ids) {
    if (id === "platform") continue;
    outputs[id] = "";
    if (Date.now() >= deadline || bytes > 2 * 1024 * 1024) {
      failures[id] = bytes > 2 * 1024 * 1024 ? "CISCO_OUTPUT_LIMIT" : "CISCO_DEADLINE";
      continue;
    }
    try {
      outputs[id] = await read(id);
    } catch (error) {
      const code = (error as { code?: unknown })?.code;
      failures[id] =
        code === "SSH_COMMAND_UNSUPPORTED"
          ? "CISCO_COMMAND_NOT_SUPPORTED"
          : code === "SSH_COMMAND_REQUIRES_PRIVILEGE"
            ? "CISCO_COMMAND_REQUIRES_PRIVILEGE"
            : code === "CISCO_DEADLINE"
              ? "CISCO_DEADLINE"
              : code === "CISCO_OUTPUT_LIMIT" || code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"
                ? "CISCO_OUTPUT_LIMIT"
                : "CISCO_COMMAND_FAILED";
    }
  }
  if (Object.keys(failures).length) warnings.push("CISCO_PARTIAL_COLLECTION");
  if (truncated.size) warnings.push("CISCO_OUTPUT_TRUNCATED");
  const collection = buildCiscoIosCollection(outputs, warnings, failures);
  if (truncated.size) {
    collection.inventoryStatus = "partial";
    for (const item of collection.commandEvidence)
      if (truncated.has(item.commandId) && item.state === "collected") item.state = "partial";
  }
  return sanitize(
    { detection, collection, warnings, collectedAt: collection.collectedAt },
    credentials.password,
    credentials.cisco?.enableSecret,
  );
}
export type CiscoInventory = Awaited<ReturnType<typeof collectCiscoInventory>>;
