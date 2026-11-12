import type { CiscoFailure } from "./cisco-types";
import type { CiscoReadCommandId } from "./cisco-commands";
import {
  detectCiscoPlatform,
  parseCiscoAccessLists,
  parseCiscoEtherChannels,
  parseCiscoInterfacesStatus,
  parseCiscoInventory,
  parseCiscoIpInterfaceBrief,
  parseCiscoSystemFacts,
  parseCiscoVlans,
} from "./cisco-parsers";

export type CiscoCapabilityState =
  | "supported"
  | "read_only"
  | "write_supported"
  | "not_configured"
  | "not_supported"
  | "unknown"
  | "requires_privilege";
export type CiscoCollectionState =
  "collected" | "partial" | "not_supported" | "command_failed" | "not_collected";

export type CiscoCommandEvidence = {
  commandId: string;
  state: CiscoCollectionState;
  lineCount: number;
  evidence: string[];
  errorCode?: string;
};

export const CISCO_IOS_CLASSIC_DISCOVERY_COMMANDS = [
  "platform",
  "inventory",
  "runningConfigHostname",
  "ipInterfaceBrief",
] as const satisfies readonly CiscoReadCommandId[];
export const CISCO_IOS_CLASSIC_INVENTORY_COMMANDS = [
  "inventory",
  "interfacesStatus",
  "interfacesErrors",
  "interfacesDetailed",
  "ipInterfaceBrief",
  "vlanBrief",
  "trunk",
  "route",
  "arp",
  "macAddressTable",
  "cdpNeighbors",
  "lldpNeighbors",
  "ospfNeighbors",
  "eigrpNeighbors",
  "bgpSummary",
  "acl",
  "nat",
  "dhcpPools",
  "dhcpBindings",
  "aaa",
  "localUsers",
  "sshStatus",
  "snmp",
  "logging",
  "ntpStatus",
  "clock",
  "cpu",
  "memory",
  "flash",
  "runningConfigMetadata",
  "startupConfigMetadata",
] as const satisfies readonly CiscoReadCommandId[];

const invalidCommandPattern =
  /%\s*(invalid input|ambiguous command|incomplete command|unknown command)|not supported|unrecognized command/i;
const requiresPrivilegePattern = /authorization failed|privilege|not authorized|permission denied/i;
const notConfiguredPattern =
  /not configured|not enabled|no .*configured|not running|is not active|no entries|none/i;

function lines(output: string) {
  return output
    .replace(/\r/g, "")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 256);
}

function commandState(
  commandId: string,
  output: string | undefined,
  failure?: CiscoFailure,
): CiscoCommandEvidence {
  if (failure)
    return {
      commandId,
      state:
        failure === "CISCO_COMMAND_NOT_SUPPORTED"
          ? "not_supported"
          : failure === "CISCO_DEADLINE"
            ? "not_collected"
            : "command_failed",
      lineCount: 0,
      evidence: [],
      errorCode: failure,
    };
  const text = String(output ?? "");
  const evidence = lines(text).slice(0, 3);
  if (!text.trim()) return { commandId, state: "not_collected", lineCount: 0, evidence: [] };
  if (requiresPrivilegePattern.test(text))
    return {
      commandId,
      state: "command_failed",
      lineCount: lines(text).length,
      evidence,
      errorCode: "CISCO_COMMAND_REQUIRES_PRIVILEGE",
    };
  if (invalidCommandPattern.test(text))
    return {
      commandId,
      state: "not_supported",
      lineCount: lines(text).length,
      evidence,
      errorCode: "CISCO_COMMAND_NOT_SUPPORTED",
    };
  if (notConfiguredPattern.test(text) && lines(text).length <= 4)
    return { commandId, state: "partial", lineCount: lines(text).length, evidence };
  return { commandId, state: "collected", lineCount: lines(text).length, evidence };
}

function capabilityFromEvidence(
  evidence: CiscoCommandEvidence | undefined,
  configuredWhenCollected = true,
): CiscoCapabilityState {
  if (!evidence || evidence.state === "not_collected") return "unknown";
  if (evidence.errorCode === "CISCO_COMMAND_REQUIRES_PRIVILEGE") return "requires_privilege";
  if (evidence.state === "not_supported") return "not_supported";
  if (evidence.state === "command_failed") return "unknown";
  if (evidence.state === "partial" && !configuredWhenCollected) return "not_configured";
  return "read_only";
}

function parseKeyValueLines(output: string) {
  return lines(output).map((line) => {
    const match = line.match(/^([^:]+):\s*(.+)$/);
    return match ? { key: match[1].trim(), value: match[2].trim(), raw: line } : { raw: line };
  });
}

function parseCpu(output: string) {
  const first = output.match(/five seconds:\s*(\d+)%/i),
    one = output.match(/one minute:\s*(\d+)%/i),
    five = output.match(/five minutes:\s*(\d+)%/i);
  const value = (match: RegExpMatchArray | null) =>
    match && Number(match[1]) <= 100 ? Number(match[1]) : null;
  return first
    ? { fiveSeconds: value(first), oneMinute: value(one), fiveMinutes: value(five) }
    : null;
}
function parseMemory(output: string) {
  const candidates = lines(output).flatMap((line) => {
    const pool = line.match(/^(.+?)\s+Pool Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)/i);
    const row = pool ?? line.match(/^([A-Za-z][\w/-]*)\s+(\d+)\s+(\d+)\s+(\d+)(?:\s|$)/);
    if (!row) return [];
    const [totalBytes, usedBytes, freeBytes] = row.slice(2, 5).map(Number);
    if (
      ![totalBytes, usedBytes, freeBytes].every(Number.isSafeInteger) ||
      totalBytes <= 0 ||
      usedBytes > totalBytes ||
      freeBytes > totalBytes
    )
      return [];
    return [{ name: row[1], totalBytes, usedBytes, freeBytes, raw: line }];
  });
  return candidates.slice(0, 16);
}

function parseFlash(output: string) {
  const match =
    output.match(/(\d+)\s+bytes\s+(?:total|available).*?(\d+)\s+bytes\s+(?:free|available)/is) ??
    output.match(/(\d+)\s+bytes\s+free/i);
  return {
    summary: lines(output).slice(-3),
    freeBytes: match ? Number(match[2] ?? match[1]) : null,
    rawLineCount: lines(output).length,
  };
}

function parseIpTable(output: string) {
  return lines(output)
    .filter((line) => !/^Protocol\s+Address|^Address\s+Age|^Codes:/i.test(line))
    .map((line) => ({ raw: line }));
}

function hasEntries(items: unknown[] | null | undefined) {
  return Array.isArray(items) && items.length > 0;
}

function groupState(
  evidence: CiscoCommandEvidence[],
  configuredWhenCollected = true,
): CiscoCollectionState {
  if (evidence.some((item) => item.state === "collected")) return "collected";
  if (evidence.some((item) => item.state === "partial"))
    return configuredWhenCollected ? "partial" : "not_supported";
  if (evidence.some((item) => item.state === "not_supported")) return "not_supported";
  if (evidence.some((item) => item.state === "command_failed")) return "command_failed";
  return "not_collected";
}

export function buildCiscoIosCapabilityProfile(
  outputs: Record<string, string>,
  failures: Partial<Record<string, CiscoFailure>> = {},
) {
  const evidence = Object.fromEntries(
    Object.entries(outputs).map(([commandId, output]) => [
      commandId,
      commandState(commandId, output, failures[commandId]),
    ]),
  ) as Record<string, CiscoCommandEvidence>;
  const platform = detectCiscoPlatform(outputs.platform ?? "").platform;
  return {
    platform,
    generatedAt: new Date().toISOString(),
    groups: {
      System: capabilityFromEvidence(evidence.platform),
      Inventory: capabilityFromEvidence(evidence.inventory),
      Interfaces: capabilityFromEvidence(evidence.ipInterfaceBrief ?? evidence.interfacesStatus),
      Switching: capabilityFromEvidence(evidence.vlanBrief),
      VLAN: capabilityFromEvidence(evidence.vlanBrief),
      Routing: capabilityFromEvidence(evidence.route),
      ACL: capabilityFromEvidence(evidence.acl, false),
      NAT: capabilityFromEvidence(evidence.nat, false),
      DHCP: capabilityFromEvidence(evidence.dhcpPools ?? evidence.dhcpBindings, false),
      AAA: capabilityFromEvidence(evidence.aaa, false),
      Monitoring: capabilityFromEvidence(evidence.logging ?? evidence.ntpStatus, false),
      Backup: capabilityFromEvidence(
        evidence.runningConfigMetadata ?? evidence.startupConfigMetadata,
      ),
      Diagnostics: capabilityFromEvidence(evidence.cpu ?? evidence.memory ?? evidence.flash),
      Security: capabilityFromEvidence(evidence.acl ?? evidence.sshStatus ?? evidence.snmp, false),
      Services: capabilityFromEvidence(
        evidence.ntpStatus ?? evidence.logging ?? evidence.snmp,
        false,
      ),
    },
    commandEvidence: evidence,
  };
}

export function parseCiscoInterfaceCounters(output: string) {
  return output
    .split(/\r?\n(?=\S+ is (?:up|down|administratively down))/)
    .flatMap((block) => {
      const name = block.match(/^(\S+) is (?:up|down|administratively down)/)?.[1];
      if (!name) return [];
      const read = (pattern: RegExp) => {
        const raw = block.match(pattern)?.[1];
        if (!raw) return null;
        const value = Number(raw);
        return Number.isSafeInteger(value) && value >= 0 ? value : null;
      };
      return [
        {
          name: name.slice(0, 128),
          rxBytes: read(/\d+ packets input,\s*(\d+) bytes/i),
          txBytes: read(/\d+ packets output,\s*(\d+) bytes/i),
        },
      ];
    })
    .slice(0, 32);
}
export function buildCiscoIosCollection(
  outputs: Record<string, string>,
  warnings: string[] = [],
  failures: Partial<Record<string, CiscoFailure>> = {},
) {
  const system = parseCiscoSystemFacts(
    outputs.platform ?? "",
    outputs.inventory ?? "",
    outputs.runningConfigHostname ?? "",
  );
  const inventory = parseCiscoInventory(outputs.inventory ?? "");
  const ipInterfaces = parseCiscoIpInterfaceBrief(outputs.ipInterfaceBrief ?? "");
  const switchportInterfaces = parseCiscoInterfacesStatus(outputs.interfacesStatus ?? "");
  const vlans = parseCiscoVlans(outputs.vlanBrief ?? "");
  const accessLists = parseCiscoAccessLists(outputs.acl ?? "");
  const profile = buildCiscoIosCapabilityProfile(outputs, failures);
  const commandEvidence = Object.values(profile.commandEvidence);
  const routeRows = parseIpTable(outputs.route ?? "");
  const arpRows = parseIpTable(outputs.arp ?? "");
  const macRows = parseIpTable(outputs.macAddressTable ?? "");
  const cdpRows = parseKeyValueLines(outputs.cdpNeighbors ?? "");
  const lldpRows = parseKeyValueLines(outputs.lldpNeighbors ?? "");
  const interfaceCount = Math.max(ipInterfaces.length, switchportInterfaces.length);
  const collectedCore =
    Boolean(system.iosVersion || system.model || system.hostname) && interfaceCount > 0;
  return {
    vendor: "cisco",
    platform: system.platform,
    platformFamily: system.platformFamily,
    collectedAt: new Date().toISOString(),
    inventoryStatus: collectedCore
      ? "collected"
      : commandEvidence.some((item) => item.state === "collected")
        ? "partial"
        : "not_collected",
    capabilityStatus: Object.values(profile.groups).some(
      (state) => state === "read_only" || state === "write_supported" || state === "supported",
    )
      ? "available"
      : "partial",
    system: {
      hostname: system.hostname,
      model: system.model,
      iosVersion: system.iosVersion,
      serialNumber: system.serialNumber,
      imageName: system.imageName,
      uptime: system.uptime,
      bootImage: system.bootImage,
      bootInformation: system.bootInformation,
      clock: lines(outputs.clock ?? "").slice(0, 4),
      license: lines(outputs.licenseSummary ?? "").slice(0, 40),
      inventory,
    },
    interfaceCounters: parseCiscoInterfaceCounters(outputs.interfacesDetailed ?? ""),
    interfaces: {
      state: groupState(
        [profile.commandEvidence.ipInterfaceBrief, profile.commandEvidence.interfacesStatus].filter(
          Boolean,
        ),
      ),
      summary: ipInterfaces,
      switchports: switchportInterfaces,
      errors: lines(outputs.interfacesErrors ?? "").slice(0, 200),
    },
    health: {
      state: groupState(
        [
          profile.commandEvidence.cpu,
          profile.commandEvidence.memory,
          profile.commandEvidence.flash,
        ].filter(Boolean),
      ),
      cpu: parseCpu(outputs.cpu ?? ""),
      memory: parseMemory(outputs.memory ?? ""),
      flash: parseFlash(outputs.flash ?? ""),
    },
    network: {
      trunk: {
        state: groupState([profile.commandEvidence.trunk].filter(Boolean), false),
        entries: parseKeyValueLines(outputs.trunk ?? ""),
      },
      etherchannel: {
        state: groupState([profile.commandEvidence.etherchannel].filter(Boolean), false),
        entries: parseCiscoEtherChannels(outputs.etherchannel ?? ""),
      },
      spanningTree: {
        state: groupState([profile.commandEvidence.spanningTree].filter(Boolean), false),
        entries: parseKeyValueLines(outputs.spanningTree ?? ""),
      },
      hosts: {
        state: groupState([profile.commandEvidence.hosts].filter(Boolean), false),
        entries: parseIpTable(outputs.hosts ?? ""),
      },
      arp: {
        state: groupState([profile.commandEvidence.arp].filter(Boolean), false),
        entries: arpRows,
      },
      macAddressTable: {
        state: groupState([profile.commandEvidence.macAddressTable].filter(Boolean), false),
        entries: macRows,
      },
      vlans: {
        state: groupState([profile.commandEvidence.vlanBrief].filter(Boolean), false),
        entries: vlans,
      },
      routingTable: {
        state: groupState([profile.commandEvidence.route].filter(Boolean), false),
        entries: routeRows,
      },
      staticRoutes: routeRows.filter((row) => /^S(?:\*|\s)/.test(row.raw)),
      ospfNeighbors: {
        state: groupState([profile.commandEvidence.ospfNeighbors].filter(Boolean), false),
        entries: parseIpTable(outputs.ospfNeighbors ?? ""),
      },
      eigrpNeighbors: {
        state: groupState([profile.commandEvidence.eigrpNeighbors].filter(Boolean), false),
        entries: parseIpTable(outputs.eigrpNeighbors ?? ""),
      },
      bgpSummary: {
        state: groupState([profile.commandEvidence.bgpSummary].filter(Boolean), false),
        entries: parseIpTable(outputs.bgpSummary ?? ""),
      },
      cdpNeighbors: {
        state: groupState([profile.commandEvidence.cdpNeighbors].filter(Boolean), false),
        entries: cdpRows,
      },
      lldpNeighbors: {
        state: groupState([profile.commandEvidence.lldpNeighbors].filter(Boolean), false),
        entries: lldpRows,
      },
    },
    configuration: {
      runningConfigMetadata: {
        state: groupState([profile.commandEvidence.runningConfigMetadata].filter(Boolean)),
        entries: parseKeyValueLines(outputs.runningConfigMetadata ?? ""),
      },
      startupConfigMetadata: {
        state: groupState([profile.commandEvidence.startupConfigMetadata].filter(Boolean)),
        entries: parseKeyValueLines(outputs.startupConfigMetadata ?? ""),
      },
      diffAvailability: profile.groups.Backup === "read_only" ? "read_only" : "unknown",
      unsavedChangeDetection: "unknown",
      safeBackupExport: profile.groups.Backup,
    },
    securityServices: {
      accessLists: {
        state: hasEntries(accessLists)
          ? "collected"
          : groupState([profile.commandEvidence.acl].filter(Boolean), false),
        entries: accessLists,
      },
      nat: {
        state: groupState([profile.commandEvidence.nat].filter(Boolean), false),
        entries: parseIpTable(outputs.nat ?? ""),
      },
      dhcpPools: {
        state: groupState([profile.commandEvidence.dhcpPools].filter(Boolean), false),
        entries: parseKeyValueLines(outputs.dhcpPools ?? ""),
      },
      dhcpBindings: {
        state: groupState([profile.commandEvidence.dhcpBindings].filter(Boolean), false),
        entries: parseIpTable(outputs.dhcpBindings ?? ""),
      },
      aaa: {
        state: groupState([profile.commandEvidence.aaa].filter(Boolean), false),
        entries: parseKeyValueLines(outputs.aaa ?? ""),
      },
      localUsers: {
        state: groupState([profile.commandEvidence.localUsers].filter(Boolean), false),
        entries: lines(outputs.localUsers ?? "").map((line) => ({
          username: line.match(/^username\s+(\S+)/i)?.[1] ?? "unknown",
          secretStored: /secret|password/i.test(line),
        })),
      },
      ssh: {
        state: groupState([profile.commandEvidence.sshStatus].filter(Boolean), false),
        entries: parseKeyValueLines(outputs.sshStatus ?? ""),
      },
      snmp: {
        state: groupState([profile.commandEvidence.snmp].filter(Boolean), false),
        entries: parseKeyValueLines(outputs.snmp ?? ""),
      },
      syslogDestinations: {
        state: groupState([profile.commandEvidence.logging].filter(Boolean), false),
        entries: lines(outputs.logging ?? "")
          .filter((line) => /logging host|trap logging|syslog/i.test(line))
          .map((line) => ({ raw: line })),
      },
      ntp: {
        state: groupState([profile.commandEvidence.ntpStatus].filter(Boolean), false),
        entries: parseKeyValueLines(outputs.ntpStatus ?? ""),
      },
    },
    capabilityProfile: profile,
    commandEvidence,
    warnings,
  };
}
export type CiscoCollection = ReturnType<typeof buildCiscoIosCollection>;
