import type { PlatformDetectionResult } from "./cisco-types";

const lineValue = (text: string, pattern: RegExp) =>
  text.match(pattern)?.[1]?.trim().slice(0, 256) ?? null;
const clean = (value: string | null | undefined) => value?.replace(/^"|"$/g, "").trim() || null;
const CISCO_SUPPORTED_PLATFORMS = new Set(["cisco-ios-xe", "cisco-ios-classic"]);

function normalizedText(output: string) {
  const ansiSequence = new RegExp(`${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`, "g");
  return output
    .replace(ansiSequence, "")
    .replace(/\r/g, "")
    .replace(/--More--|<--- More --->/gi, "")
    .split("\n")
    .slice(0, 256)
    .map((line) => line.slice(0, 1024))
    .join("\n");
}

export function isSupportedCiscoAutomationPlatform(platform: string | null | undefined) {
  return CISCO_SUPPORTED_PLATFORMS.has(String(platform ?? ""));
}

export function detectCiscoPlatform(showVersionOutput: string): PlatformDetectionResult {
  const text = normalizedText(showVersionOutput);
  const evidence: string[] = [];

  const version =
    lineValue(text, /Cisco IOS XE Software, Version\s+([^\n]+)/i) ??
    lineValue(text, /Cisco IOS Software[^\n]*, Version\s+([^,\n]+)/i) ??
    lineValue(text, /Version\s+([0-9][^,\n\s]+)/i);
  const model =
    lineValue(text, /Model Number\s*:\s*([^\n]+)/i) ??
    lineValue(text, /^cisco\s+(\S+)\s+\([^\n]+\)\s+processor/im) ??
    lineValue(text, /Cisco\s+(\S+)\s+\(revision/i);
  const hostname = lineValue(text, /^([^\s#>]+)\s+uptime is\s+/im);
  let platform = "cisco-unknown";
  let confidence = 20;
  if (/^\s*Cisco IOS(?:[- ]XE) Software\b/im.test(text)) {
    platform = "cisco-ios-xe";
    confidence = 90;
    evidence.push("show version contains IOS-XE marker");
  } else if (
    /^\s*(?:Cisco Nexus Operating System \(NX-OS\)|NX-OS(?: Software)?(?: version|[ ,]))/im.test(
      text,
    )
  ) {
    platform = "cisco-nx-os";
    confidence = 90;
    evidence.push("show version contains NX-OS marker");
  } else if (/^\s*Cisco IOS XR Software\b/im.test(text)) {
    platform = "cisco-ios-xr";
    confidence = 90;
    evidence.push("show version contains IOS XR marker");
  } else if (/^\s*Cisco (?:Adaptive Security Appliance|ASA) Software\b/im.test(text)) {
    platform = "cisco-asa";
    confidence = 90;
    evidence.push("show version contains ASA marker");
  } else if (/^\s*Cisco Firepower Threat Defense\b/im.test(text)) {
    platform = "cisco-ftd";
    confidence = 90;
    evidence.push("show version contains FTD marker");
  } else if (/^\s*Cisco IOS Software\b/im.test(text)) {
    platform = "cisco-ios-classic";
    confidence = 85;
    evidence.push("show version contains classic IOS marker");
  }
  if (version) evidence.push(`version=${version}`);
  if (model) evidence.push(`model=${model}`);
  return {
    vendor: "cisco",
    platform,
    version,
    model,
    hostname,
    confidence,
    evidence,
    supported: isSupportedCiscoAutomationPlatform(platform) && confidence >= 80,
  };
}

export function parseCiscoSystemFacts(
  showVersionOutput: string,
  showInventoryOutput = "",
  runningConfigHostnameOutput = "",
) {
  const versionText = normalizedText(showVersionOutput);
  const inventoryText = normalizedText(showInventoryOutput);
  const detection = detectCiscoPlatform(versionText);
  const hostnameFromConfig = lineValue(
    normalizedText(runningConfigHostnameOutput),
    /^hostname\s+(\S+)/im,
  );
  const imageName = clean(lineValue(versionText, /System image file is\s+"([^"]+)"/i));
  const bootImage = clean(
    lineValue(versionText, /BOOT path-list\s*:\s*([^\n]+)/i) ??
      lineValue(versionText, /BOOT variable\s*=\s*([^\n]+)/i),
  );
  const uptime = lineValue(versionText, /^\S+\s+uptime is\s+([^\n]+)/im);
  const serialNumber = clean(
    lineValue(versionText, /Processor board ID\s+(\S+)/i) ??
      lineValue(versionText, /System serial number\s*:\s*(\S+)/i) ??
      lineValue(inventoryText, /SN:\s*([^,\n\s]+)/i),
  );
  const model = clean(detection.model ?? lineValue(inventoryText, /PID:\s*([^,\n]+)/i));
  return {
    vendor: "cisco",
    platform: detection.platform,
    platformFamily:
      detection.platform === "cisco-ios-classic"
        ? "IOS Classic"
        : detection.platform === "cisco-ios-xe"
          ? "IOS-XE"
          : detection.platform,
    hostname: clean(detection.hostname ?? hostnameFromConfig),
    model,
    serialNumber,
    iosVersion: clean(String(detection.version ?? "")),
    imageName,
    uptime: clean(uptime),
    bootImage,
    bootInformation: bootImage ?? imageName,
    detection,
  };
}

export function parseCiscoInventory(output: string) {
  return normalizedText(output)
    .split(/\n(?=NAME:)/)
    .map((block) => {
      const name = lineValue(block, /NAME:\s*"?([^",\n]+)"?/i) ?? "unknown";
      const description = lineValue(block, /DESCR:\s*"?([^"\n]+)"?/i);
      const pid = lineValue(block, /PID:\s*([^,\n]+)/i);
      const vid = lineValue(block, /VID:\s*([^,\n]+)/i);
      const serialNumber = lineValue(block, /SN:\s*([^,\n\s]+)/i);
      return {
        name,
        description,
        model: clean(pid),
        version: clean(vid),
        serialNumber: clean(serialNumber),
        raw: block.trim(),
      };
    })
    .filter(
      (item) => item.raw.length > 0 && (item.name !== "unknown" || item.model || item.serialNumber),
    );
}

export function parseCiscoIpInterfaceBrief(output: string) {
  return normalizedText(output)
    .split(/\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => !/^Interface\s+/i.test(line))
    .filter((line) =>
      /^[A-Za-z][\w./:-]*\s+(?:unassigned|(?:\d{1,3}\.){3}\d{1,3})\s+(?:YES|NO)\s+/i.test(line),
    )
    .map((line) => {
      const parts = line.split(/\s+/);
      if (parts.length < 6) return null;
      const [name, ipAddress, ok, method, statusPart, ...protocolParts] = parts;
      const protocol = protocolParts.at(-1) ?? "unknown";
      const status = [statusPart, ...protocolParts.slice(0, -1)].join(" ") || "unknown";
      return {
        name,
        ipAddress: ipAddress === "unassigned" ? null : ipAddress,
        ok,
        method,
        administrativeStatus: status,
        operationalStatus: protocol,
        raw: line,
      };
    })
    .filter((item): item is NonNullable<typeof item> => item !== null);
}

export function parseCiscoInterfacesStatus(output: string) {
  const states =
    "connected|notconnect|disabled|err-disabled|inactive|monitoring|sfpAbsent|suspended";
  const rowPattern = new RegExp(
    String.raw`^(\S+)\s+(.*?)\s+(${states})\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$`,
    "i",
  );
  return normalizedText(output)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^[A-Za-z]+[\w/.-]+\s+/.test(line) && !/^Port\s+/i.test(line))
    .map((line) => {
      const match = line.match(rowPattern);
      if (match) {
        return {
          name: match[1],
          description: clean(match[2]),
          status: match[3].toLowerCase(),
          operationalStatus: match[3].toLowerCase() === "connected" ? "up" : "down",
          vlan: match[4],
          duplex: match[5],
          speed: match[6],
          mediaType: clean(match[7]),
          raw: line,
        };
      }
      const parts = line.split(/\s{2,}|\t+/).filter(Boolean);
      const [name = "unknown", nameOrStatus = "", statusMaybe = ""] = parts;
      const parsedStatus =
        /connected|notconnect|disabled|err-disabled|inactive|monitoring|sfpAbsent|suspended/i.test(
          nameOrStatus,
        )
          ? nameOrStatus
          : statusMaybe;
      return {
        name,
        description: null,
        status: parsedStatus.toLowerCase() || "unknown",
        operationalStatus:
          parsedStatus.toLowerCase() === "connected" ? "up" : parsedStatus ? "down" : "unknown",
        vlan: null,
        duplex: null,
        speed: null,
        mediaType: null,
        raw: line,
      };
    });
}

export function parseCiscoVlans(output: string) {
  return normalizedText(output)
    .split(/\r?\n/)
    .flatMap((line) => {
      const match = line.trim().match(/^(\d+)\s+(\S+)\s+(\S+)\s*(.*)$/);
      if (!match || Number(match[1]) < 1 || Number(match[1]) > 4094) return [];
      return [
        {
          vlanId: Number(match[1]),
          name: match[2],
          status: match[3],
          ports: match[4].split(/,\s*/).filter(Boolean),
          raw: line.trim(),
        },
      ];
    });
}

export function parseCiscoEtherChannels(output: string) {
  return normalizedText(output)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^\d+\s+\S+\s+\S+/.test(line))
    .map((line) => {
      const parts = line.split(/\s+/);
      return {
        group: parts[0],
        portChannel: parts[1],
        protocol: parts[2],
        ports: parts.slice(3),
        raw: line,
      };
    });
}

export function parseCiscoAccessLists(output: string) {
  return normalizedText(output)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => /access list|permit|deny/i.test(line))
    .map((line) => ({
      raw: line,
      action: line.match(/\b(permit|deny)\b/i)?.[1]?.toLowerCase() ?? "summary",
    }));
}
