import { SaxesParser } from "saxes";
import type { Device } from "./device.entity";
import type { ApiSecret } from "./ssh-credential-vault";
import { VendorApiError, VendorHttpsClient, redactApiResult } from "./vendor-https";
const DISCOVERY_ENTITIES = [
  "Interface",
  "Zone",
  "Gateway",
  "FirewallRule",
  "IPHost",
  "Services",
  "VPNIPSecConnection",
  "VPNProfile",
] as const;
export type SophosInterface = {
  name: string;
  hardware: string;
  zone?: string;
  ipAddresses: string[];
  netmask?: string;
  macAddress?: string;
  speed?: string;
  operationalStatus: "up" | "down" | "unknown";
  administrativeStatus: "up" | "down" | "unknown";
};

export type SophosInventory = {
  kind: "sophos";
  product: "Sophos Firewall";
  apiVersion?: string;
  interfaces: SophosInterface[];
  zones: string[];
  gateways: string[];
  firewallRules: Array<{
    name: string;
    status: "enabled" | "disabled" | "unknown";
    action?: string;
    sourceZones: string[];
    destinationZones: string[];
    services: string[];
  }>;
  ipHosts: Array<{
    name: string;
    address?: string;
    hostType?: string;
    netmask?: string;
    ipFamily?: string;
  }>;
  services: Array<{ name: string; protocol?: string; ports: string[] }>;
  vpnConnections: Array<{
    name: string;
    status?: string;
    runtimeState?: "unknown";
    connectionType?: string;
    profile?: string;
    wanInterface?: string;
    remoteGateway?: string;
    localSubnet?: string;
    remoteNetworks?: string[];
    localId?: string;
    remoteId?: string;
    startupMode?: string;
    authenticationType?: string;
  }>;
  vpnProfiles?: Array<{
    name: string;
    keyingMethod?: string;
    ikeVersion?: string;
    phase1Encryption: string[];
    phase2Encryption: string[];
    phase1Authentication: string[];
    phase2Authentication: string[];
    dhGroups: string[];
  }>;
  collectionWarnings?: string[];
  collectedModules?: string[];
  collectedAt: string;
};

type XmlNode = {
  name: string;
  attributes: Record<string, string>;
  text: string;
  children: XmlNode[];
};
function parseResponse(xml: string): XmlNode {
  if (Buffer.byteLength(xml) > 12 * 1024 * 1024) throw new VendorApiError("SOPHOS_INVALID_XML");
  const container: XmlNode = { name: "root", attributes: {}, text: "", children: [] },
    stack = [container];
  const parser = new SaxesParser({ xmlns: true });
  let count = 0;
  parser.on("doctype", () => {
    throw new Error("DTD forbidden");
  });
  parser.on("opentag", (tag) => {
    if (stack.length > 64 || ++count > 50000) throw new Error("XML limit");
    const attributes = Object.fromEntries(
      Object.values(tag.attributes).map((attribute) => [attribute.local, attribute.value]),
    );
    const node: XmlNode = { name: tag.local, attributes, text: "", children: [] };
    stack[stack.length - 1].children.push(node);
    stack.push(node);
  });
  parser.on("text", (text) => {
    stack[stack.length - 1].text += text;
  });
  parser.on("cdata", (text) => {
    stack[stack.length - 1].text += text;
  });
  parser.on("closetag", () => {
    stack.pop();
  });
  try {
    parser.write(xml).close();
  } catch {
    throw new VendorApiError("SOPHOS_INVALID_XML");
  }
  const root = container.children[0];
  if (container.children.length !== 1 || root?.name !== "Response")
    throw new VendorApiError("SOPHOS_INVALID_XML");
  return root;
}
const child = (node: XmlNode | undefined, name: string) =>
  node?.children.find((item) => item.name === name);
const text = (node: XmlNode | undefined) => node?.text.trim().slice(0, 2000) ?? "";
const field = (node: XmlNode | undefined, name: string) => text(child(node, name));
function nodes(node: XmlNode | undefined, name: string): XmlNode[] {
  if (!node) return [];
  const nested = node.children.flatMap((item) => nodes(item, name));
  if (node.name === name && !nested.length) return [node];
  return nested.slice(0, 1000);
}
const values = (node: XmlNode | undefined, name: string) =>
  nodes(node, name).map(text).filter(Boolean);
const named = (node: XmlNode) => !!field(node, "Name");
function link(value: string): "up" | "down" | "unknown" {
  if (/^(up|connected|active|on|enable|enabled)$/i.test(value)) return "up";
  if (/^(down|disconnected|unplugged|inactive|off|disable|disabled)$/i.test(value)) return "down";
  return "unknown";
}
function discovery(root: XmlNode): SophosInventory {
  return {
    kind: "sophos",
    product: "Sophos Firewall",
    apiVersion: root.attributes.APIVersion?.slice(0, 80),
    interfaces: nodes(root, "Interface")
      .filter((node) => field(node, "Hardware") || field(node, "Name"))
      .map((node) => ({
        name: field(node, "Name") || field(node, "Hardware"),
        hardware: field(node, "Hardware") || field(node, "Name"),
        zone: field(node, "NetworkZone"),
        ipAddresses: values(node, "IPAddress"),
        netmask: field(node, "Netmask"),
        macAddress: field(node, "MACAddress"),
        speed: field(node, "InterfaceSpeed"),
        operationalStatus: link(field(node, "Status")),
        administrativeStatus: link(field(node, "InterfaceStatus")),
      })),
    zones: [
      ...new Set(
        nodes(root, "Zone")
          .map((node) => field(node, "Name") || text(node))
          .filter(Boolean),
      ),
    ],
    gateways: nodes(root, "Gateway")
      .map((node) => field(node, "Name") || field(node, "GatewayName") || text(node))
      .filter(Boolean),
    firewallRules: nodes(root, "FirewallRule")
      .filter(named)
      .map((node) => ({
        name: field(node, "Name"),
        status:
          link(field(node, "Status")) === "up"
            ? "enabled"
            : link(field(node, "Status")) === "down"
              ? "disabled"
              : "unknown",
        action: field(node, "Action"),
        sourceZones: values(child(node, "SourceZones"), "Zone"),
        destinationZones: values(child(node, "DestinationZones"), "Zone"),
        services: values(child(node, "Services"), "Service"),
      })),
    ipHosts: nodes(root, "IPHost")
      .filter(named)
      .map((node) => ({
        name: field(node, "Name"),
        address: field(node, "IPAddress"),
        hostType: field(node, "HostType"),
        netmask:
          field(node, "Subnet").match(/\((\d+\.\d+\.\d+\.\d+)\)/)?.[1] ||
          field(node, "Subnet") ||
          field(node, "Netmask"),
        ipFamily: field(node, "IPFamily"),
      })),
    services: nodes(root, "Services")
      .filter(named)
      .map((node) => ({
        name: field(node, "Name"),
        protocol: field(node, "Protocol"),
        ports: [
          ...values(node, "SourcePort"),
          ...values(node, "DestinationPort"),
          ...values(node, "Port"),
        ],
      })),
    vpnConnections: nodes(root, "VPNIPSecConnection")
      .flatMap((node) => nodes(node, "Configuration"))
      .filter(named)
      .map((node) => ({
        name: field(node, "Name"),
        status: field(node, "Status"),
        runtimeState: "unknown",
        connectionType: field(node, "ConnectionType"),
        profile: field(node, "Policy"),
        wanInterface: field(node, "LocalWANPort"),
        remoteGateway: field(node, "RemoteHost"),
        localSubnet: field(node, "LocalSubnet"),
        remoteNetworks: values(child(node, "RemoteNetwork"), "Network"),
        localId: field(node, "LocalID"),
        remoteId: field(node, "RemoteID"),
        startupMode: field(node, "ActionOnVPNRestart"),
        authenticationType: field(node, "AuthenticationType"),
      })),
    vpnProfiles: nodes(root, "VPNProfile")
      .filter(named)
      .map((node) => {
        const algorithms = (phase: string, algorithm: string) =>
          [1, 2, 3]
            .flatMap((index) => values(child(node, phase), `${algorithm}${index}`))
            .filter((value) => !/^(none|n\/a|-)$/i.test(value));
        return {
          name: field(node, "Name"),
          keyingMethod: field(node, "KeyingMethod"),
          ikeVersion: field(node, "IKEVersion"),
          phase1Encryption: algorithms("Phase1", "EncryptionAlgorithm"),
          phase2Encryption: algorithms("Phase2", "EncryptionAlgorithm"),
          phase1Authentication: algorithms("Phase1", "AuthenticationAlgorithm"),
          phase2Authentication: algorithms("Phase2", "AuthenticationAlgorithm"),
          dhGroups: values(child(node, "Phase1"), "DHGroup"),
        };
      }),
    collectedAt: new Date().toISOString(),
  };
}
const escapeXml = (value: string) =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
export async function collectSophosXml(
  device: Device,
  secret: ApiSecret,
): Promise<SophosInventory> {
  const client = await VendorHttpsClient.connect(device, secret, true);
  const inventory = discovery(parseResponse("<Response/>"));
  inventory.collectionWarnings = [];
  inventory.collectedModules = [];
  try {
    for (const entity of DISCOVERY_ENTITIES) {
      try {
        const xml = `<Request><Login><Username>${escapeXml(secret.username)}</Username><Password>${escapeXml(secret.password)}</Password></Login><Get><${entity}></${entity}></Get></Request>`;
        const response = await client.request("/webconsole/APIController", {
          method: "POST",
          body: new URLSearchParams({ reqxml: xml }).toString(),
          maxBytes: 12 * 1024 * 1024,
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "application/xml,text/xml",
          },
        });
        const root = parseResponse(response);
        const loginStatus = text(
          child(root, "Login")?.children.find((node) => node.name.toLowerCase() === "status"),
        );
        if (
          /authentication\s+(failed|failure)|invalid\s+(user|password|credential)|login\s+failed/i.test(
            loginStatus,
          )
        )
          throw new VendorApiError("SOPHOS_AUTH_FAILED");
        if (!/^Authentication Successful$/i.test(loginStatus))
          throw new VendorApiError("SOPHOS_AUTH_UNCONFIRMED");
        const failure = nodes(root, "Status")
          .map((node) => Number(node.attributes.code))
          .find((code) => Number.isFinite(code) && code >= 400);
        if (failure) throw new VendorApiError("SOPHOS_OPERATION_FAILED", failure);
        if (!nodes(root, entity).length) throw new VendorApiError("SOPHOS_MODULE_UNCONFIRMED");
        const data = discovery(root);
        inventory.apiVersion ??= data.apiVersion;
        if (entity === "Interface") inventory.interfaces = data.interfaces;
        else if (entity === "Zone") inventory.zones = data.zones;
        else if (entity === "Gateway") inventory.gateways = data.gateways;
        else if (entity === "FirewallRule") inventory.firewallRules = data.firewallRules;
        else if (entity === "IPHost") inventory.ipHosts = data.ipHosts;
        else if (entity === "Services") inventory.services = data.services;
        else if (entity === "VPNIPSecConnection") inventory.vpnConnections = data.vpnConnections;
        else inventory.vpnProfiles = data.vpnProfiles;
        inventory.collectedModules.push(entity);
      } catch (error) {
        if (
          !(error instanceof VendorApiError) ||
          !["SOPHOS_OPERATION_FAILED", "SOPHOS_MODULE_UNCONFIRMED"].includes(error.code)
        )
          throw error;
        inventory.collectionWarnings.push(
          `${entity}: ${error.code}${error.apiStatus ? ` (${error.apiStatus})` : ""}`,
        );
      }
    }
    if (
      !["Interface", "FirewallRule", "IPHost"].some((entity) =>
        inventory.collectedModules!.includes(entity),
      )
    )
      throw new VendorApiError("SOPHOS_DISCOVERY_UNAVAILABLE");
    inventory.collectedAt = new Date().toISOString();
    return {
      ...redactApiResult(inventory, secret),
      collectedModules: inventory.collectedModules,
      collectionWarnings: inventory.collectionWarnings,
    };
  } finally {
    client.close();
  }
}
