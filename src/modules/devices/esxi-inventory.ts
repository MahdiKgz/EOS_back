import type { Device } from "./device.entity";
import type { ApiSecret } from "./ssh-credential-vault";
import {
  EsxiSoapClient,
  EsxiSoapError,
  child,
  children,
  field,
  references,
  value,
  type XmlNode,
} from "./esxi-soap";

export type EsxiVm = {
  id: string;
  name: string;
  powerState: string;
  guest?: string;
  cpuCount: number | null;
  memoryMb: number | null;
};
export type EsxiDatastore = {
  id: string;
  name: string;
  capacityBytes: number | null;
  freeBytes: number | null;
  accessible: boolean | null;
};
export type EsxiDiscovery = {
  transport?: "ssh" | "api";
  hostId: string;
  hostname: string;
  version: string;
  build: string;
  model: string;
  hardwareVendor: string;
  serialNumber: string;
  biosVersion: string;
  lockdownMode: string;
  connectionState: string;
  overallStatus: string;
  maintenanceMode: boolean | null;
  bootTime: string | null;
  cpuPercent: number | null;
  memoryPercent: number | null;
  cpuCores: number | null;
  memoryBytes: number | null;
  vmCount: number | null;
  vms: EsxiVm[];
  vmsTruncated: boolean;
  datastores: EsxiDatastore[];
  datastoreCount: number | null;
  networks: string[];
  sensors: Array<{ name: string; state: string; reading: number | null; unit: string }>;
  services: Array<{
    key: string;
    label: string;
    running: boolean | null;
    policy: string;
    required: boolean | null;
  }>;
  storageAdapters: Array<{ name: string; model: string; driver: string; status: string }>;
  storageDevices: Array<{
    name: string;
    displayName: string;
    deviceType: string;
    operationalState: string;
  }>;
  firewallRulesets: Array<{
    key: string;
    label: string;
    enabled: boolean | null;
    required: boolean | null;
  }>;
  physicalNics: Array<{ name: string; linkUp: boolean | null; speedMb: number | null }>;
  vmkernelNics: Array<{ name: string; ip: string }>;
  virtualSwitches: Array<{ name: string; ports: number | null }>;
  portGroups: Array<{ name: string; vlanId: number | null; vSwitch: string }>;
  dns: { hostName: string; domainName: string; servers: string[] };
  time: { ntpServers: string[]; lastSyncTime: string | null; protocol: string };
  serviceSystemId: string | null;
  dateTimeSystemId: string | null;
  interfaceCounters?: Array<{ name: string; rxBytes: number | null; txBytes: number | null }>;
  coverage?: Array<{ key: string; status: "available" | "unavailable" }>;
  collectedAt: string;
};
const number = (value: unknown) => {
  const n = Number(value);
  return value !== "" && value !== null && Number.isFinite(n) && n >= 0 ? n : null;
};
const percent = (part: number | null, total: number | null) =>
  part !== null && total !== null && total > 0
    ? Math.max(0, Math.min(100, Math.round((part / total) * 1000) / 10))
    : null;
const prop = (map: Map<string, XmlNode> | undefined, name: string) => map?.get(name);
const nested = (node: XmlNode | undefined, ...path: string[]) =>
  path.reduce<XmlNode | undefined>((current, key) => child(current, key), node);
const str = (node: XmlNode | undefined, ...path: string[]) =>
  field(path.length > 1 ? nested(node, ...path.slice(0, -1)) : node, path[path.length - 1]);
const bool = (value: string): boolean | null =>
  value === "true" ? true : value === "false" ? false : null;

function sensorReading(sensor: XmlNode) {
  const raw = field(sensor, "currentReading");
  const modifier = field(sensor, "unitModifier");
  if (!raw) return null;
  const reading = Number(raw) * 10 ** (modifier ? Number(modifier) : 0);
  return Number.isFinite(reading) ? reading : null;
}

async function hostReference(client: EsxiSoapClient, service: XmlNode) {
  const root = field(service, "rootFolder");
  if (!root)
    throw new EsxiSoapError("ESXI_INVENTORY_MISSING", "ESXi did not provide an inventory root.");
  const rootFolder = (await client.properties("Folder", [root], ["childEntity"])).get(root);
  const datacenters = references(prop(rootFolder, "childEntity"), "Datacenter");
  for (const datacenter of datacenters.slice(0, 5)) {
    const dc = (await client.properties("Datacenter", [datacenter], ["hostFolder"])).get(
      datacenter,
    );
    const folders = references(prop(dc, "hostFolder"), "Folder");
    for (const folder of folders.slice(0, 5)) {
      const hostFolder = (await client.properties("Folder", [folder], ["childEntity"])).get(folder);
      const resources = references(prop(hostFolder, "childEntity"), "ComputeResource");
      for (const resource of resources.slice(0, 5)) {
        const compute = (await client.properties("ComputeResource", [resource], ["host"])).get(
          resource,
        );
        const host = references(prop(compute, "host"), "HostSystem")[0];
        if (host) return host;
      }
    }
  }
  throw new EsxiSoapError("ESXI_HOST_NOT_FOUND", "ESXi did not expose a host in its inventory.");
}

export async function readEsxiInventory(
  client: EsxiSoapClient,
  content: XmlNode,
  device: Device,
): Promise<EsxiDiscovery> {
  const hostId = await hostReference(client, content);
  const host = (
    await client.properties(
      "HostSystem",
      [hostId],
      [
        "summary",
        "runtime",
        "hardware",
        "vm",
        "datastore",
        "network",
        "configManager",
        "config.service",
        "config.network",
        "config.dateTimeInfo",
        "config.storageDevice",
        "config.firewall",
        "config.lockdownMode",
      ],
    )
  ).get(hostId);
  if (!host)
    throw new EsxiSoapError("ESXI_HOST_NOT_FOUND", "ESXi host properties are not accessible.");
  const summary = prop(host, "summary"),
    hardware = child(summary, "hardware"),
    quick = child(summary, "quickStats"),
    runtime = prop(host, "runtime") ?? child(summary, "runtime");
  const totalCpuMhz =
    number(field(hardware, "cpuMhz")) !== null && number(field(hardware, "numCpuCores")) !== null
      ? number(field(hardware, "cpuMhz"))! * number(field(hardware, "numCpuCores"))!
      : null;
  const cpuPercent = percent(number(field(quick, "overallCpuUsage")), totalCpuMhz);
  const memoryBytes = number(field(hardware, "memorySize"));
  const memoryPercent = percent(
    number(field(quick, "overallMemoryUsage")),
    memoryBytes === null ? null : memoryBytes / 1024 / 1024,
  );
  const vmIds = references(prop(host, "vm"), "VirtualMachine");
  const vmProperties = await client.properties("VirtualMachine", vmIds.slice(0, 100), ["summary"]);
  const vms: EsxiVm[] = vmIds.slice(0, 100).map((id) => {
    const data = prop(vmProperties.get(id), "summary");
    const config = child(data, "config"),
      state = child(data, "runtime");
    return {
      id,
      name: field(config, "name") || id,
      powerState: field(state, "powerState") || "unknown",
      guest: field(config, "guestFullName") || undefined,
      cpuCount: number(field(config, "numCpu")),
      memoryMb: number(field(config, "memorySizeMB")),
    };
  });
  const datastoreIds = references(prop(host, "datastore"), "Datastore");
  const datastoreProperties = await client.properties("Datastore", datastoreIds.slice(0, 50), [
    "summary",
  ]);
  const datastores: EsxiDatastore[] = datastoreIds.slice(0, 50).map((id) => {
    const data = prop(datastoreProperties.get(id), "summary");
    return {
      id,
      name: field(data, "name") || id,
      capacityBytes: number(field(data, "capacity")),
      freeBytes: number(field(data, "freeSpace")),
      accessible: bool(field(data, "accessible")),
    };
  });
  const networkIds = references(prop(host, "network"), "Network");
  const networkProperties = await client.properties("Network", networkIds.slice(0, 50), ["name"]);
  const networks = networkIds
    .slice(0, 50)
    .map(
      (id) =>
        field(prop(networkProperties.get(id), "name"), "name") ||
        networkProperties.get(id)?.get("name")?.text.trim() ||
        id,
    );
  const health = nested(runtime, "healthSystemRuntime", "systemHealthInfo");
  const sensors = children(health, "numericSensorInfo")
    .slice(0, 40)
    .map((item) => ({
      name: field(item, "name"),
      state: str(item, "healthState", "key") || "unknown",
      reading: sensorReading(item),
      unit: field(item, "baseUnits"),
    }));
  const serviceConfig = prop(host, "config.service");
  const services = children(serviceConfig, "service")
    .slice(0, 100)
    .map((item) => ({
      key: field(item, "key"),
      label: field(item, "label"),
      running: bool(field(item, "running")),
      policy: field(item, "policy"),
      required: bool(field(item, "required")),
    }))
    .filter((item) => item.key);
  const hostHardware = prop(host, "hardware");
  const storage = prop(host, "config.storageDevice");
  const storageAdapters = children(storage, "hostBusAdapter")
    .slice(0, 100)
    .map((item) => ({
      name: field(item, "device"),
      model: field(item, "model"),
      driver: field(item, "driver"),
      status: field(item, "status"),
    }))
    .filter((item) => item.name);
  const storageDevices = children(storage, "scsiLun")
    .slice(0, 100)
    .map((item) => ({
      name: field(item, "canonicalName"),
      displayName: field(item, "displayName"),
      deviceType: field(item, "deviceType"),
      operationalState: children(item, "operationalState")
        .map((value) => value.text.trim())
        .join(", "),
    }))
    .filter((item) => item.name);
  const firewallRulesets = children(prop(host, "config.firewall"), "ruleset")
    .slice(0, 100)
    .map((item) => ({
      key: field(item, "key"),
      label: field(item, "label"),
      enabled: bool(field(item, "enabled")),
      required: bool(field(item, "required")),
    }))
    .filter((item) => item.key);
  const networkConfig = prop(host, "config.network");
  const physicalNics = children(networkConfig, "pnic")
    .slice(0, 100)
    .map((item) => ({
      name: field(item, "device"),
      linkUp: bool(field(child(item, "linkSpeed"), "speedMb") ? "true" : "false"),
      speedMb: number(field(child(item, "linkSpeed"), "speedMb")),
    }))
    .filter((item) => item.name);
  const vmkernelNics = children(networkConfig, "vnic")
    .slice(0, 100)
    .map((item) => ({
      name: field(item, "device"),
      ip: field(child(item, "spec"), "ip") || field(child(child(item, "spec"), "ip"), "ipAddress"),
    }))
    .filter((item) => item.name);
  const virtualSwitches = children(networkConfig, "vswitch")
    .slice(0, 100)
    .map((item) => ({ name: field(item, "name"), ports: number(field(item, "numPorts")) }))
    .filter((item) => item.name);
  const portGroups = children(networkConfig, "portgroup")
    .slice(0, 100)
    .map((item) => ({
      name: field(child(item, "spec"), "name"),
      vlanId: number(field(child(item, "spec"), "vlanId")),
      vSwitch: field(child(item, "spec"), "vswitchName"),
    }))
    .filter((item) => item.name);
  const dnsConfig = child(networkConfig, "dnsConfig");
  const dns = {
    hostName: field(dnsConfig, "hostName"),
    domainName: field(dnsConfig, "domainName"),
    servers: children(dnsConfig, "address")
      .map((item) => item.text.trim())
      .filter(Boolean),
  };
  const dateTime = prop(host, "config.dateTimeInfo");
  const time = {
    ntpServers: children(child(dateTime, "ntpConfig"), "server")
      .map((item) => item.text.trim())
      .filter(Boolean),
    lastSyncTime: field(dateTime, "lastSyncTime") || null,
    protocol: field(dateTime, "systemClockProtocol"),
  };
  const manager = prop(host, "configManager");
  return {
    hostId,
    hostname: field(summary, "hostName") || field(child(summary, "config"), "name") || device.name,
    version: field(child(content, "about"), "version"),
    build: field(child(content, "about"), "build"),
    model: field(hardware, "model"),
    hardwareVendor: field(hardware, "vendor"),
    serialNumber: field(child(hostHardware, "systemInfo"), "serialNumber"),
    biosVersion: field(child(hostHardware, "biosInfo"), "biosVersion"),
    lockdownMode: value(prop(host, "config.lockdownMode")),
    connectionState: field(runtime, "connectionState") || "unknown",
    overallStatus: field(summary, "overallStatus") || "unknown",
    maintenanceMode: bool(field(runtime, "inMaintenanceMode")),
    bootTime: Number.isFinite(Date.parse(field(runtime, "bootTime")))
      ? field(runtime, "bootTime")
      : null,
    cpuPercent,
    memoryPercent,
    cpuCores: number(field(hardware, "numCpuCores")),
    memoryBytes,
    vmCount: prop(host, "vm") ? vmIds.length : null,
    vms,
    vmsTruncated: vmIds.length > 100,
    datastores,
    datastoreCount: prop(host, "datastore") ? datastoreIds.length : null,
    networks,
    sensors,
    services,
    storageAdapters,
    storageDevices,
    firewallRulesets,
    physicalNics,
    vmkernelNics,
    virtualSwitches,
    portGroups,
    dns,
    time,
    serviceSystemId: field(manager, "serviceSystem") || null,
    dateTimeSystemId: field(manager, "dateTimeSystem") || null,
    coverage: (
      [
        ["summary", quick],
        ["hardware", hardware],
        ["maintenance", runtime],
        ["datastores", prop(host, "datastore")],
        ["nics", networkConfig],
        ["vmkernel", networkConfig],
        ["portgroups", networkConfig],
        ["switches", networkConfig],
        ["dns", dnsConfig],
        ["ntp", dateTime],
        ["services", serviceConfig],
        ["adapters", prop(host, "config.storageDevice")],
        ["firewall", prop(host, "config.firewall")],
        ["sensors", nested(runtime, "healthSystemRuntime", "systemHealthInfo")],
      ] as Array<[string, XmlNode | undefined]>
    ).map(([key, node]) => ({ key, status: node ? "available" : "unavailable" })),
    collectedAt: new Date().toISOString(),
  };
}

export async function collectEsxiInventory(
  device: Device,
  secret: ApiSecret,
): Promise<EsxiDiscovery> {
  const { client, content } = await EsxiSoapClient.connect(device, secret);
  try {
    return await readEsxiInventory(client, content, device);
  } finally {
    await client.disconnect();
  }
}
