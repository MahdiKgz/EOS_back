import type { Device } from "./device.entity";
import type { ApiSecret } from "./ssh-credential-vault";
import { VendorApiError, VendorHttpsClient, redactApiResult } from "./vendor-https";
export type InventoryRow = Record<string, string | number | boolean | null>;
export type MikroTikInventory = {
  kind: "mikrotik";
  identity: string;
  routerosVersion: string;
  architecture: string;
  uptime: string;
  cpuLoad: number | null;
  cpuCount: number | null;
  memoryFree: number | null;
  memoryTotal: number | null;
  storageFree: number | null;
  storageTotal: number | null;
  sections: Record<string, InventoryRow[]>;
  interfaceCounters: { name: string; rxBytes: number; txBytes: number }[];
  warnings: { section: string; code: string }[];
  collectedAt: string;
};
const sections = [
  ["packages", "/rest/system/package", ["name", "version", "build-time", "disabled"]],
  [
    "interfaces",
    "/rest/interface",
    ["name", "type", "mac-address", "actual-mtu", "mtu", "running", "disabled", "comment"],
  ],
  [
    "addresses",
    "/rest/ip/address",
    ["address", "network", "interface", "actual-interface", "disabled", "dynamic"],
  ],
  [
    "routes",
    "/rest/ip/route",
    [
      "dst-address",
      "gateway",
      "routing-table",
      "distance",
      "active",
      "disabled",
      "dynamic",
      "comment",
    ],
  ],
  [
    "filterRules",
    "/rest/ip/firewall/filter",
    [
      "chain",
      "action",
      "protocol",
      "src-address",
      "dst-address",
      "src-port",
      "dst-port",
      "disabled",
      "comment",
    ],
  ],
  [
    "natRules",
    "/rest/ip/firewall/nat",
    [
      "chain",
      "action",
      "protocol",
      "src-address",
      "dst-address",
      "dst-port",
      "to-addresses",
      "to-ports",
      "disabled",
      "comment",
    ],
  ],
  [
    "mangleRules",
    "/rest/ip/firewall/mangle",
    ["chain", "action", "protocol", "src-address", "dst-address", "disabled", "comment"],
  ],
  [
    "addressLists",
    "/rest/ip/firewall/address-list",
    ["list", "address", "timeout", "disabled", "dynamic", "comment"],
  ],
  ["services", "/rest/ip/service", ["name", "port", "address", "disabled", "certificate", "vrf"]],
  ["logs", "/rest/log", ["time", "topics", "message"]],
  ["counters", "/rest/interface?.proplist=name,rx-byte,tx-byte", ["name", "rx-byte", "tx-byte"]],
  [
    "arp",
    "/rest/ip/arp",
    ["address", "mac-address", "interface", "status", "dynamic", "complete", "disabled"],
  ],
  [
    "dhcpLeases",
    "/rest/ip/dhcp-server/lease",
    [
      "address",
      "mac-address",
      "host-name",
      "status",
      "server",
      "expires-after",
      "dynamic",
      "disabled",
    ],
  ],
  [
    "bridgeHosts",
    "/rest/interface/bridge/host",
    ["mac-address", "on-interface", "bridge", "vid", "local", "dynamic"],
  ],
  ["dnsCache", "/rest/ip/dns/cache", ["name", "address", "type", "ttl", "data"]],
] as const;
function numeric(value: unknown) {
  if (typeof value === "number") return value;
  if (typeof value === "string" && value.trim()) return Number(value);
  return NaN;
}
function nonnegative(value: unknown) {
  const number = numeric(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}
function records(value: unknown): Record<string, unknown>[] {
  const rows = Array.isArray(value) ? value : [value];
  return rows.filter(
    (row): row is Record<string, unknown> =>
      !!row && typeof row === "object" && !Array.isArray(row),
  );
}
function text(value: unknown) {
  return typeof value === "string" ? value.slice(0, 2000) : "";
}
export async function collectMikroTikRest(
  device: Device,
  secret: ApiSecret,
): Promise<MikroTikInventory> {
  if (secret.username.includes(":")) throw new VendorApiError("MIKROTIK_USERNAME_INVALID");
  const client = await VendorHttpsClient.connect(device, secret, false);
  const warnings: MikroTikInventory["warnings"] = [];
  const authorization =
    "Basic " + Buffer.from(secret.username + ":" + secret.password).toString("base64");
  async function read(path: string) {
    const body = await client.request(path, {
      method: "GET",
      headers: { Accept: "application/json", Authorization: authorization },
    });
    let value: unknown;
    try {
      value = JSON.parse(body);
    } catch {
      throw new VendorApiError("MIKROTIK_INVALID_JSON");
    }
    const rows = Array.isArray(value) ? value : [value];
    if (!rows.every((row) => !!row && typeof row === "object" && !Array.isArray(row)))
      throw new VendorApiError("MIKROTIK_INVALID_RESPONSE");
    return value;
  }
  try {
    const [identityValue, resourceValue] = await Promise.all([
      read("/rest/system/identity"),
      read("/rest/system/resource"),
    ]);
    const identity = records(identityValue)[0] ?? {},
      resource = records(resourceValue)[0] ?? {};
    const name = text(identity.name),
      version = text(resource.version);
    if (!name || !/^(?:[7-9]|[1-9][0-9]+)\./.test(version))
      throw new VendorApiError("MIKROTIK_IDENTITY_UNCONFIRMED");
    const result: Record<string, InventoryRow[]> = {};
    for (let offset = 0; offset < sections.length; offset += 3) {
      await Promise.all(
        sections.slice(offset, offset + 3).map(async ([section, path, fields]) => {
          try {
            const value = await read(path);
            const source = records(value);
            result[section] = source
              .slice(0, section === "logs" ? 200 : 1000)
              .map((row) =>
                Object.fromEntries(
                  (fields as readonly string[]).flatMap<[string, string | number | boolean | null]>(
                    (field) => {
                      const item = row[field];
                      if (typeof item === "string") return [[field, text(item)]];
                      if (
                        typeof item === "boolean" ||
                        (typeof item === "number" && Number.isFinite(item)) ||
                        item === null
                      )
                        return [[field, item]];
                      return [];
                    },
                  ),
                ),
              )
              .filter((row) => Object.keys(row).length > 0);
            if (source.length && !result[section].length)
              throw new VendorApiError("MIKROTIK_INVALID_RESPONSE");
          } catch (error) {
            if (
              error instanceof VendorApiError &&
              ["API_AUTH_FAILED", "API_TLS_OR_NETWORK", "API_TIMEOUT"].includes(error.code)
            )
              throw error;
            result[section] = [];
            warnings.push({
              section,
              code: error instanceof VendorApiError ? error.code : "API_READ_FAILED",
            });
          }
        }),
      );
    }
    return redactApiResult(
      {
        kind: "mikrotik",
        identity: name,
        routerosVersion: version,
        architecture: text(resource["architecture-name"]),
        uptime: text(resource.uptime),
        cpuLoad: nonnegative(resource["cpu-load"]),
        cpuCount: nonnegative(resource["cpu-count"]),
        memoryFree: nonnegative(resource["free-memory"]),
        memoryTotal: nonnegative(resource["total-memory"]),
        storageFree: nonnegative(resource["free-hdd-space"]),
        storageTotal: nonnegative(resource["total-hdd-space"]),
        sections: result,
        interfaceCounters: (result.counters ?? []).flatMap((row) => {
          const rxBytes = nonnegative(row["rx-byte"]),
            txBytes = nonnegative(row["tx-byte"]);
          return typeof row.name === "string" &&
            rxBytes !== null &&
            txBytes !== null &&
            Number.isSafeInteger(rxBytes) &&
            Number.isSafeInteger(txBytes)
            ? [{ name: row.name, rxBytes, txBytes }]
            : [];
        }),
        warnings,
        collectedAt: new Date().toISOString(),
      },
      secret,
    );
  } finally {
    client.close();
  }
}
