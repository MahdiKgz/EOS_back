import { collectEsxiInventory, type EsxiDiscovery } from "./esxi-inventory";
import { collectMikroTikRest, type MikroTikInventory } from "./mikrotik-rest";
import { collectSophosXml, type SophosInventory } from "./sophos-xml";
import { vendorApiKind } from "./vendor-api-kind";
import { VendorApiError } from "./vendor-https";
import type { Device } from "./device.entity";
import type { ApiSecret } from "./ssh-credential-vault";
export type ApiInventory = (EsxiDiscovery & { kind: "esxi" }) | MikroTikInventory | SophosInventory;
export async function collectVendorApi(device: Device, secret: ApiSecret): Promise<ApiInventory> {
  const kind = vendorApiKind(device);
  if (kind === "mikrotik") return collectMikroTikRest(device, secret);
  if (kind === "sophos") return collectSophosXml(device, secret);
  if (kind !== "esxi") throw new VendorApiError("API_METHOD_UNSUPPORTED");
  if (secret.tlsFingerprint) throw new VendorApiError("API_TLS_PIN_NOT_SUPPORTED");
  return { ...(await collectEsxiInventory(device, secret)), kind: "esxi" };
}
