import type { Device } from "./device.entity";
export type VendorApiKind = "esxi" | "mikrotik" | "sophos";
export function vendorApiKind(
  device: Pick<Device, "type" | "vendor" | "protocol">,
): VendorApiKind | null {
  if (device.protocol !== "api") return null;
  if (device.type === "esxi") return "esxi";
  if (device.type === "mikrotik") return "mikrotik";
  if (device.type === "generic_firewall" && /^sophos(?:[ _-]firewall)?$/i.test(device.vendor))
    return "sophos";
  return null;
}
