import type { Device } from "./device.entity";
import type { SshCredentials } from "./linux-ssh";
import { runSshCommand } from "./ssh-transport";
import { redactApiResult } from "./vendor-https";
import {
  ESXI_SSH_READ_COMMANDS,
  esxiNicStatsCommand,
  parseEsxiNicStats,
  parseEsxiSshInventory,
  type EsxiSshOutputs,
} from "./esxi-ssh-inventory";
export async function collectEsxiSshInventory(device: Device, credentials: SshCredentials) {
  const outputs: EsxiSshOutputs = {},
    deadline = Date.now() + 30000;
  const read = async (command: string) => {
    const remaining = deadline - Date.now();
    if (remaining < 250) throw new Error("ESXI_SSH_DEADLINE");
    const result = (
      await runSshCommand(device, credentials, command, {
        timeout: Math.min(5000, remaining),
        maxBuffer: 256 * 1024,
      })
    )
      .toString("utf8")
      .trim();
    if (!result || /^(?:Error:|Unknown command|Invalid command)/im.test(result))
      throw new Error("ESXI_SSH_COMMAND_UNAVAILABLE");
    return result;
  };
  // Identity is mandatory; collect health and traffic before optional host metadata.
  outputs.identity = await read(ESXI_SSH_READ_COMMANDS.identity);
  parseEsxiSshInventory(outputs, device);
  const priority = ["summary", "memory", "cpu", "datastores", "nics"] as const;
  for (const key of priority) {
    if (Date.now() >= deadline) break;
    try {
      outputs[key] = await read(ESXI_SSH_READ_COMMANDS[key]);
    } catch {
      /* Unknown metrics stay unavailable. */
    }
  }
  const base = parseEsxiSshInventory(outputs, device),
    counters: NonNullable<typeof base.interfaceCounters> = [];
  for (const nic of base.physicalNics.filter((n) => /^vmnic\d{1,4}$/.test(n.name)).slice(0, 16)) {
    if (Date.now() >= deadline) break;
    try {
      counters.push(parseEsxiNicStats(nic.name, await read(esxiNicStatsCommand(nic.name))));
    } catch {
      /* Per-interface failure does not fabricate a zero counter. */
    }
  }
  for (const key of Object.keys(ESXI_SSH_READ_COMMANDS) as (keyof EsxiSshOutputs)[]) {
    if (key === "identity" || priority.some((p) => p === key)) continue;
    if (Date.now() >= deadline) break;
    try {
      outputs[key] = await read(ESXI_SSH_READ_COMMANDS[key]);
    } catch {
      /* Optional read-only inventory may be incomplete. */
    }
  }
  const inventory = parseEsxiSshInventory(outputs, device);
  inventory.interfaceCounters = counters;
  inventory.coverage!.push({
    key: "traffic",
    status:
      inventory.physicalNics.length > 0 &&
      counters.length === inventory.physicalNics.length &&
      counters.every((n) => n.rxBytes !== null && n.txBytes !== null)
        ? "available"
        : "unavailable",
  });
  if (!credentials.password) return inventory;
  const sanitized = redactApiResult(inventory, {
    username: credentials.username,
    password: credentials.password,
  });
  // Controlled metadata is not a device-provided string and must retain its enum value.
  return { ...sanitized, transport: "ssh" as const, coverage: inventory.coverage };
}
