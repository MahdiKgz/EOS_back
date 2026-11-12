import { buildFortiDailyCheck } from "./fortigate-daily-check";
import { FORTIGATE_LOG_PREPARATION } from "./fortigate-logs";
import type { Device } from "./device.entity";
import type { SshCredentials } from "./linux-ssh";
import { runSshCommand } from "./ssh-transport";
import { redactFortiOutput, sanitizeFortiReport } from "./fortigate-output";
export { redactFortiOutput } from "./fortigate-output";
import {
  FORTIGATE_READ_COMMANDS,
  isFortiConfigComplete,
  buildFortiInventory,
  fortiIdentity,
  type FortiCommandId,
  type FortiEvidence,
} from "./fortigate-inventory";
function cleanTranscript(value: string, command: string) {
  const ansi = new RegExp(`${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`, "g"),
    lines = value
      .replace(ansi, "")
      .replace(/\r/g, "")
      .replace(/--More--|<--- More --->/g, "")
      .replaceAll(String.fromCharCode(8), "")
      .split("\n");
  const echo = lines.findIndex(
    (line) =>
      line.trim() === command ||
      line.trim().replace(/^[^\s]{1,120}(?: \([^)]+\))?\s*[#$>]\s*/, "") === command,
  );
  return (echo < 0 ? lines : lines.slice(echo + 1))
    .filter(
      (line) => !/^\s*[^\s]{1,120}(?: \([^)]+\))?\s*[#$>]\s*$/.test(line) && line.trim() !== "exit",
    )
    .join("\n");
}
export async function collectFortiInventory(device: Device, credentials: SshCredentials) {
  const outputs: Partial<Record<FortiCommandId, string>> = {},
    evidence: FortiEvidence[] = [],
    warnings: string[] = [],
    deadline = Date.now() + 60000;
  let bytes = 0;
  const read = async (id: FortiCommandId) => {
    const remaining = deadline - Date.now();
    if (remaining < 250 || bytes >= 2 * 1024 * 1024) {
      evidence.push({
        commandId: id,
        state: "not_collected",
        lineCount: 0,
        errorCode: remaining < 250 ? "FORTIGATE_DEADLINE" : "FORTIGATE_OUTPUT_LIMIT",
        evidence: [],
      });
      return;
    }
    try {
      const raw = await runSshCommand(device, credentials, FORTIGATE_READ_COMMANDS[id], {
        interactive: true,
        ...(id === "logs" ? { prepareCommands: FORTIGATE_LOG_PREPARATION } : {}),
        timeout: Math.min(8000, remaining),
        maxBuffer: 128 * 1024,
      });
      bytes += raw.length;
      const safe = redactFortiOutput(
        cleanTranscript(raw.toString("utf8"), FORTIGATE_READ_COMMANDS[id]),
      );
      const lines = safe.split("\n"),
        truncated =
          lines.length > (id === "logs" ? 510 : 512) || lines.some((line) => line.length > 1024);
      const bounded = lines
        .slice(0, id === "logs" ? 510 : 512)
        .map((line) =>
          Array.from(line)
            .filter((c) => c.charCodeAt(0) >= 32 || c === "\t")
            .join("")
            .slice(0, 1024),
        )
        .join("\n");
      outputs[id] = bounded;
      const parseIncomplete =
        FORTIGATE_READ_COMMANDS[id].startsWith("show ") &&
        !isFortiConfigComplete(bounded, FORTIGATE_READ_COMMANDS[id].replace(/^show /, "config "));
      evidence.push({
        commandId: id,
        state: truncated || parseIncomplete ? "partial" : "collected",
        lineCount: lines.length,
        ...(truncated
          ? { errorCode: "FORTIGATE_OUTPUT_TRUNCATED" }
          : parseIncomplete
            ? { errorCode: "FORTIGATE_PARSE_INCOMPLETE" }
            : {}),
        evidence: bounded.split("\n").filter(Boolean).slice(0, 4),
      });
    } catch (error) {
      const code = (error as { code?: unknown })?.code;
      evidence.push({
        commandId: id,
        state:
          code === "SSH_COMMAND_UNSUPPORTED"
            ? "not_supported"
            : code === "SSH_COMMAND_REQUIRES_PRIVILEGE"
              ? "requires_privilege"
              : "command_failed",
        lineCount: 0,
        errorCode:
          code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"
            ? "FORTIGATE_OUTPUT_LIMIT"
            : code === "SSH_COMMAND_REQUIRES_PRIVILEGE"
              ? "FORTIGATE_COMMAND_REQUIRES_PRIVILEGE"
              : code === "SSH_COMMAND_UNSUPPORTED"
                ? "FORTIGATE_COMMAND_NOT_SUPPORTED"
                : "FORTIGATE_COMMAND_FAILED",
        evidence: [],
      });
    }
  };
  await read("system");
  if (!outputs.system)
    throw Object.assign(new Error("FortiGate status unavailable"), {
      code: "FORTIGATE_CONNECTION_FAILED",
    });
  const detection = fortiIdentity(outputs.system);
  if (!detection.supported)
    return sanitizeFortiReport(
      {
        detection,
        collection: null,
        warnings: ["FORTIGATE_PLATFORM_UNSUPPORTED"],
        collectedAt: new Date().toISOString(),
      },
      credentials.password,
    );
  // Required metrics/interfaces run before optional discovery so a slow optional command cannot starve health.
  for (const id of Object.keys(FORTIGATE_READ_COMMANDS) as FortiCommandId[])
    if (id !== "system") await read(id);
  if (evidence.some((item) => item.state !== "collected"))
    warnings.push("FORTIGATE_PARTIAL_COLLECTION");
  if (evidence.some((item) => item.errorCode === "FORTIGATE_OUTPUT_TRUNCATED"))
    warnings.push("FORTIGATE_OUTPUT_TRUNCATED");
  const collection = buildFortiInventory(outputs, evidence, warnings);
  return sanitizeFortiReport(
    {
      detection,
      collection: { ...collection, dailyCheck: buildFortiDailyCheck(collection) },
      warnings,
      collectedAt: collection.collectedAt,
    },
    credentials.password,
  );
}
export type FortiInventory = Awaited<ReturnType<typeof collectFortiInventory>>;
