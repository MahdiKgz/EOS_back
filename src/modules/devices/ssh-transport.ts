import { ciscoAccessError, legacyCiscoOptions } from "./cisco-access-error";
import { receiveScpFile, sendScpFile } from "./ssh-scp";
import { sendSftpFile } from "./ssh-sftp";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Device } from "./device.entity";
import type { SshCredentials } from "./linux-ssh";
const execute = promisify(execFile);

// Commands are selected by server-side callers, never by request parameters.
export async function runSshCommand(
  device: Device,
  input: SshCredentials,
  command: string,
  {
    interactive = false,
    timeout = 12000,
    maxBuffer = 256 * 1024,
    strictStderr = false,
    scp = false,
    stdin,
    scpUpload,
    sftpUpload,
    allowPromptChange = false,
    prepareCommands = [],
  }: {
    interactive?: boolean;
    timeout?: number;
    maxBuffer?: number;
    strictStderr?: boolean;
    scp?: boolean;
    stdin?: Buffer;
    scpUpload?: { filename: string; content: Buffer };
    sftpUpload?: { filename: string; content: Buffer };
    allowPromptChange?: boolean;
    prepareCommands?: readonly string[];
  } = {},
): Promise<Buffer> {
  if (
    prepareCommands.length &&
    (!interactive ||
      device.type !== "fortigate" ||
      command !== "execute log display" ||
      JSON.stringify(prepareCommands) !==
        JSON.stringify(["execute log filter reset", "execute log filter view-lines 500"]))
  )
    throw new Error("Invalid FortiGate log preparation");
  if ([interactive, scp, !!stdin, !!scpUpload, !!sftpUpload].filter(Boolean).length > 1)
    throw new Error("Conflicting SSH input modes");
  if (sftpUpload && command !== "sftp") throw new Error("Invalid SFTP subsystem");
  if (
    scpUpload &&
    !/^(?:scp -t fgt-restore-config|scp -t flash:\/soar-[a-f0-9]{32}\.cfg)$/.test(command)
  )
    throw new Error("Invalid SCP restore destination");
  if (
    scpUpload &&
    (!/^soar-[a-f0-9]{32}\.(?:cfg|conf)$/.test(scpUpload.filename) ||
      !scpUpload.content.length ||
      scpUpload.content.length > 20 * 1024 * 1024)
  )
    throw new Error("Invalid SCP upload");
  if (
    sftpUpload &&
    (!/^soar-[a-f0-9]{32}\.rsc$/.test(sftpUpload.filename) ||
      !sftpUpload.content.length ||
      sftpUpload.content.length > 20 * 1024 * 1024)
  )
    throw new Error("Invalid SFTP upload");
  const directory = await mkdtemp(join(tmpdir(), "eos-ssh-"));
  const identity = join(directory, "identity");
  const knownHosts = join(directory, "known_hosts");
  try {
    const askpass = join(directory, "askpass");
    const passwordFile = join(directory, "password");
    if (input.password !== undefined) {
      await writeFile(passwordFile, input.password + "\n", { mode: 0o600 });
      await writeFile(askpass, '#!/bin/sh\nexec /bin/cat "$EOS_SSH_PASSWORD_FILE"\n', {
        mode: 0o700,
      });
    } else {
      await writeFile(identity, input.privateKey.trimEnd() + "\n", { mode: 0o600 });
    }
    await writeFile(knownHosts, `eos-device ${input.hostKey}\n`, { mode: 0o600 });
    const execution = execute(
      "ssh",
      [
        "-F",
        "/dev/null",
        "-o",
        input.password !== undefined ? "BatchMode=no" : "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        input.password !== undefined ? "PasswordAuthentication=yes" : "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        ...(input.password !== undefined
          ? ["-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1"]
          : ["-i", identity]),
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "HostKeyAlias=eos-device",
        "-o",
        `UserKnownHostsFile=${knownHosts}`,
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ClearAllForwardings=yes",
        ...(device.type === "cisco" && input.cisco?.profile === "legacy_cisco"
          ? legacyCiscoOptions
          : []),
        "-p",
        String(device.managementPort),
        "-l",
        input.username,
        ...(interactive ? ["-tt"] : []),
        ...(sftpUpload ? ["-s"] : []),
        "--",
        device.host,
        ...(interactive ? [] : [command]),
      ],
      {
        timeout,
        maxBuffer: maxBuffer + (scp ? 4096 : 0),
        encoding: "buffer" as const,
        killSignal: "SIGKILL",
        env:
          input.password !== undefined
            ? {
                ...process.env,
                SSH_ASKPASS: askpass,
                SSH_ASKPASS_REQUIRE: "force",
                EOS_SSH_PASSWORD_FILE: passwordFile,
              }
            : process.env,
      },
    );
    const scpResult = scp ? receiveScpFile(execution.child, maxBuffer) : undefined;
    const uploadResult = scpUpload
      ? sendScpFile(execution.child, scpUpload.content, scpUpload.filename)
      : sftpUpload
        ? sendSftpFile(execution.child, sftpUpload.content, sftpUpload.filename)
        : undefined;
    if (stdin) {
      execution.child.stdin?.on("error", () => {});
      execution.child.stdin?.end(stdin);
    }
    let completed = false;
    let accessFailure: string | undefined;
    let preparationFailed = false;
    if (interactive) {
      const ansi = new RegExp(`${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`, "g");
      let phase = "login";
      let pending = "";
      let prompt = "";
      let commandIndex = 0;
      let stageOutput = "";
      const commands = [...prepareCommands, command];
      execution.child.stdin?.on("error", () => {});
      execution.child.stdout?.on("data", (chunk: Buffer) => {
        if (phase === "command") stageOutput += chunk.toString();
        pending = (pending + chunk.toString()).slice(-4096);
        const visible = pending.replace(ansi, "").replaceAll(String.fromCharCode(8), "");
        if (phase === "command" && /(?:--More--|<--- More --->)\s*$/.test(visible)) {
          pending = "";
          execution.child.stdin?.write(" ");
        } else {
          const line = visible
            .trimEnd()
            .split(/[\r\n]/)
            .at(-1)
            ?.trim();
          const isPrompt = line && /^[^\s]{1,120}(?: \([^)]+\))?\s*[#$>]$/.test(line);
          const fail = (code: string) => {
            accessFailure = code;
            phase = "exit";
            execution.child.stdin?.end("exit\n");
          };
          const sendCommand = () => {
            prompt = line!;
            phase = "command";
            pending = "";
            stageOutput = "";
            execution.child.stdin?.write(commands[commandIndex] + "\n");
          };
          if (phase === "login" && isPrompt) {
            if (device.type === "cisco" && line!.endsWith(">")) {
              if (!input.cisco?.enableSecret) fail("CISCO_ENABLE_REQUIRED");
              else {
                phase = "enable_password";
                pending = "";
                execution.child.stdin?.write("enable\n");
              }
            } else sendCommand();
          } else if (phase === "enable_password" && /password:\s*$/i.test(visible)) {
            phase = "enable_result";
            pending = "";
            execution.child.stdin?.write(input.cisco!.enableSecret! + "\n");
          } else if (phase === "enable_password" && isPrompt) {
            if (line!.endsWith("#")) sendCommand();
            else fail("CISCO_ENABLE_FAILED");
          } else if (phase === "enable_result") {
            if (isPrompt && line!.endsWith("#")) sendCommand();
            else if (
              isPrompt ||
              /password:\s*$|access denied|bad secrets|authentication failed/i.test(visible)
            )
              fail("CISCO_ENABLE_FAILED");
          } else if (
            phase === "command" &&
            (line === prompt ||
              (allowPromptChange && line && /^[^\s]{1,120}(?: \([^)]+\))?\s*[#$>]$/.test(line)))
          ) {
            if (commandIndex < commands.length - 1) {
              if (
                /^(?:% (?:Invalid|Incomplete|Ambiguous|Authorization)|Command fail|command parse error|Unknown action|Permission denied|You do not have permission)/im.test(
                  stageOutput.replace(ansi, ""),
                )
              ) {
                preparationFailed = true;
                phase = "exit";
                execution.child.stdin?.end("exit\n");
              } else {
                commandIndex++;
                sendCommand();
              }
            } else {
              completed = true;
              phase = "exit";
              execution.child.stdin?.end("exit\n");
            }
          }
        }
      });
    }
    const { stdout, stderr } = await execution.catch((error: unknown) => {
      if (device.type !== "cisco") throw error;
      const detail = (error as { stderr?: Buffer })?.stderr?.toString() ?? "";
      const code =
        accessFailure ??
        ((error as { code?: unknown })?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"
          ? "CISCO_OUTPUT_LIMIT"
          : undefined) ??
        (/REMOTE HOST IDENTIFICATION|Host key verification failed/i.test(detail)
          ? "CISCO_HOST_KEY_MISMATCH"
          : /Permission denied/i.test(detail)
            ? "CISCO_AUTH_FAILED"
            : /no matching|Unable to negotiate/i.test(detail)
              ? "CISCO_NEGOTIATION_FAILED"
              : "CISCO_CONNECTION_FAILED");
      throw ciscoAccessError(code);
    });
    if (accessFailure) throw ciscoAccessError(accessFailure);
    if (strictStderr && stderr.length && !interactive) throw new Error("SSH stderr is not empty");
    if (
      interactive &&
      (!completed ||
        preparationFailed ||
        /^(?:% (?:Invalid|Incomplete|Ambiguous|Authorization)|Command fail|command parse error|Unknown action|Permission denied|You do not have permission)/im.test(
          stdout.toString("utf8"),
        ))
    )
      throw Object.assign(new Error("SSH CLI rejected command"), {
        code: /%\s*Authorization|permission denied|not authorized|do not have permission/i.test(
          stdout.toString("utf8"),
        )
          ? "SSH_COMMAND_REQUIRES_PRIVILEGE"
          : /%\s*(?:Invalid|Incomplete|Ambiguous)|command parse error|Unknown action|Command fail.*(?:-61|-160)/i.test(
                stdout.toString("utf8"),
              )
            ? "SSH_COMMAND_UNSUPPORTED"
            : "SSH_CLI_FAILED",
      });
    uploadResult?.();
    return scpResult ? scpResult() : stdout;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
