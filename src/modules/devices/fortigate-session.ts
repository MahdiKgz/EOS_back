import { Client } from "ssh2";
import { StringDecoder } from "node:string_decoder";
import type { Device } from "./device.entity";
import type { SshCredentials } from "./linux-ssh";
const ansi = new RegExp(`${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`, "g");
export async function runFortiSession(
  device: Device,
  credentials: SshCredentials,
  commands: readonly string[],
  options: { confirmVdomCreate?: { name: string } } = {},
) {
  if (
    device.type !== "fortigate" ||
    device.protocol !== "ssh" ||
    !commands.length ||
    commands.length > 80 ||
    commands.some((c) => !c || c.length > 8192 || /[\r\n\0]/.test(c))
  )
    throw new Error("FORTI_INVALID_PLAN");
  const createName = options.confirmVdomCreate?.name;
  const createCommand = createName ? `edit ${JSON.stringify(createName)}` : undefined;
  const createIndex = createCommand
    ? commands.findIndex(
        (command, index) =>
          command === createCommand &&
          commands[index - 1] === "config vdom" &&
          commands[index + 1] === "next" &&
          commands[index + 2] === "end",
      )
    : -1;
  if (
    options.confirmVdomCreate &&
    (!createName || !/^[A-Za-z0-9_.:-]{1,31}$/.test(createName) || createIndex < 0)
  )
    throw new Error("FORTI_INVALID_PLAN");
  return new Promise<string[]>((resolve, reject) => {
    const decoder = new StringDecoder("utf8");
    const client = new Client(),
      outputs: string[] = [];
    let stream: import("ssh2").ClientChannel | undefined,
      index = -1,
      pending = "",
      bytes = 0,
      settled = false,
      answeredVdomPrompt = false;
    const finish = (error?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stream?.close();
      client.end();
      if (error) reject(Object.assign(new Error(error), { code: error }));
      else resolve(outputs);
    };
    const timer = setTimeout(() => finish("FORTI_SESSION_TIMEOUT"), 25000);
    client
      .on("error", () => finish("FORTI_SSH_FAILED"))
      .on("close", () => {
        if (!settled) finish("FORTI_SESSION_CLOSED");
      });
    client.on("ready", () =>
      client.shell({ term: "vt100", cols: 200, rows: 1000 }, (error, shell) => {
        if (error) return finish("FORTI_SHELL_FAILED");
        stream = shell;
        shell.stderr.on("data", () => finish("FORTI_STDERR_RECEIVED"));
        shell.on("error", () => finish("FORTI_SHELL_FAILED"));
        shell.on("close", () => {
          if (!settled) finish("FORTI_SESSION_CLOSED");
        });
        shell.on("data", (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > 1024 * 1024) return finish("FORTI_OUTPUT_LIMIT");
          pending += decoder.write(chunk);
          if (pending.length > 256 * 1024) return finish("FORTI_OUTPUT_LIMIT");
          const text = pending.replace(ansi, "").replaceAll(String.fromCharCode(8), "");
          if (/--More--\s*$/.test(text)) {
            pending = pending.replace(/--More--/g, "").replaceAll(String.fromCharCode(8), "");
            shell.write(" ");
            return;
          }
          if (/(?:Do you want|Please press|Are you sure)[\s\S]{0,512}\(y\/n\)\s*$/i.test(text)) {
            const specific =
              /The input VDOM name doesn't exist\.\s*Do you want to create a new VDOM\?\s*Please press 'y' to continue, or press 'n' to cancel\.\s*\(y\/n\)\s*$/i.test(
                text,
              );
            if (!specific || !createCommand || index !== createIndex || answeredVdomPrompt)
              return finish("FORTI_CONFIRMATION_REQUIRED");
            answeredVdomPrompt = true;
            shell.write("y\n");
            return;
          }
          const prompt = text
            .trimEnd()
            .split(/[\r\n]/)
            .at(-1)
            ?.trim();
          if (!prompt || !/^\S{1,120}(?: \([^)]+\))?\s*[#$>]$/.test(prompt)) return;
          if (index >= 0) {
            const lines = text.replace(/\r/g, "").split("\n"),
              body = lines
                .slice(0, -1)
                .join("\n")
                .replace(/^\S{1,120}(?: \([^)]+\))?\s*[#$>]\s*/, "");
            const clean = body
              .split("\n")
              .filter((line) => line.trim() !== commands[index])
              .join("\n")
              .trim();
            if (
              /^(?:Command fail|command parse error|value parse error|Unknown action|Permission denied|You do not have permission|%\s*(?:Invalid|Authorization))/im.test(
                clean,
              )
            )
              return finish("FORTI_CLI_FAILED");
            outputs.push(clean);
          }
          pending = "";
          index++;
          if (index === commands.length) return finish();
          shell.write(commands[index] + "\n");
        });
      }),
    );
    const expected = Buffer.from(credentials.hostKey.split(" ")[1] ?? "", "base64");
    client.connect({
      host: device.host,
      port: device.managementPort,
      username: credentials.username,
      password: credentials.password,
      privateKey: credentials.privateKey,
      readyTimeout: 8000,
      hostVerifier: (raw: Buffer) => !!expected.length && raw.equals(expected),
    });
  });
}
