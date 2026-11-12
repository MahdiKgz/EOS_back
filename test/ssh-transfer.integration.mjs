import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { mkdtemp, readFile, stat, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { runSshCommand } = require("../dist/modules/devices/ssh-transport.js");
const { sendScpFile } = require("../dist/modules/devices/ssh-scp.js");
// Host test dependencies: OpenSSH client and Python 3 with Paramiko. No dependency is added to the API runtime.
try {
  execFileSync("python3", ["-c", "import paramiko"], { stdio: "ignore" });
} catch {
  throw new Error("This loopback integration test requires Python 3 and Paramiko.");
}
const directory = await mkdtemp(join(tmpdir(), "eos-transfer-wire-"));
const server = spawn("python3", ["test/fixtures/sftp-server.py", directory], {
  stdio: ["ignore", "pipe", "pipe"],
});
server.stderr.on("data", () => {});
const lines = createInterface({ input: server.stdout });
try {
  const [line] = await once(lines, "line", { signal: AbortSignal.timeout(10000) });
  const fixture = JSON.parse(line);
  const device = { host: "127.0.0.1", managementPort: fixture.port };
  const credentials = { username: "fixture", password: "fixture-secret", hostKey: fixture.hostKey };
  const filename = "soar-" + randomBytes(16).toString("hex");
  const content = randomBytes(131099);
  await runSshCommand(device, credentials, "sftp", {
    sftpUpload: { filename: filename + ".rsc", content },
    timeout: 15000,
    strictStderr: true,
  });
  assert.deepEqual(await readFile(join(directory, filename + ".rsc")), content);
  assert.equal((await stat(join(directory, filename + ".rsc"))).mode & 0o777, 0o600);
  const replaced = await runSshCommand(
    device,
    credentials,
    `configure replace flash:/${filename}.cfg force time 3`,
    { interactive: true, allowPromptChange: true, timeout: 10000 },
  );
  assert.match(replaced.toString(), /Replacement complete/);
  await assert.rejects(
    runSshCommand(device, credentials, "fixture-denied", { interactive: true, timeout: 10000 }),
  );
  await assert.rejects(
    runSshCommand(device, credentials, "sftp", {
      sftpUpload: { filename: filename + ".rsc", content: Buffer.from("must not replace") },
      timeout: 10000,
    }),
  );
  assert.deepEqual(await readFile(join(directory, filename + ".rsc")), content);
  const deniedName = "soar-" + randomBytes(16).toString("hex") + ".rsc";
  await assert.rejects(
    runSshCommand(device, { ...credentials, password: "wrong-fixture-password" }, "sftp", {
      sftpUpload: { filename: deniedName, content },
      timeout: 10000,
    }),
  );
  await assert.rejects(
    runSshCommand(device, { ...credentials, hostKey: fixture.wrongHostKey }, "sftp", {
      sftpUpload: { filename: deniedName, content },
      timeout: 10000,
    }),
  );
  await assert.rejects(readFile(join(directory, deniedName)), { code: "ENOENT" });
  const scp = spawn("scp", ["-t", directory], { stdio: ["pipe", "pipe", "pipe"] });
  scp.stderr.on("data", () => {});
  const closed = once(scp, "close", { signal: AbortSignal.timeout(10000) });
  const received = sendScpFile(scp, content, filename + ".cfg");
  const [code] = await closed;
  assert.equal(code, 0);
  received();
  assert.deepEqual(await readFile(join(directory, filename + ".cfg")), content);
  console.log(
    "PASS: real OpenSSH client + independent Paramiko SFTP server, exclusive creation, binary integrity, host-key/password rejection and system SCP sink",
  );
} finally {
  lines.close();
  if (server.exitCode === null && server.signalCode === null) {
    const closed = once(server, "close");
    server.kill("SIGTERM");
    const timeout = setTimeout(() => server.kill("SIGKILL"), 5000);
    await closed;
    clearTimeout(timeout);
  }
  await rm(directory, { recursive: true, force: true });
}
