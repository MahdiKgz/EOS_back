import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url),
  { runFortiSession } = require("../dist/modules/devices/fortigate-session.js"),
  {
    compileFortiChange,
    fortiActionMatches,
    fortiActionContexts,
  } = require("../dist/modules/devices/fortigate-change.js"),
  { parseFortiBlocks } = require("../dist/modules/devices/fortigate-inventory.js"),
  { parseFortiSystemConfig } = require("../dist/modules/devices/fortigate-network.js"),
  {
    fortiAdminPasswordLine,
    fortiAdminPasswordPlaceholder,
  } = require("../dist/modules/devices/fortigate-admin.js");
const server = spawn(
  "python3",
  ["test/fixtures/terminal-server.py", "--fortigate", "--fortigate-admin"],
  { stdio: ["ignore", "pipe", "pipe"] },
);
server.stderr.on("data", () => {});
const lines = createInterface({ input: server.stdout });
try {
  const [line] = await once(lines, "line", { signal: AbortSignal.timeout(10000) }),
    fixture = JSON.parse(line),
    device = {
      type: "fortigate",
      protocol: "ssh",
      host: "127.0.0.1",
      managementPort: fixture.port,
    },
    credentials = { username: "fixture", password: "fixture-secret", hostKey: fixture.hostKey },
    password = 'Private "quoted" \\ test گذرواژه!';
  async function execute(input) {
    const p = compileFortiChange({ value: "", ...input }),
      contexts = fortiActionContexts(input.action),
      result = await runFortiSession(device, credentials, [
        "config global",
        ...p.commands.map((c) =>
          c === fortiAdminPasswordPlaceholder ? fortiAdminPasswordLine(password) : c,
        ),
        ...contexts.map((c) => "show full-configuration " + c),
      ]),
      tables = Object.fromEntries(
        contexts.map((c, i) => [
          c,
          parseFortiSystemConfig(c, result.at(-contexts.length + i)) ??
            parseFortiBlocks(result.at(-contexts.length + i)),
        ]),
      );
    assert.equal(
      fortiActionMatches(tables[p.context], input, p.assignments, tables),
      true,
      input.action,
    );
    return tables[p.context];
  }
  const created = await execute({
    action: "admin.create",
    name: "wire-admin",
    adminProfile: "limited",
    accountVdoms: "root,tenant",
    adminSecretId: "fixture",
  });
  assert.equal(
    created.find((r) => r.name === "wire-admin").settings.password.join(" "),
    "ENC " + createHash("sha256").update(password).digest("hex"),
  );
  await execute({ action: "admin.trusthost", name: "wire-admin", value: "198.51.100.0/24" });
  await execute({
    action: "apiUser.create",
    name: "wire-api",
    adminProfile: "limited",
    accountVdoms: "root",
  });
  await execute({ action: "management.httpsPort", name: "system", value: "8443" });
  for (const value of ["telnet", "ssh-v1", "ssh-password", "scp"])
    await execute({ action: "management.disableService", name: "system", value });
  await execute({ action: "admin.disable", name: "wire-admin" });
  await execute({ action: "admin.delete", name: "wire-admin" });
  for (const command of ["set admin-http disable", "set admin-ssh disable"])
    await assert.rejects(
      runFortiSession(device, credentials, [
        "config global",
        "config system global",
        command,
        "end",
      ]),
      (e) => e.code === "FORTI_CLI_FAILED",
    );
  await assert.rejects(
    runFortiSession(device, credentials, [
      "config vdom",
      'edit "root"',
      "show full-configuration system admin",
    ]),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  await assert.rejects(
    runFortiSession(device, credentials, [
      "config global",
      "config system admin",
      'edit "operator"',
      "set status disable",
      "next",
      "end",
    ]),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  console.log(
    "Forti admin independent wire: global scope, quoted Unicode password encoded at readback (no placeholder execution), profiles/VDOMs, trusthost, native service flags/HTTPS, API config, disable/delete; invalid generic service/status CLI and VDOM-scoped admin reads rejected.",
  );
} finally {
  lines.close();
  server.kill("SIGTERM");
  await once(server, "exit");
}
