import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url),
  { runFortiSession } = require("../dist/modules/devices/fortigate-session.js"),
  {
    compileFortiChange,
    fortiActionMatches,
    fortiActionTarget,
  } = require("../dist/modules/devices/fortigate-change.js"),
  { parseFortiBlocks } = require("../dist/modules/devices/fortigate-inventory.js"),
  { parseFortiSystemConfig } = require("../dist/modules/devices/fortigate-network.js");
const server = spawn(
  "python3",
  ["test/fixtures/terminal-server.py", "--fortigate", "--fortigate-network"],
  { stdio: ["ignore", "pipe", "pipe"] },
);
server.stderr.on("data", () => {});
const lines = createInterface({ input: server.stdout });
try {
  const [line] = await once(lines, "line", { signal: AbortSignal.timeout(10000) }),
    fixture = JSON.parse(line);
  const device = {
      type: "fortigate",
      protocol: "ssh",
      host: "127.0.0.1",
      managementPort: fixture.port,
    },
    credentials = { username: "fixture", password: "fixture-secret", hostKey: fixture.hostKey };
  async function execute(input) {
    const compiled = compileFortiChange(input);
    const contexts = [compiled.context, ...(compiled.dependencies ?? [])];
    const outputs = await runFortiSession(device, credentials, [
      ...(compiled.global ? ["config global"] : ["config vdom", 'edit "root"']),
      ...compiled.commands,
      ...contexts.map((context) => "show full-configuration " + context),
    ]);
    const views = Object.fromEntries(
      contexts.map((context, index) => [
        context,
        parseFortiSystemConfig(context, outputs.at(-contexts.length + index)) ??
          parseFortiBlocks(outputs.at(-contexts.length + index)),
      ]),
    );
    assert.equal(
      fortiActionMatches(views[compiled.context], input, compiled.assignments, views),
      true,
      JSON.stringify({
        action: input.action,
        expected: compiled.assignments,
        actual: views[compiled.context],
      }),
    );
    return {
      compiled,
      views,
      row: fortiActionTarget(views[compiled.context], input, compiled.assignments),
    };
  }
  const route = await execute({
    action: "route.create",
    name: "auto-route",
    value: "",
    destinationCidr: "198.51.100.0/24",
    gateway: "192.0.2.254",
    dstInterface: "lan",
    executionTag: "route-wire",
  });
  assert.equal(route.row.name, "9000");
  assert.deepEqual(route.row.settings.dst, ["198.51.100.0", "255.255.255.0"]);
  const updated = await execute({
    action: "route.update",
    name: "9000",
    value: "",
    gateway: "192.0.2.253",
  });
  assert.deepEqual(updated.row.settings.device, ["lan"]);
  assert.deepEqual(updated.row.settings.dst, ["198.51.100.0", "255.255.255.0"]);
  const snat = await execute({
    action: "snat.create",
    name: "auto-snat",
    value: "",
    srcInterface: "lan",
    dstInterface: "any",
    sourceCidr: "192.0.2.0/24",
    executionTag: "snat-wire",
  });
  assert.equal(snat.row.name, "9001");
  assert.deepEqual(snat.row.settings["orig-addr"], [snat.compiled.assignments.__sourceName]);
  assert.equal(snat.views["system settings"][0].settings["central-nat"][0], "disable");
  await assert.rejects(
    runFortiSession(device, credentials, [
      "config vdom",
      'edit "root"',
      "config firewall central-snat-map",
      "edit 9999",
      'set orig-addr "192.0.2.0/24"',
      "next",
      "end",
    ]),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  const dns = await execute({
    action: "dns.update",
    name: "system",
    value: "",
    primaryDns: "198.51.100.53",
    secondaryDns: "198.51.100.54",
  });
  assert.equal(dns.row.settings.protocol[0], "dot");
  const ntp = await execute({
    action: "ntp.update",
    name: "system",
    value: "",
    ntpServer: "time.example.com",
  });
  assert.equal(ntp.row.settings.type[0], "custom");
  assert.equal(ntp.row.settings.ntpsync[0], "enable");
  assert.equal(ntp.row.settings.server[0], "time.example.com");
  assert.equal(ntp.row.settings.syncinterval[0], "60");
  const ntpRaw = (
    await runFortiSession(device, credentials, [
      "config global",
      "show full-configuration system ntp",
    ])
  )[1];
  assert.ok(ntpRaw.includes("keep.ntp.local"));
  await assert.rejects(
    runFortiSession(device, credentials, [
      "config vdom",
      'edit "root"',
      "show full-configuration system dns",
    ]),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  assert.equal((await execute({ action: "route.delete", name: "9000", value: "" })).row, undefined);
  console.log(
    "Forti network wire: real SSH2 vs independent Paramiko; VDOM/global scope enforcement, auto route/SNAT IDs, subnet mask vs CIDR, real address reference, source readback, preserved route/DNS fields, NTP custom/server1 with server2 retained and explicit route deletion passed.",
  );
} finally {
  lines.close();
  server.kill("SIGTERM");
  await once(server, "exit");
}
