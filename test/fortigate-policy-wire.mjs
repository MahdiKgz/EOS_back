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
  } = require("../dist/modules/devices/fortigate-change.js"),
  { fortiPolicyTarget } = require("../dist/modules/devices/fortigate-policy.js"),
  { parseFortiBlocks } = require("../dist/modules/devices/fortigate-inventory.js");
const server = spawn(
  "python3",
  ["test/fixtures/terminal-server.py", "--fortigate", "--fortigate-split-utf8"],
  {
    stdio: ["ignore", "pipe", "pipe"],
  },
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
    const outputs = await runFortiSession(device, credentials, [
      ...compiled.commands,
      "show full-configuration firewall policy",
      "show full-configuration firewall address",
    ]);
    const rows = parseFortiBlocks(outputs.at(-2)),
      addresses = parseFortiBlocks(outputs.at(-1));
    assert.equal(
      fortiActionMatches(rows, input, compiled.assignments, { "firewall address": addresses }),
      true,
    );
    return {
      compiled,
      rows,
      addresses,
      target: fortiPolicyTarget(rows, input, compiled.assignments),
    };
  }
  const input = {
    action: "policy.egress",
    name: "outbound",
    srcInterface: "lan",
    dstInterface: "any",
    sourceCidr: "198.51.100.0/24",
    value: "شبکه",
    executionTag: "independent-invocation",
  };
  const created = await execute(input);
  assert.equal(created.target.name, "7000");
  assert.equal(created.target.settings.nat[0], "enable");
  assert.equal(created.target.settings.status[0], "disable");
  assert.equal(
    created.target.settings.comments[0],
    "firewall-log-analyzer شبکه invocation=independent-invocation",
  );
  assert.equal(created.addresses[0].settings.subnet.join(" "), "198.51.100.0 255.255.255.0");
  assert.equal(
    fortiActionMatches(
      created.rows,
      { ...input, executionTag: "other" },
      { ...created.compiled.assignments, comments: "other" },
      { "firewall address": created.addresses },
    ),
    false,
  );
  const singleIp = await execute({
    ...input,
    name: "one-host",
    sourceCidr: "198.51.100.9",
    executionTag: "single-ip-invocation",
  });
  assert.equal(
    singleIp.addresses
      .find((r) => r.name === singleIp.compiled.assignments.__sourceName)
      .settings.subnet.join(" "),
    "198.51.100.9 255.255.255.255",
  );
  await execute({
    action: "policy.update",
    name: "7000",
    value: "",
    nat: false,
    logTraffic: "utm",
    dstAddresses: "all",
  });
  await execute({ action: "policy.enable", name: "7000", value: "" });
  await execute({ action: "policy.disable", name: "7000", value: "" });
  await execute({ action: "policy.comment", name: "7000", value: "توضیح جدید" });
  const moved = await execute({
    action: "policy.move",
    name: "7000",
    value: "",
    relativeTo: "10",
    position: "before",
  });
  assert.deepEqual(
    moved.rows.map((r) => r.name),
    ["7000", "10", "7001"],
  );
  assert.equal(
    fortiActionMatches(moved.rows, { action: "policy.move", name: "7000" }, { __after: "10" }),
    false,
  );
  assert.deepEqual(
    (
      await execute({
        action: "policy.move",
        name: "7000",
        value: "",
        relativeTo: "10",
        position: "after",
      })
    ).rows.map((r) => r.name),
    ["10", "7000", "7001"],
  );
  assert.deepEqual(
    (await execute({ action: "policy.delete", name: "7000", value: "" })).rows.map((r) => r.name),
    ["10", "7001"],
  );
  console.log(
    "Forti policy wire: real SSH2 vs independent Paramiko, edit 0 assigned ID, invocation/source readback, split UTF-8 Unicode comments, partial updates, enable/disable, actual adjacent move order and delete passed.",
  );
} finally {
  lines.close();
  server.kill("SIGTERM");
  await once(server, "exit");
}
