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
    fortiActionContexts,
  } = require("../dist/modules/devices/fortigate-change.js"),
  {
    parseFortiBlocks,
    isFortiConfigComplete,
  } = require("../dist/modules/devices/fortigate-inventory.js"),
  { parseFortiSystemConfig } = require("../dist/modules/devices/fortigate-network.js"),
  {
    parseFortiSdwan,
    fortiClusterReadCommands,
    fortiClusterReadMetadata,
  } = require("../dist/modules/devices/fortigate-cluster.js");
const server = spawn(
  "python3",
  ["test/fixtures/terminal-server.py", "--fortigate", "--fortigate-cluster"],
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
    credentials = { username: "fixture", password: "fixture-secret", hostKey: fixture.hostKey };
  async function execute(input) {
    input = { value: "", executionTag: "independent-cluster-wire", ...input };
    const p = compileFortiChange(input),
      contexts = fortiActionContexts(input.action),
      extra = fortiClusterReadCommands(input.action),
      output = await runFortiSession(device, credentials, [
        ...(p.global ? ["config global"] : ["config vdom", 'edit "root"']),
        ...p.commands,
        ...contexts.map((c) => "show full-configuration " + c),
        ...extra,
      ]),
      raw = output.slice(-(contexts.length + extra.length));
    contexts.forEach((c, i) => assert.equal(isFortiConfigComplete(raw[i], "config " + c), true));
    const tables = {
      ...Object.fromEntries(
        contexts.map((c, i) => [
          c,
          c === "system sdwan"
            ? parseFortiSdwan(raw[i])
            : (parseFortiSystemConfig(c, raw[i]) ?? parseFortiBlocks(raw[i])),
        ]),
      ),
      ...fortiClusterReadMetadata(input.action, raw.slice(contexts.length)),
    };
    assert.equal(
      fortiActionMatches(tables[p.context], input, p.assignments, tables),
      true,
      input.action,
    );
    return { tables, row: fortiActionTarget(tables[p.context], input, p.assignments), raw };
  }
  const ha = await execute({
    action: "ha.configure",
    name: "system",
    haMode: "a-p",
    haGroup: 'Persian گروه "A"',
  });
  assert.deepEqual(ha.row.settings.hbdev, ["ha1", "50", "ha2", "100"]);
  assert.equal(ha.tables.__haStatus[0].settings.mode[0], "a-p");
  await execute({ action: "ha.priority", name: "system", haPriority: "255" });
  await execute({ action: "sdwanZone.create", name: "branch" });
  const member = await execute({
    action: "sdwanMember.create",
    name: "auto-member",
    dstInterface: "lan",
    sdwanZone: "branch",
    gateway: "192.0.2.1",
  });
  assert.equal(member.row.name, "9500");
  assert.deepEqual(member.row.settings.interface, ["lan"]);
  for (const invalidId of ["0", "named-id", "-1", "4294967295"])
    assert.equal(
      fortiActionTarget(
        [{ ...member.row, name: invalidId }],
        { action: "sdwanMember.create", name: "auto-member" },
        { comment: member.row.settings.comment.join(" ") },
      ),
      undefined,
    );
  assert.equal(
    fortiActionTarget(
      [member.row, { ...member.row, name: "9502" }],
      { action: "sdwanMember.create", name: "auto-member" },
      { comment: member.row.settings.comment.join(" ") },
    ),
    undefined,
  );

  const health = await execute({
    action: "sdwanHealth.create",
    name: "Probe",
    probeServer: "probe.example.com",
    sdwanMembers: "1,9500",
  });
  assert.equal(health.row.name, "Probe");
  assert.equal(
    health.tables["system sdwan"].filter((r) => r.settings.__section?.[0] === "health-check")
      .length,
    1,
  );
  assert.ok(health.raw[0].includes("config sla"));
  const rule = await execute({
    action: "sdwanRule.create",
    name: "BranchTraffic",
    sdwanMembers: "9500,1",
  });
  assert.equal(rule.row.name, "9501");
  assert.deepEqual(rule.row.settings["priority-members"], ["9500", "1"]);
  assert.equal(rule.tables["system sdwan"][0].settings.status[0], "disable");
  assert.equal(
    isFortiConfigComplete(
      health.raw[0].replace(/set latency-threshold 50\nnext/, "set latency-threshold 50"),
      "config system sdwan",
    ),
    false,
  );
  await assert.rejects(
    runFortiSession(device, credentials, ["config global", "show full-configuration system sdwan"]),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  await assert.rejects(
    runFortiSession(device, credentials, [
      "config vdom",
      'edit "root"',
      "show full-configuration system ha",
    ]),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  await assert.rejects(
    runFortiSession(device, credentials, [
      "config vdom",
      'edit "root"',
      "config system sdwan",
      "config members",
      'edit "named-member"',
    ]),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  console.log(
    "Forti cluster independent wire: global HA vs VDOM SD-WAN scopes, mode/priority with preserved heartbeat, nested zone/member/health/SLA/manual-rule, real auto IDs, ordered priority-members, disabled SD-WAN retained, malformed nested block and named numeric-member rejection passed.",
  );
} finally {
  lines.close();
  server.kill("SIGTERM");
  await once(server, "exit");
}
