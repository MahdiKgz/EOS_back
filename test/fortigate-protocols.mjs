import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fortigateSshFixture } from "./fixtures/fortigate-ssh-server.mjs";
const require = createRequire(import.meta.url),
  {
    collectFortiInventory,
    redactFortiOutput,
  } = require("../dist/modules/devices/fortigate-collector.js"),
  { fortiHealth, parseFortiBlocks } = require("../dist/modules/devices/fortigate-inventory.js"),
  { runLinuxSsh } = require("../dist/modules/devices/linux-ssh.js"),
  { collectSshMonitoring } = require("../dist/modules/devices/monitoring-ssh.js");
const fixture = await fortigateSshFixture();
try {
  const target = {
      id: "fixture",
      host: fixture.host,
      managementPort: fixture.port,
      type: "fortigate",
      protocol: "ssh",
    },
    credentials = {
      username: fixture.username,
      password: fixture.password,
      hostKey: fixture.hostKey,
    };
  let report = await collectFortiInventory(target, credentials);
  assert.equal(report.detection.supported, true);
  assert.equal(report.collection.system.model, "FortiGate-101F");
  assert.equal(report.collection.health.cpuUsagePercent, 8);
  assert.equal(report.collection.health.memoryUsagePercent, 40);
  assert.equal(report.collection.health.memoryTotalBytes, 1024000000);
  assert.equal(report.collection.health.sessionCount, 42);
  assert.equal(report.collection.health.uptimeSeconds, 183840);
  assert.equal(report.collection.interfaceCounters.length, 2);
  const table = (key) => report.collection.tables.find((table) => table.key === key);
  assert.equal(table("interfaces").rows.length, 2);
  assert.equal(table("admins").rows.length, 1);
  assert.equal(table("admins").rows[0].name, "operator");
  assert.equal(table("vpn").rows[0].status, "up");
  assert.equal(table("vpn").rows[0].phase2, "office-remote");
  assert.equal(table("staticRoutes").rows[0].name, "7");
  assert.equal(table("centralSnat").rows[0].name, "8");
  assert.equal(table("centralSnat").rows[0].nat, "enable");
  assert.equal(table("vipGroups").rows[0].name, "public-services");
  assert.equal(table("vipGroups").rows[0].member, "web-vip");
  assert.equal(table("policies").rows[0].id, "1");
  assert.equal(table("policies").rows[0].name, "office internet");
  assert.ok(!JSON.stringify(report).includes("NEVER_FORTI_SECRET"));
  assert.ok(!JSON.stringify(report).includes(fixture.password));
  assert.equal(table("physical").rows[0].status, "up");
  assert.ok(
    fixture.calls.every(
      (command) =>
        /^(?:get|show|diagnose) /.test(command) ||
        /^execute log (?:filter reset|filter view-lines 500|display)$/.test(command),
    ),
  );
  assert.ok(!fixture.calls.some((command) => /^(?:config|set|delete)/.test(command)));
  const keyVerified = await runLinuxSsh(target, {
    username: fixture.username,
    privateKey: fixture.privateKey,
    hostKey: fixture.hostKey,
    operation: "verify",
  });
  assert.equal(keyVerified.identity.Manufacturer, "Fortinet");
  fixture.mode("partial");
  report = await collectFortiInventory(target, credentials);
  assert.equal(
    report.collection.tables.find((t) => t.key === "admins").state,
    "requires_privilege",
  );
  assert.equal(
    report.collection.commandEvidence.find((c) => c.commandId === "processes").state,
    "not_supported",
  );
  assert.ok(report.warnings.includes("FORTIGATE_PARTIAL_COLLECTION"));
  fixture.mode("unsupported");
  const before = fixture.calls.length;
  report = await collectFortiInventory(target, credentials);
  assert.equal(report.detection.supported, false);
  assert.equal(report.collection, null);
  assert.equal(fixture.calls.length, before + 1);
  assert.equal(fortiHealth("CPU states: none\nMemory: unknown").cpuUsagePercent, null);
  assert.equal(fortiHealth("CPU states: 101% idle\nMemory: 101%").memoryUsagePercent, null);
  assert.deepEqual(
    parseFortiBlocks('config system interface\nedit "incomplete"\n set ip 192.0.2.1\n'),
    [],
  );
  const sanitized = redactFortiOutput(
    'set private-key "BEGIN\nSECRET_KEY_LINE\nEND"\nset psksecret ENC SECRET_PSK\nset auth-passwd "AUTH_SECRET"\nset name "safe"',
  );
  assert.ok(!sanitized.includes("SECRET"));
  assert.ok(sanitized.includes('set name "safe"'));
  assert.ok(
    !redactFortiOutput("enc: aes key=32 SECRET_DIAGNOSTIC_HEX").includes("SECRET_DIAGNOSTIC_HEX"),
  );
  fixture.mode("normal");
  const monitoring = await collectSshMonitoring(target, credentials);
  assert.equal(monitoring.measurements.find((m) => m.key === "cpu.usage_percent")?.value, 8);
  assert.equal(monitoring.measurements.filter((m) => m.key === "network.rx_bytes").length, 2);
  fixture.mode("large");
  report = await collectFortiInventory(target, credentials);
  assert.ok(report.warnings.includes("FORTIGATE_OUTPUT_TRUNCATED"));
  assert.ok(report.collection.tables.find((t) => t.key === "addresses").rows.length < 300);
  assert.equal(report.collection.inventoryStatus, "partial");
  console.log(
    "FortiGate: real OpenSSH PTY/More, password/key, FortiOS identity, CPU/memory/sessions/uptime/counters, nested config/VPN parsing, permission/unsupported/large output, secret redaction and monitoring passed.",
  );
} finally {
  await fixture.close();
}
