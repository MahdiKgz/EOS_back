import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { esxiSshFixture } from "./fixtures/esxi-ssh-server.mjs";
const require = createRequire(import.meta.url),
  { collectEsxiSshInventory } = require("../dist/modules/devices/esxi-ssh-collector.js"),
  { apiMeasurements } = require("../dist/modules/devices/monitoring-measurements.js"),
  { esxiNicStatsCommand, esxiCsv } = require("../dist/modules/devices/esxi-ssh-inventory.js");
const fixture = await esxiSshFixture();
try {
  const device = {
      id: "fixture",
      host: fixture.host,
      managementPort: fixture.port,
      type: "esxi",
      protocol: "ssh",
    },
    credentials = {
      username: fixture.username,
      password: fixture.password,
      hostKey: fixture.hostKey,
    };
  const report = await collectEsxiSshInventory(device, credentials);
  assert.equal(report.transport, "ssh");
  assert.equal(report.cpuPercent, 25);
  assert.equal(report.memoryPercent, 12.5);
  assert.equal(report.memoryBytes, 8589934592);
  assert.equal(report.hostname, "esxi.fixture");
  assert.equal(report.services[0].label, 'SSH "daemon" {safe}');
  assert.equal(report.services[0].running, true);
  assert.equal(report.services[0].required, false);
  assert.equal(report.datastores[0].name, "data, store");
  assert.equal(report.physicalNics[0].linkUp, true);
  assert.equal(report.interfaceCounters[0].rxBytes, 123456789);
  assert.equal(report.portGroups[0].vlanId, 10);
  assert.equal(report.firewallRulesets[0].enabled, true);
  assert.ok(!JSON.stringify(report).includes(fixture.password));
  assert.equal(
    apiMeasurements({ ...report, kind: "esxi" }).find((m) => m.key === "datastore.usage_percent")
      .value,
    50,
  );
  const keyReport = await collectEsxiSshInventory(device, {
    username: fixture.username,
    privateKey: fixture.privateKey,
    hostKey: fixture.hostKey,
  });
  assert.equal(keyReport.hostname, "esxi.fixture");
  fixture.mode("partial");
  const partial = await collectEsxiSshInventory(device, credentials);
  assert.equal(partial.cpuPercent, null);
  assert.equal(partial.memoryPercent, null);
  assert.equal(partial.memoryBytes, 8589934592);
  assert.ok(partial.coverage.some((c) => c.key === "summary" && c.status === "unavailable"));
  fixture.mode("malformed");
  const malformed = await collectEsxiSshInventory(device, credentials);
  assert.equal(malformed.datastoreCount, null);
  assert.deepEqual(malformed.datastores, []);
  fixture.mode("mismatch");
  const before = fixture.calls.length;
  await assert.rejects(
    collectEsxiSshInventory(device, credentials),
    (error) => error.code === "ESXI_SSH_PLATFORM_MISMATCH",
  );
  assert.deepEqual(fixture.calls.slice(before), ["vmware -v"]);
  assert.throws(() => esxiNicStatsCommand("vmnic0;reboot"));
  assert.throws(() => esxiCsv('name,type\n"unclosed'));
  await assert.rejects(collectEsxiSshInventory(device, { ...credentials, password: "incorrect" }));
  console.log(
    "PASS ESXi SSH: actual OpenSSH password/key transport, typed summary and quoted VIM/CSV, real readonly command whitelist, projected inventory/counters, partial/invalid responses, platform rejection and password redaction",
  );
} finally {
  await fixture.close();
}
