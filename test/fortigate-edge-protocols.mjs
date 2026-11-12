import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fortigateSshFixture } from "./fixtures/fortigate-ssh-server.mjs";
const require = createRequire(import.meta.url),
  {
    collectFortiInventory,
    redactFortiOutput,
  } = require("../dist/modules/devices/fortigate-collector.js"),
  { sanitizeFortiReport } = require("../dist/modules/devices/fortigate-output.js");
const fixture = await fortigateSshFixture({ password: "Version" });
try {
  const report = await collectFortiInventory(
    {
      id: "fixture",
      host: fixture.host,
      managementPort: fixture.port,
      type: "fortigate",
      protocol: "ssh",
    },
    { username: fixture.username, password: fixture.password, hostKey: fixture.hostKey },
  );
  assert.equal(report.detection.supported, true);
  assert.equal(report.detection.version, "7.4.4");
  assert.equal(report.collection.health.memoryUsagePercent, 40);
  assert.equal(report.collection.system.vendor, "fortigate");
  assert.ok(!JSON.stringify(report).includes("Version"));
  const sample = sanitizeFortiReport(
    {
      state: "collected",
      commandId: "system",
      key: "admins",
      title: "Admin",
      columns: ["name", "profile"],
      sources: ["admins"],
      rows: [{ name: "collected-user" }],
      evidence: ["collected"],
    },
    "collected",
  );
  assert.equal(sample.state, "collected");
  assert.equal(sample.rows[0].name, "[REDACTED]-user");
  assert.equal(sample.evidence[0], "[REDACTED]");
  assert.ok(
    !redactFortiOutput("enc: aes key=32 SECRET_DIAGNOSTIC_HEX").includes("SECRET_DIAGNOSTIC_HEX"),
  );
  console.log(
    "FortiGate edge protocol: short credential matching a header does not break identity, values are scrubbed after parsing, fixed states/schema preserved, diagnostic key material redacted.",
  );
} finally {
  await fixture.close();
}
