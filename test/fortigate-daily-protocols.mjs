import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fortigateSshFixture } from "./fixtures/fortigate-ssh-server.mjs";
const require = createRequire(import.meta.url),
  { runSshCommand } = require("../dist/modules/devices/ssh-transport.js"),
  { collectFortiInventory } = require("../dist/modules/devices/fortigate-collector.js"),
  { buildFortiDailyCheck } = require("../dist/modules/devices/fortigate-daily-check.js"),
  {
    parseFortiLogs,
    FORTIGATE_LOG_PREPARATION,
  } = require("../dist/modules/devices/fortigate-logs.js"),
  { redactFortiOutput } = require("../dist/modules/devices/fortigate-output.js");
const fixture = await fortigateSshFixture();
try {
  const device = {
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
  const report = await collectFortiInventory(device, credentials),
    daily = report.collection.dailyCheck;
  assert.equal(daily.sections.length, 8);
  assert.equal(daily.status, "needs_review");
  assert.equal(daily.sections.find((s) => s.key === "license").status, "needs_review");
  assert.equal(daily.sections.find((s) => s.key === "system_health").status, "safe");
  assert.ok(daily.findings.some((f) => f.title.includes("wan1")));
  assert.ok(!JSON.stringify(report).includes("NEVER_FORTI_SECRET"));
  assert.equal(report.collection.logs.entries.length, 2);
  assert.equal(report.collection.logs.entries[0].eventTime, "1794052800000000000");
  assert.equal(report.collection.logs.reportedTotal, 2);
  assert.ok(
    fixture.logSessions.some(
      (commands) =>
        JSON.stringify(commands) ===
        JSON.stringify([...FORTIGATE_LOG_PREPARATION, "execute log display"]),
    ),
  );
  const safe = structuredClone(report.collection);
  safe.system.license = "Valid";
  safe.tables.find((t) => t.key === "interfaces").rows.forEach((row) => (row.allowaccess = "ping"));
  assert.equal(
    buildFortiDailyCheck(safe).status,
    "safe",
    JSON.stringify(
      buildFortiDailyCheck(safe).sections.map((s) => ({
        key: s.key,
        status: s.status,
        coverage: s.coverage,
      })),
    ) +
      JSON.stringify(
        safe.commandEvidence
          .filter((e) => e.state !== "collected")
          .map((e) => ({ id: e.commandId, state: e.state, error: e.errorCode })),
      ),
  );
  const missing = structuredClone(safe);
  missing.health.memoryUsagePercent = null;
  missing.commandEvidence.find((e) => e.commandId === "admins").state = "requires_privilege";
  assert.equal(buildFortiDailyCheck(missing).status, "not_checked");
  assert.equal(buildFortiDailyCheck(missing).coverage, "partial");
  const critical = structuredClone(safe);
  critical.health.cpuUsagePercent = 95;
  assert.equal(buildFortiDailyCheck(critical).status, "critical");
  const unavailable = structuredClone(safe);
  unavailable.commandEvidence.forEach((e) => (e.state = "not_supported"));
  unavailable.health.cpuUsagePercent = null;
  unavailable.health.memoryUsagePercent = null;
  assert.equal(buildFortiDailyCheck(unavailable).status, "not_supported");
  fixture.mode("log-failure");
  let before = fixture.calls.length;
  await assert.rejects(
    runSshCommand(device, credentials, "execute log display", {
      interactive: true,
      prepareCommands: FORTIGATE_LOG_PREPARATION,
    }),
    (e) => e.code === "SSH_COMMAND_REQUIRES_PRIVILEGE",
  );
  assert.deepEqual(fixture.calls.slice(before), ["execute log filter reset"]);
  fixture.mode("empty-logs");
  let raw = await runSshCommand(device, credentials, "execute log display", {
    interactive: true,
    prepareCommands: FORTIGATE_LOG_PREPARATION,
  });
  assert.equal(parseFortiLogs(raw.toString()).reportedTotal, 0);
  fixture.mode("large-logs");
  raw = await runSshCommand(device, credentials, "execute log display", {
    interactive: true,
    prepareCommands: FORTIGATE_LOG_PREPARATION,
  });
  assert.equal(parseFortiLogs(raw.toString()).entries.length, 500);
  await assert.rejects(
    runSshCommand(device, credentials, "execute log display", {
      interactive: true,
      prepareCommands: ["execute log delete all"],
    }),
    /Invalid FortiGate/,
  );
  const sanitized = redactFortiOutput(
    'date=2026-11-07 logid=1 msg="private" password="NEVER_INLINE_SECRET" other=tail',
  );
  assert.ok(!JSON.stringify(parseFortiLogs(sanitized)).includes("NEVER_INLINE_SECRET"));
  console.log(
    "FortiGate daily/logs: real same-PTY filter reset/500/display, abort on preparation failure, bounded/empty/secret logs, eight evidence-based checks, safe/incomplete/unsupported/critical and incomplete coverage passed.",
  );
} finally {
  await fixture.close();
}
