import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { Client } from "pg";
import { config } from "dotenv";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
import { esxiSshFixture } from "./fixtures/esxi-ssh-server.mjs";
import { monitoringSnmpAgent } from "./fixtures/monitoring-snmp-agent.mjs";
import { networkApiFixture } from "./fixtures/network-api-server.mjs";
import "reflect-metadata";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { validateEnv } = require("../dist/config/env.js"),
  { databaseOptions } = require("../dist/database/database.options.js");
const original = validateEnv(process.env),
  name = "eos_monitor_test_" + randomBytes(8).toString("hex");
const maintenance = new Client({
  host: original.DB_HOST,
  port: original.DB_PORT,
  user: original.DB_USERNAME,
  password: original.DB_PASSWORD,
  database: original.DB_DATABASE,
});
let app,
  db,
  fixture,
  created = false,
  snmpAgent,
  sshFixture;
try {
  await maintenance.connect();
  await maintenance.query(`CREATE DATABASE "${name}"`);
  created = true;
  process.env.DB_DATABASE = name;
  const migration = new DataSource({
    ...databaseOptions(validateEnv(process.env)),
    logging: false,
  });
  try {
    await migration.initialize();
    await migration.runMigrations();
  } finally {
    if (migration.isInitialized) await migration.destroy();
  }
  fixture = await networkApiFixture();
  const { AppModule } = require("../dist/app.module.js"),
    { AppUser } = require("../dist/modules/users/user.entity.js"),
    { DeviceMonitoringService } = require("../dist/modules/devices/device-monitoring.service.js"),
    { DeviceMonitoringWorker } = require("../dist/modules/devices/device-monitoring.worker.js");
  app = await NestFactory.create(AppModule, { logger: false });
  app.setGlobalPrefix("api/v1");
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
  await app.listen(0, "127.0.0.1");
  db = app.get(DataSource);
  const base = (await app.getUrl()) + "/api/v1",
    monitor = app.get(DeviceMonitoringService),
    worker = app.get(DeviceMonitoringWorker);
  async function call(path, { token, body, method = body === undefined ? "GET" : "POST" } = {}) {
    const r = await fetch(base + path, {
      method,
      headers: {
        ...(token ? { authorization: "Bearer " + token } : {}),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: r.status, body: await r.json() };
  }
  async function account(role, owner) {
    const r = await call("/auth/register", {
      body: {
        username: "monitor_" + randomBytes(6).toString("hex"),
        password: "Monitoring-Fixture-2026!",
        displayName: "آزمون پایش",
      },
    });
    assert.equal(r.status, 201);
    await db
      .getRepository(AppUser)
      .update(r.body.user.id, { role, workspaceOwnerId: owner ?? null });
    return { id: r.body.user.id, token: r.body.accessToken };
  }
  const admin = await account("co_admin"),
    employee = await account("co_employee", admin.id),
    other = await account("co_admin"),
    auth = { token: admin.token };
  const actor = await db.getRepository(AppUser).findOneByOrFail({ id: admin.id });
  await call("/devices/companies", auth);
  const credentialBody = {
    name: "Monitor",
    username: fixture.username,
    password: fixture.password,
    caCertificate: fixture.ca,
  };
  const credential = await call("/devices/api-credentials", { ...auth, body: credentialBody });
  assert.equal(credential.status, 201);
  const input = {
    name: "Monitor fixture",
    vendor: "mikrotik",
    type: "mikrotik",
    protocol: "api",
    host: fixture.host,
    managementPort: fixture.port,
    companyId: admin.id,
    apiCredentialId: credential.body.id,
    environment: "lab",
    tags: [],
  };
  const createdDevice = await call("/devices", { ...auth, body: input });
  assert.equal(createdDevice.status, 201);
  const id = createdDevice.body.id,
    path = `/devices/${id}/monitoring`;
  assert.equal((await call(path, { token: other.token })).status, 404);
  assert.equal(
    (await call(path, { ...auth, body: { enabled: true, intervalSeconds: 2 }, method: "PUT" }))
      .status,
    400,
  );
  assert.equal(
    (
      await call(path, {
        token: employee.token,
        method: "PUT",
        body: { enabled: true, intervalSeconds: 300 },
      })
    ).status,
    403,
  );
  assert.equal((await call(path + "/collect", { token: employee.token, body: {} })).status, 403);
  let report = await call(path, auth);
  assert.equal(report.status, 200);
  assert.equal(report.body.latest, null);
  assert.deepEqual(report.body.series, []);
  const collected = await call(path + "/collect", { ...auth, body: {} });
  assert.equal(collected.status, 201);
  assert.equal(collected.body.collected, true);
  report = await call(path, auth);
  assert.equal(report.body.stale, false);
  assert.equal(
    report.body.latest.measurements.find((m) => m.key === "cpu.usage_percent").value,
    15,
  );
  assert.equal(
    report.body.latest.measurements.find((m) => m.key === "memory.usage_percent").value,
    50,
  );
  assert.equal(
    report.body.latest.measurements.find((m) => m.key === "system.uptime_seconds").value,
    266400,
  );
  assert.ok(report.body.series.some((s) => s.key === "cpu.usage_percent"));
  assert.ok(!JSON.stringify(report.body).includes(fixture.password));
  assert.ok(!JSON.stringify(report.body).includes("sealedCredentials"));
  assert.ok(!JSON.stringify(report.body).includes("authorizedBindings"));
  assert.equal((await call(path, { token: employee.token })).body.latest.measurements[0].value, 15);
  const saved = await call(path, {
    ...auth,
    method: "PUT",
    body: { enabled: true, intervalSeconds: 60, revision: report.body.config.revision },
  });
  assert.equal(saved.status, 200);
  assert.equal(
    (
      await call(path, {
        ...auth,
        method: "PUT",
        body: { enabled: false, intervalSeconds: 60, revision: report.body.config.revision },
      })
    ).status,
    409,
  );
  assert.equal(
    (await call(path, { ...auth, method: "PUT", body: { enabled: false, intervalSeconds: 60 } }))
      .status,
    409,
  );
  // The actual worker loop uses a dedicated test database, never user schedules.
  worker.start();
  const waitUntil = Date.now() + 12000;
  while (Date.now() < waitUntil) {
    const [count] = await db.query(
      'SELECT count(*)::int AS count FROM "device_monitor_runs" WHERE "deviceId"=$1',
      [id],
    );
    if (count.count >= 2) break;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  await worker.onModuleDestroy();
  let [count] = await db.query(
    'SELECT count(*)::int AS count FROM "device_monitor_runs" WHERE "deviceId"=$1',
    [id],
  );
  assert.ok(count.count >= 2, "scheduled collection executes");
  // Two processes cannot own the same collection lease; changed credentials discard in-flight results.
  let observed = fixture.pause("mikrotik");
  const pending = monitor.collect(actor, id);
  await observed;
  assert.equal((await call(path + "/collect", { ...auth, body: {} })).status, 409);
  const changed = await call(`/devices/api-credentials/${credential.body.id}`, {
    ...auth,
    method: "PUT",
    body: credentialBody,
  });
  assert.equal(changed.status, 200);
  fixture.release();
  await assert.rejects(pending, (error) => error.getStatus?.() === 409);
  assert.equal((await call(path, auth)).body.latest, null);
  await db.query(
    'UPDATE "device_monitoring" SET "nextRunAt"=now()-interval \'1 minute\' WHERE "deviceId"=$1',
    [id],
  );
  await worker.tick();
  report = await call(path, auth);
  assert.equal(report.body.config.enabled, false);
  assert.equal(report.body.config.lastErrorCode, "MONITOR_CONFIGURATION_INVALID");
  assert.equal((await monitor.collect(actor, id)).collected, true);
  report = await call(path, auth);
  assert.equal(
    (
      await call(path, {
        ...auth,
        method: "PUT",
        body: { enabled: true, intervalSeconds: 60, revision: report.body.config.revision },
      })
    ).status,
    200,
  );
  fixture.mode("malformed");
  assert.equal((await monitor.collect(actor, id)).collected, false);
  fixture.mode("normal");
  report = await call(path, auth);
  assert.equal(report.body.stale, true);
  assert.ok(report.body.latest);
  assert.equal(report.body.history[0].status, "failed");
  const backoff = Date.parse(report.body.config.nextRunAt) - Date.now();
  assert.ok(backoff > 90000 && backoff <= 120000);
  // Archiving halts scheduling and restoring does not reactivate it.
  await call(path, {
    ...auth,
    method: "PUT",
    body: { enabled: true, intervalSeconds: 300, revision: report.body.config.revision },
  });
  observed = fixture.pause("mikrotik");
  const archivedPending = monitor.collect(actor, id);
  await observed;
  assert.equal((await call(`/devices/${id}`, { ...auth, method: "DELETE" })).status, 200);
  fixture.release();
  await assert.rejects(archivedPending, (error) => error.getStatus?.() === 404);
  assert.equal((await call(path, auth)).status, 404);
  assert.equal(
    (await db.query('SELECT enabled FROM device_monitoring WHERE "deviceId"=$1', [id]))[0].enabled,
    false,
  );
  assert.equal((await call(`/devices/${id}/restore`, { ...auth, body: {} })).status, 201);
  assert.equal((await call(path, auth)).body.config.enabled, false);
  // Company transfer separates current graphs and stops automatic requests.
  const company = await call("/devices/companies", { ...auth, body: { name: "انتقال پایش" } });
  assert.equal(company.status, 201);
  assert.equal(
    (
      await call(`/devices/${id}`, {
        ...auth,
        method: "PUT",
        body: { ...input, companyId: company.body.id },
      })
    ).status,
    200,
  );
  report = await call(path, auth);
  assert.equal(report.body.latest, null);
  assert.deepEqual(report.body.history, []);
  assert.deepEqual(report.body.series, []);
  // History and metric storage are bounded and roll up without losing weighted means.
  const {
    storeMeasurements,
    metricSeries,
  } = require("../dist/modules/devices/monitoring-storage.js");
  const at = new Date(Date.now() - 2 * 86400000).toISOString(),
    old = new Date(Date.now() - 40 * 86400000).toISOString();
  await db.transaction(async (manager) => {
    await storeMeasurements(manager, id, company.body.id, "generation", "epoch", at, [
      { key: "cpu.usage_percent", value: 20, label: "", kind: "gauge", unit: "percent" },
    ]);
    await storeMeasurements(manager, id, company.body.id, "generation", "epoch", at, [
      { key: "cpu.usage_percent", value: 40, label: "", kind: "gauge", unit: "percent" },
    ]);
    await storeMeasurements(manager, id, company.body.id, "generation", "epoch", old, [
      { key: "cpu.usage_percent", value: 99, label: "", kind: "gauge", unit: "percent" },
    ]);
  });
  const rows = await db.query(
    'SELECT * FROM device_metric_buckets WHERE "deviceId"=$1 AND generation=$2',
    [id, "generation"],
  );
  assert.equal(rows.length, 1);
  assert.equal(rows[0].resolution, 3600);
  assert.equal(rows[0].sampleCount, 2);
  assert.equal(rows[0].sumValue, 60);
  const first = {
    metricKey: "network.rx_bytes",
    label: "ether1",
    unit: "bytes",
    kind: "counter",
    counterEpoch: "a",
    bucketAt: new Date(0),
    firstAt: new Date(0),
    lastAt: new Date(0),
    firstValue: 10,
    lastValue: 10,
    sumValue: 10,
    sampleCount: 1,
  };
  const rates = metricSeries([
    first,
    { ...first, lastAt: new Date(1000), lastValue: 1000010 },
    { ...first, counterEpoch: "b", lastAt: new Date(2000), lastValue: 2000010 },
  ]);
  assert.equal(rates[0].points.length, 1);
  assert.equal(rates[0].points[0].value, 8);
  // Run pruning is tested with actual collections and existing synthetic histories.
  await db.query(
    `INSERT INTO device_monitor_runs (id,"deviceId","companyId","actorId",status,"startedAt","completedAt") SELECT md5(i::text),$1,$2,$3,'success',now()-i*interval '1 minute',now()-i*interval '1 minute' FROM generate_series(1,65) i`,
    [id, company.body.id, admin.id],
  );
  await call(`/devices/${id}/api-credential`, {
    ...auth,
    method: "PUT",
    body: { credentialId: credential.body.id },
  });
  assert.equal((await monitor.collect(actor, id)).collected, true);
  [count] = await db.query(
    'SELECT count(*)::int AS count FROM device_monitor_runs WHERE "deviceId"=$1',
    [id],
  );
  assert.equal(count.count, 50);
  // An interface counter reset starts a new epoch even when uptime does not change.
  const previousEpoch = (
    await db.query('SELECT "counterEpoch" FROM device_monitoring WHERE "deviceId"=$1', [id])
  )[0].counterEpoch;
  fixture.counters(100, 200);
  assert.equal((await monitor.collect(actor, id)).collected, true);
  const resetEpoch = (
    await db.query('SELECT "counterEpoch" FROM device_monitoring WHERE "deviceId"=$1', [id])
  )[0].counterEpoch;
  assert.notEqual(resetEpoch, previousEpoch);
  fixture.counters(200, 400);
  assert.equal((await monitor.collect(actor, id)).collected, true);
  assert.equal(
    (await db.query('SELECT "counterEpoch" FROM device_monitoring WHERE "deviceId"=$1', [id]))[0]
      .counterEpoch,
    resetEpoch,
  );
  // Preferred SNMP monitoring produces real metrics; failure falls back to the saved API.
  snmpAgent = await monitoringSnmpAgent();
  const snmpCredential = await call("/devices/snmp-credentials", {
    ...auth,
    body: { name: "SNMP monitoring", ...snmpAgent.secret },
  });
  assert.equal(snmpCredential.status, 201);
  const channel = await call(`/devices/${id}/connection-channels`, {
    ...auth,
    method: "PUT",
    body: {
      method: "snmpv3",
      credentialId: snmpCredential.body.id,
      host: snmpAgent.host,
      port: snmpAgent.port,
      priority: 1,
    },
  });
  assert.equal(channel.status, 200);
  const tested = await call(`/devices/${id}/connection-channels/test-secondary`, {
    ...auth,
    body: {},
  });
  assert.equal(tested.body.connected, true);
  assert.equal((await monitor.collect(actor, id)).collected, true);
  report = await call(path, auth);
  assert.equal(report.body.latest.source.role, "observability");
  assert.equal(
    report.body.latest.measurements.find((m) => m.key === "cpu.usage_percent").value,
    30,
  );
  snmpAgent.close();
  snmpAgent = undefined;
  assert.equal((await monitor.collect(actor, id)).collected, true);
  report = await call(path, auth);
  assert.equal(report.body.latest.source.role, "management");
  assert.ok(report.body.latest.warnings.includes("PREFERRED_SOURCE_UNAVAILABLE"));
  // ESXi SSH inventory is projected through the normal authenticated API and feeds monitoring.
  sshFixture = await esxiSshFixture();
  const sshCredentialBody = {
    name: "ESXi SSH",
    operation: "verify",
    username: sshFixture.username,
    password: sshFixture.password,
    hostKey: sshFixture.hostKey,
  };
  const sshCredential = await call("/devices/credentials", { ...auth, body: sshCredentialBody });
  assert.equal(sshCredential.status, 201);
  const sshInput = {
    name: "ESXi SSH",
    type: "esxi",
    vendor: "vmware",
    protocol: "ssh",
    host: sshFixture.host,
    managementPort: sshFixture.port,
    companyId: admin.id,
    credentialId: sshCredential.body.id,
    environment: "lab",
    tags: [],
  };
  const sshDevice = await call("/devices", { ...auth, body: sshInput });
  assert.equal(sshDevice.status, 201);
  const sshId = sshDevice.body.id,
    sshPath = `/devices/${sshId}/esxi-ssh-inventory`;
  assert.equal((await call(sshPath, { token: employee.token, body: {} })).status, 403);
  assert.equal((await call(sshPath, { token: other.token, body: {} })).status, 404);
  const sshReport = await call(sshPath, { ...auth, body: {} });
  assert.equal(sshReport.status, 201);
  assert.equal(sshReport.body.cpuPercent, 25);
  assert.equal(sshReport.body.services[0].running, true);
  assert.equal(sshReport.body.transport, "ssh");
  assert.ok(!JSON.stringify(sshReport.body).includes(sshFixture.password));
  assert.equal((await monitor.collect(actor, sshId)).collected, true);
  const sshMetrics = (await call(`/devices/${sshId}/monitoring`, auth)).body;
  assert.equal(sshMetrics.latest.source.method, "ssh");
  assert.equal(sshMetrics.latest.measurements.find((m) => m.key === "cpu.usage_percent").value, 25);
  assert.ok(sshMetrics.series.some((s) => s.key === "datastore.usage_percent"));
  const sshHeld = sshFixture.pause("vim-cmd hostsvc/hostsummary"),
    sshPending = call(sshPath, { ...auth, body: {} });
  await sshHeld;
  assert.equal((await call(sshPath, { ...auth, body: {} })).status, 409);
  assert.equal(
    (
      await call(`/devices/credentials/${sshCredential.body.id}`, {
        ...auth,
        method: "PUT",
        body: sshCredentialBody,
      })
    ).status,
    200,
  );
  sshFixture.release();
  assert.equal((await sshPending).status, 409);
  assert.equal((await call(`/devices/${sshId}`, auth)).body.verification, null);
  const archiveHeld = sshFixture.pause("vim-cmd hostsvc/hostsummary"),
    archivePending = call(sshPath, { ...auth, body: {} });
  await archiveHeld;
  assert.equal((await call(`/devices/${sshId}`, { ...auth, method: "DELETE" })).status, 200);
  sshFixture.release();
  assert.equal((await archivePending).status, 409);
  // Revoking the scheduler's role prevents any network call.
  report = await call(path, auth);
  await call(path, {
    ...auth,
    method: "PUT",
    body: { enabled: true, intervalSeconds: 60, revision: report.body.config.revision },
  });
  await db.getRepository(AppUser).update(admin.id, { role: "co_employee" });
  const before = fixture.calls.length;
  await worker.tick();
  assert.equal(fixture.calls.length, before);
  assert.equal(
    (await db.query('SELECT enabled FROM device_monitoring WHERE "deviceId"=$1', [id]))[0].enabled,
    false,
  );
  const {
    LINUX_MONITOR_SCRIPT,
    parseLinuxMonitoring,
    parseCliMonitoring,
  } = require("../dist/modules/devices/monitoring-ssh.js");
  const { stdout } = await promisify(execFile)("sh", ["-c", LINUX_MONITOR_SCRIPT], {
    timeout: 5000,
  });
  const local = parseLinuxMonitoring(stdout);
  assert.ok(local.some((m) => m.key === "memory.usage_percent" && m.value >= 0 && m.value <= 100));
  assert.ok(local.some((m) => m.key === "network.rx_bytes"));
  assert.throws(() => parseLinuxMonitoring("partial response"));
  assert.deepEqual(parseCliMonitoring("cisco", "unsupported"), []);
  assert.equal(
    parseCliMonitoring("mikrotik", "cpu-load: 15%\nfree-memory: 32MiB\ntotal-memory: 64MiB").find(
      (m) => m.key === "memory.usage_percent",
    ).value,
    50,
  );
  console.log(
    "PASS monitoring: real HTTPS collector, scheduler, roles, lease/races, stale data, archive/restore, company isolation, credential revocation, aggregation/retention, counter epochs, preferred SNMP/API fallback, ESXi SSH inventory/monitoring/races and read-only Linux metrics",
  );
} finally {
  if (app) await app.close();
  if (fixture) await fixture.close();
  if (snmpAgent) snmpAgent.close();
  if (sshFixture) await sshFixture.close();
  if (created) await maintenance.query(`DROP DATABASE "${name}" WITH (FORCE)`);
  await maintenance.end();
  process.env.DB_DATABASE = original.DB_DATABASE;
}
