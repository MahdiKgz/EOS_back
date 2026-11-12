import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
import { ciscoSshFixture } from "./fixtures/cisco-ssh-server.mjs";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js"),
  { DeviceCapabilitiesService } = require("../dist/modules/devices/device-capabilities.service.js"),
  { DevicesService } = require("../dist/modules/devices/devices.service.js"),
  { DeviceMonitoringService } = require("../dist/modules/devices/device-monitoring.service.js"),
  users = [];
const fixture = await ciscoSshFixture();
let app, db;
try {
  app = await NestFactory.create(AppModule, { logger: false });
  app.setGlobalPrefix("api/v1");
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
  await app.listen(0, "127.0.0.1");
  db = app.get(DataSource);
  const base = (await app.getUrl()) + "/api/v1";
  async function call(path, { token, body, method = body === undefined ? "GET" : "POST" } = {}) {
    const response = await fetch(base + path, {
      method,
      headers: {
        ...(token ? { authorization: "Bearer " + token } : {}),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  }
  async function account(role, owner) {
    const result = await call("/auth/register", {
      body: {
        username: "cisco_" + randomBytes(6).toString("hex"),
        password: "Cisco-fixture-2026!",
        displayName: "آزمون کشف قابلیت",
      },
    });
    assert.equal(result.status, 201);
    users.push(result.body.user.id);
    await db
      .getRepository(AppUser)
      .update(result.body.user.id, { role, workspaceOwnerId: owner ?? null });
    return { id: result.body.user.id, token: result.body.accessToken };
  }
  const admin = await account("co_admin"),
    employee = await account("co_employee", admin.id),
    other = await account("co_admin"),
    auth = { token: admin.token };
  const actor = await db.getRepository(AppUser).findOneByOrFail({ id: admin.id }),
    service = app.get(DeviceCapabilitiesService);
  await call("/devices/companies", auth);
  const credentialBody = {
    name: "Cisco fixture",
    operation: "verify",
    username: fixture.username,
    password: fixture.password,
    hostKey: fixture.hostKey,
  };
  const credential = await call("/devices/credentials", { ...auth, body: credentialBody });
  assert.equal(credential.status, 201);
  const input = {
    name: "Cisco fixture",
    type: "cisco",
    vendor: "Cisco Systems",
    protocol: "ssh",
    host: fixture.host,
    managementPort: fixture.port,
    companyId: admin.id,
    credentialId: credential.body.id,
    environment: "lab",
    tags: [],
  };
  const created = await call("/devices", { ...auth, body: input });
  assert.equal(created.status, 201);
  const id = created.body.id,
    path = `/devices/${id}/capabilities`;
  assert.equal((await call(path)).status, 401);
  assert.equal((await call(path, { token: other.token })).status, 404);
  assert.equal((await call(path + "/refresh", { token: employee.token, body: {} })).status, 403);
  assert.equal(fixture.calls.length, 0);
  assert.equal((await call(path, auth)).body.latest, null);
  let result = await call(path + "/refresh", { ...auth, body: {} });
  assert.equal(result.status, 201);
  assert.equal(result.body.supported, true);
  let report = (await call(path, auth)).body;
  assert.equal(report.ready, true);
  assert.equal(report.stale, false);
  assert.equal(report.running, false);
  assert.equal(report.latest.detection.platform, "cisco-ios-xe");
  assert.equal(report.latest.collection.health.cpu.fiveSeconds, 7);
  assert.equal(report.latest.collection.health.memory[0].usedBytes, 45000000);
  for (const forbidden of [
    "NEVER_CISCO_",
    fixture.password,
    "leaseToken",
    "binding",
    "sealedCredentials",
  ])
    assert.ok(!JSON.stringify(report).includes(forbidden));
  assert.equal(
    (await call(path, { token: employee.token })).body.latest.detection.platform,
    "cisco-ios-xe",
  );
  let list = await call("/vendors/cisco", auth);
  assert.equal(list.body.devices.items[0].platform, "cisco-ios-xe");
  assert.ok(list.body.devices.items[0].platformCollectedAt);
  await db.query(
    'UPDATE device_capability_cache SET "expiresAt"=now()-interval \'1 second\' WHERE "deviceId"=$1',
    [id],
  );
  report = (await call(path, auth)).body;
  assert.equal(report.stale, true);
  assert.equal(report.ready, false);
  assert.ok(report.latest);
  let observed = fixture.pause("show processes cpu"),
    pending = service.refresh(actor, id);
  await observed;
  assert.equal((await call(path + "/refresh", { ...auth, body: {} })).status, 409);
  const secondService = new DeviceCapabilitiesService(db, app.get(DevicesService));
  await assert.rejects(secondService.refresh(actor, id), (error) => error.getStatus?.() === 409);
  assert.equal(
    (
      await call(`/devices/credentials/${credential.body.id}`, {
        ...auth,
        method: "PUT",
        body: credentialBody,
      })
    ).status,
    200,
  );
  fixture.release();
  await assert.rejects(pending, (error) => error.getStatus?.() === 409);
  assert.equal((await call(path, auth)).body.ready, false);
  observed = fixture.pause("show processes cpu");
  pending = service.refresh(actor, id);
  await observed;
  assert.equal((await call(`/devices/${id}`, { ...auth, method: "DELETE" })).status, 200);
  assert.equal((await call(path, auth)).status, 404);
  assert.equal((await call(`/devices/${id}/restore`, { ...auth, body: {} })).status, 201);
  fixture.release();
  await assert.rejects(pending, (error) => error.getStatus?.() === 409);
  report = (await call(path, auth)).body;
  assert.equal(report.ready, false);
  assert.equal(report.history.length, 1);
  observed = fixture.pause("show processes cpu");
  pending = service.refresh(actor, id);
  await observed;
  await db.getRepository(AppUser).update(admin.id, { role: "co_employee" });
  fixture.release();
  await assert.rejects(pending, (error) => error.getStatus?.() === 403);
  await db.getRepository(AppUser).update(admin.id, { role: "co_admin" });
  fixture.mode("nxos");
  let before = fixture.calls.length;
  result = await service.refresh(actor, id);
  assert.equal(result.supported, false);
  assert.deepEqual(fixture.calls.slice(before), ["show version"]);
  report = (await call(path, auth)).body;
  assert.equal(report.stale, false);
  assert.equal(report.ready, false);
  assert.equal(report.latest.collection, null);
  assert.equal(report.latest.detection.platform, "cisco-nx-os");
  assert.equal((await call(`/devices/${id}`, auth)).body.verification, null);
  fixture.mode("partial");
  await service.refresh(actor, id);
  report = (await call(path, auth)).body;
  assert.equal(
    report.latest.collection.commandEvidence.find((c) => c.commandId === "memory").errorCode,
    "CISCO_COMMAND_REQUIRES_PRIVILEGE",
  );
  assert.equal(report.history[0].status, "partial");
  fixture.mode("normal");
  const monitor = app.get(DeviceMonitoringService);
  assert.equal((await monitor.collect(actor, id)).collected, true);
  const metrics = (await call(`/devices/${id}/monitoring`, auth)).body;
  assert.equal(metrics.latest.measurements.find((m) => m.key === "cpu.usage_percent").value, 7);
  assert.equal(metrics.latest.measurements.find((m) => m.key === "memory.usage_percent").value, 45);
  const company = await call("/devices/companies", { ...auth, body: { name: "انتقال Cisco" } });
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
  report = (await call(path, auth)).body;
  assert.equal(report.latest, null);
  assert.deepEqual(report.history, []);
  list = await call("/vendors/cisco", auth);
  assert.equal(list.body.devices.items[0].platform, null);
  await call(`/devices/${id}`, {
    ...auth,
    method: "PUT",
    body: { ...input, companyId: company.body.id },
  });
  await db.query(
    `INSERT INTO device_capability_runs (id,"deviceId","companyId","actorName",status,"startedAt","completedAt") SELECT $3||i::text,$1,$2,'fixture','collected',now()-i*interval '1 minute',now()-i*interval '1 minute' FROM generate_series(1,65) i`,
    [id, company.body.id, randomUUID()],
  );
  await service.refresh(actor, id);
  assert.equal(
    (
      await db.query(
        'SELECT count(*)::int AS count FROM device_capability_runs WHERE "deviceId"=$1',
        [id],
      )
    )[0].count,
    50,
  );
  const wrong = { ...credentialBody, password: "incorrect" };
  await call(`/devices/credentials/${credential.body.id}`, { ...auth, method: "PUT", body: wrong });
  await assert.rejects(service.refresh(actor, id), (error) => error.getStatus?.() === 502);
  report = (await call(path, auth)).body;
  assert.equal(report.stale, true);
  assert.ok(report.latest);
  assert.equal(report.lastErrorCode, "CISCO_AUTH_FAILED");
  assert.equal(report.history[0].status, "failed");
  console.log(
    "PASS Cisco capability API: actual SSH inventory/resources, employee/tenant permissions, safe cache/expiry, database lease, credential/archive-restore/role races, unsupported families, partial commands, monitoring samples, company transfer and bounded history",
  );
} finally {
  fixture.release();
  if (db && users.length) await db.getRepository(AppUser).delete(users);
  if (app) await app.close();
  await fixture.close();
}
