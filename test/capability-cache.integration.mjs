import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js");
let app, db, user;
try {
  app = await NestFactory.create(AppModule, { logger: false });
  app.setGlobalPrefix("api/v1");
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
  await app.listen(0, "127.0.0.1");
  db = app.get(DataSource);
  const base = (await app.getUrl()) + "/api/v1";
  async function call(path, { body, method = body === undefined ? "GET" : "POST" } = {}) {
    const response = await fetch(base + path, {
      method,
      headers: {
        ...(user ? { authorization: "Bearer " + user.accessToken } : {}),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  }
  user = (
    await call("/auth/register", {
      body: {
        username: "cache_" + randomBytes(6).toString("hex"),
        password: "Cache-fixture-2026!",
        displayName: "آزمون جداسازی موجودی",
      },
    })
  ).body;
  await db.getRepository(AppUser).update(user.user.id, { role: "co_admin" });
  await call("/devices/companies");
  const input = {
      name: "Scope fixture",
      host: "192.0.2.9",
      managementPort: 22,
      type: "fortigate",
      vendor: "fortinet",
      protocol: "ssh",
      companyId: user.user.id,
      tags: [],
      environment: "lab",
    },
    created = await call("/devices", { body: input });
  assert.equal(created.status, 201);
  const id = created.body.id,
    path = `/devices/${id}/capabilities`;
  const snapshot = {
    detection: { vendor: "fortigate", platform: "fortios", supported: true },
    collection: null,
    warnings: [],
    collectedAt: new Date().toISOString(),
    source: { host: input.host, port: 22 },
  };
  await db.query(
    'INSERT INTO device_capability_cache ("deviceId","companyId",snapshot,"collectedAt","expiresAt") VALUES ($1,$2,$3,now(),now()+interval \'5 minutes\')',
    [id, user.user.id, snapshot],
  );
  for (const [company, age] of [
    [user.user.id, 0],
    [user.user.id, 40],
    [randomUUID(), 0],
  ])
    await db.query(
      'INSERT INTO device_capability_runs (id,"deviceId","companyId","actorName",status,"startedAt","completedAt") VALUES ($1,$2,$3,$4,$5,now()-$6*interval \'1 day\',now()-$6*interval \'1 day\')',
      [randomUUID(), id, company, "fixture", "collected", age],
    );
  let report = (await call(path)).body;
  assert.ok(report.latest);
  assert.equal(report.companyId, user.user.id);
  assert.equal(report.history.length, 1);
  assert.equal(report.ready, false);
  assert.equal(
    (
      await call(`/devices/${id}`, {
        method: "PUT",
        body: { ...input, type: "cisco", vendor: "cisco" },
      })
    ).status,
    200,
  );
  report = (await call(path)).body;
  assert.equal(report.latest, null);
  assert.equal((await call("/vendors/cisco")).body.devices.items[0].platform, null);
  assert.equal((await call(`/devices/${id}`, { method: "PUT", body: input })).status, 200);
  report = (await call(path)).body;
  assert.equal(report.latest.detection.vendor, "fortigate");
  assert.equal(report.stale, true);
  assert.equal(
    (
      await call(`/devices/${id}`, {
        method: "PUT",
        body: { ...input, type: "linux_edge", vendor: "linux" },
      })
    ).status,
    200,
  );
  assert.equal((await call(path)).status, 400);
  console.log(
    "Capability cache: vendor/type isolation, historical stale snapshot, 30-day read cutoff, company-scoped history and unsupported device rejection passed without network calls.",
  );
} finally {
  if (db && user?.user?.id) await db.getRepository(AppUser).delete(user.user.id);
  if (app) await app.close();
}
