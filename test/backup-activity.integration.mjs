import assert from "node:assert/strict";
import { randomBytes, createHmac } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import "reflect-metadata";
import { config } from "dotenv";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { DataSource } from "typeorm";

config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const directory = mkdtempSync(join(tmpdir(), "eos-activity-test-"));
mkdirSync(join(directory, "etc"));
writeFileSync(join(directory, "etc", "hostname"), "fixture-host\n");
const archive = execFileSync("tar", ["-czf", "-", "-C", directory, "etc"]),
  require = createRequire(import.meta.url);
let failure = false;
require("../dist/modules/devices/ssh-transport.js").runSshCommand = async () => {
  if (failure) throw Error("fixture failure");
  return archive;
};
const { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js"),
  { Device } = require("../dist/modules/devices/device.entity.js");
const app = await NestFactory.create(AppModule, { logger: false });
app.useBodyParser("raw", { type: "application/octet-stream", limit: 20 * 1024 * 1024 });
app.setGlobalPrefix("api/v1");
app.useGlobalPipes(
  new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
);
const users = [];
try {
  await app.listen(0, "127.0.0.1");
  const base = (await app.getUrl()) + "/api/v1",
    db = app.get(DataSource);
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
        username: "activity_" + randomBytes(7).toString("hex"),
        password: "Activity-Strong-2026!",
        displayName: "کاربر تست تاریخچه",
      },
    });
    assert.equal(result.status, 201);
    users.push(result.body.user.id);
    await db
      .getRepository(AppUser)
      .update(result.body.user.id, { role, workspaceOwnerId: owner ?? null });
    return {
      id: result.body.user.id,
      token: result.body.accessToken,
      username: result.body.user.username,
    };
  }
  const admin = await account("co_admin"),
    other = await account("co_admin"),
    employee = await account("co_employee", admin.id);
  const auth = { token: admin.token },
    activityPath = "/devices/backup-activity",
    previewPath = "/devices/backup-activity-preview",
    clearPath = "/devices/backup-activity-clear";
  assert.equal((await call(activityPath)).status, 401);
  assert.equal((await call(activityPath, { token: employee.token })).status, 403);
  assert.equal((await call(activityPath, { token: other.token })).body.total, 0);
  const companyA = (await call("/devices/companies", { ...auth, body: { name: "Audit A" } })).body,
    companyB = (await call("/devices/companies", { ...auth, body: { name: "Audit B" } })).body;
  const credential = await call("/devices/credentials", {
    ...auth,
    body: {
      name: "audit-credential",
      operation: "verify",
      username: "fixture",
      password: "fixture-secret",
      hostKey: "ssh-ed25519 AAAA",
    },
  });
  assert.equal(credential.status, 201);
  const devices = [];
  for (const [index, company] of [companyA, companyB].entries()) {
    const result = await call("/devices", {
      ...auth,
      body: {
        name: index ? "Audit Beta" : "Audit Alpha",
        companyId: company.id,
        credentialId: credential.body.id,
        type: "linux_edge",
        vendor: "linux",
        host: "192.0.2." + (31 + index),
        managementPort: 22,
        protocol: "ssh",
        environment: "lab",
        tags: [],
      },
    });
    assert.equal(result.status, 201);
    devices.push(result.body);
  }
  const [a, b] = devices,
    pathA = `/devices/${a.id}`,
    pathB = `/devices/${b.id}`;
  const first = await call(pathA + "/backups", { ...auth, method: "POST" });
  assert.equal(first.status, 201);
  await call(pathA + "/backups/" + first.body.id, auth);
  const uploaded = await fetch(base + pathB + "/backup-upload", {
    method: "POST",
    headers: {
      authorization: "Bearer " + admin.token,
      "content-type": "application/octet-stream",
      "x-backup-filename": "snapshot-fixture.tar.gz",
    },
    body: archive,
  });
  assert.equal(uploaded.status, 201);
  const file = await uploaded.json();
  await call(pathA + "/backups/" + first.body.id, { ...auth, method: "DELETE" });
  const original = (
    await call(activityPath + "?search=" + encodeURIComponent(first.body.filename), auth)
  ).body;
  assert.equal(original.total, 3);
  assert.ok(
    original.items.every(
      (item) =>
        item.filename === first.body.filename &&
        item.backupId === null &&
        item.sha256 === first.body.sha256 &&
        item.byteLength === archive.length,
    ),
  );
  assert.ok(
    original.items.every(
      (item) =>
        item.deviceName === "Audit Alpha" &&
        item.companyName === "Audit A" &&
        item.actorUsername === admin.username,
    ),
  );
  assert.ok(original.items.find((item) => item.action === "created").durationMs >= 0);
  assert.ok(
    original.items.every((item) => item.content === undefined && item.sealedContent === undefined),
  );
  assert.equal(
    (await call(pathA + "/backups?search=" + encodeURIComponent(first.body.filename), auth)).body
      .totalEvents,
    3,
  );
  await db.getRepository(Device).update(a.id, { name: "Changed Alpha" });
  assert.equal((await call(activityPath + "?search=Audit%20Alpha", auth)).body.total, 3);
  assert.equal((await call(activityPath + "?companyId=" + companyA.id, auth)).body.total, 3);
  assert.equal((await call(activityPath + "?companyId=" + companyB.id, auth)).body.total, 1);
  assert.equal((await call(activityPath + "?companyId=" + other.id, auth)).body.total, 0);
  assert.equal((await call(activityPath + "?page=0", auth)).status, 400);
  assert.equal((await call(activityPath + "?event=invalid", auth)).status, 400);
  assert.equal((await call(activityPath + "?companyId=invalid", auth)).status, 400);
  failure = true;
  assert.equal((await call(pathA + "/backups", { ...auth, method: "POST" })).status, 502);
  failure = false;
  assert.equal(
    (await call(activityPath + "?event=failed&companyId=" + companyA.id, auth)).body.items[0]
      .failureCode,
    "collection_failed",
  );
  await db.getRepository(Device).update(a.id, { credentialId: null });
  assert.equal((await call(pathA + "/backups", { ...auth, method: "POST" })).status, 404);
  assert.equal(
    (await call(activityPath + "?event=failed&companyId=" + companyA.id, auth)).body.items[0]
      .failureCode,
    "credential_unavailable",
  );
  await db.getRepository(Device).update(a.id, { credentialId: credential.body.id });
  await db.query(
    `INSERT INTO "device_backup_events" ("deviceId","actorName","action") VALUES ($1,'Literal 100% event','failed'),($1,'Literal 100x event','failed')`,
    [b.id],
  );
  assert.equal(
    (await call(activityPath + "?search=" + encodeURIComponent("100%"), auth)).body.total,
    1,
  );
  await db.query(
    `INSERT INTO "device_backup_events" ("deviceId","actorName","action") SELECT $1,'Page fixture','failed' FROM generate_series(1,25)`,
    [b.id],
  );
  const pageOne = (await call(activityPath + "?event=failed&search=Page&page=1", auth)).body,
    pageTwo = (await call(activityPath + "?event=failed&search=Page&page=2", auth)).body;
  assert.equal(pageOne.total, 25);
  assert.equal(pageOne.items.length, 20);
  assert.equal(pageTwo.items.length, 5);
  assert.equal(
    pageOne.items.some((a) => pageTwo.items.some((b) => a.id === b.id)),
    false,
  );
  async function preview(body) {
    const result = await call(previewPath, { ...auth, body });
    assert.equal(result.status, 201);
    return result.body;
  }
  async function clear(selectionToken) {
    return call(clearPath, { ...auth, body: { selectionToken } });
  }
  assert.equal((await call(previewPath, { token: employee.token, body: {} })).status, 403);
  assert.equal((await call(previewPath, { token: other.token, body: {} })).body.count, 0);
  const snapshot = await preview({ companyId: companyB.id, event: "failed", search: "Page" });
  assert.equal(snapshot.count, 25);
  await db.query(
    `INSERT INTO "device_backup_events" ("deviceId","actorName","action") VALUES ($1,'Page fixture newer','failed')`,
    [b.id],
  );
  assert.equal((await clear(snapshot.selectionToken)).body.deleted, 25);
  assert.equal((await call(activityPath + "?search=Page", auth)).body.total, 1);
  const [auditsBefore] = await db.query(
    `SELECT COUNT(*)::integer AS count FROM "device_backup_events" WHERE "deviceId"=$1 AND "action"='history_cleared'`,
    [b.id],
  );
  assert.equal((await clear(snapshot.selectionToken)).body.deleted, 0);
  const [auditsAfter] = await db.query(
    `SELECT COUNT(*)::integer AS count FROM "device_backup_events" WHERE "deviceId"=$1 AND "action"='history_cleared'`,
    [b.id],
  );
  assert.equal(auditsAfter.count, auditsBefore.count);
  assert.equal((await call(pathB + "/backups/" + file.id, auth)).status, 200);
  async function lateCommit(scope, label) {
    const writer = db.createQueryRunner();
    await writer.connect();
    await writer.startTransaction();
    try {
      const [late] = await writer.query(
        `INSERT INTO "device_backup_events" ("deviceId","actorName","action") VALUES ($1,$2,'failed') RETURNING "id"::text`,
        [b.id, label],
      );
      const [visible] = await db.query(
        `INSERT INTO "device_backup_events" ("deviceId","actorName","action") VALUES ($1,$2,'failed') RETURNING "id"::text`,
        [b.id, label],
      );
      assert.ok(BigInt(late.id) < BigInt(visible.id));
      const selection =
        scope === "global"
          ? await preview({ search: label })
          : (await call(pathB + "/backup-history-preview", { ...auth, body: { search: label } }))
              .body;
      assert.equal(selection.count, 1);
      await writer.commitTransaction();
      const removed =
        scope === "global"
          ? await clear(selection.selectionToken)
          : await call(pathB + "/backup-history-clear", {
              ...auth,
              body: { selectionToken: selection.selectionToken },
            });
      assert.equal(removed.body.deleted, 1);
      const remaining = (await call(activityPath + "?search=" + encodeURIComponent(label), auth))
        .body;
      assert.equal(remaining.total, 1);
      assert.equal(remaining.items[0].id, late.id);
    } finally {
      if (writer.isTransactionActive) await writer.rollbackTransaction();
      await writer.release();
    }
  }
  await lateCommit("global", "Global late snapshot");
  await lateCommit("device", "Device late snapshot");
  const remaining = (await call(activityPath + "?search=Global%20late%20snapshot", auth)).body
    .items[0];
  const single = await preview({ eventId: remaining.id });
  assert.equal(single.count, 1);
  assert.equal((await clear(single.selectionToken)).body.deleted, 1);
  const [audit] = await db.query(
    `SELECT "id"::text,"deletedCount" FROM "device_backup_events" WHERE "deviceId"=$1 AND "action"='history_cleared' ORDER BY "id" DESC LIMIT 1`,
    [b.id],
  );
  assert.equal(audit.deletedCount, 1);
  assert.equal((await preview({ eventId: audit.id })).count, 0);
  const global = await preview({ event: "uploaded" }),
    local = (
      await call(pathB + "/backup-history-preview", { ...auth, body: { event: "uploaded" } })
    ).body;
  assert.equal((await clear(local.selectionToken)).status, 400);
  assert.equal(
    (
      await call(pathB + "/backup-history-clear", {
        ...auth,
        body: { selectionToken: global.selectionToken },
      })
    ).status,
    400,
  );
  assert.equal(
    (await call(clearPath, { token: other.token, body: { selectionToken: global.selectionToken } }))
      .status,
    400,
  );
  assert.equal(
    (
      await call(clearPath, {
        token: employee.token,
        body: { selectionToken: global.selectionToken },
      })
    ).status,
    403,
  );
  assert.equal((await clear("tampered")).status, 400);
  const payload = JSON.parse(
    Buffer.from(global.selectionToken.split(".")[1], "base64url").toString(),
  );
  delete payload.exp;
  delete payload.iat;
  const expired = new JwtService({
    secret: createHmac("sha256", process.env.JWT_SECRET)
      .update("backup-global-history-selection")
      .digest(),
  }).sign(payload, { algorithm: "HS256", expiresIn: -1 });
  assert.equal((await clear(expired)).status, 400);
  await db.query(
    `UPDATE "backup_activity_selections" SET "expiresAt"=clock_timestamp()-interval '1 second' WHERE "id"=$1`,
    [payload.id],
  );
  assert.equal((await clear(global.selectionToken)).status, 400);
  const all = await preview({});
  const [beforeAtomic] = await db.query(
    'SELECT COUNT(*)::integer AS count FROM "device_backup_events" WHERE "deviceId" = ANY($1)',
    [[a.id, b.id]],
  );
  await db.getRepository(Device).update(a.id, { name: "Atomic stale device" });
  assert.equal((await clear(all.selectionToken)).status, 409);
  const [afterAtomic] = await db.query(
    'SELECT COUNT(*)::integer AS count FROM "device_backup_events" WHERE "deviceId" = ANY($1)',
    [[a.id, b.id]],
  );
  assert.equal(afterAtomic.count, beforeAtomic.count);
  await db.getRepository(Device).update(a.id, { name: "Changed Alpha" });
  const rename = await preview({ companyId: companyA.id });
  await db.getRepository(Device).update(a.id, { name: "Renamed after preview" });
  assert.equal((await clear(rename.selectionToken)).status, 409);
  await db.getRepository(Device).update(a.id, { name: "Changed Alpha" });
  const archived = await preview({ companyId: companyA.id });
  await call(pathA, { ...auth, method: "DELETE" });
  assert.equal((await clear(archived.selectionToken)).status, 409);
  assert.equal((await call(activityPath + "?companyId=" + companyA.id, auth)).body.total, 0);
  await call(pathA + "/restore", { ...auth, method: "POST" });
  const moved = await preview({ companyId: companyA.id });
  await db.getRepository(Device).update(a.id, { companyId: companyB.id });
  assert.equal((await clear(moved.selectionToken)).status, 409);
  await db.getRepository(Device).update(a.id, { companyId: companyA.id });
  assert.equal((await call(pathB + "/backups/" + file.id, auth)).status, 200);
  console.log(
    "PASS: global backup audit scope/filters/pagination/snapshots, metadata after deletion/rename, atomic signed cleanup, late-commit retention in both scopes, replay and stale-device rejection",
  );
} finally {
  if (users.length) await app.get(DataSource).getRepository(AppUser).delete(users);
  await app.close();
  rmSync(directory, { recursive: true, force: true });
}
