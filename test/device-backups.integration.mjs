import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { JwtService } from "@nestjs/jwt";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";

config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const fixtureDir = mkdtempSync(join(tmpdir(), "eos-backup-test-"));
mkdirSync(join(fixtureDir, "etc"));
writeFileSync(join(fixtureDir, "etc", "hostname"), "fixture-host\n");
const archive = execFileSync("tar", ["-czf", "-", "-C", fixtureDir, "etc"]);
const require = createRequire(import.meta.url);
const transport = require("../dist/modules/devices/ssh-transport.js");
let transportResult = archive;
let blockTransport;
let startedTransport;
let permissionRetry = false;
transport.runSshCommand = async (_device, _credentials, command) => {
  if (startedTransport) startedTransport();
  if (blockTransport) await blockTransport;
  if (permissionRetry && !command.includes("sudo -n")) {
    const error = new Error("fixture permission");
    error.stderr = Buffer.from("permission denied");
    throw error;
  }
  assert.ok(command.includes("tar -czf - -C / etc"));
  return transportResult;
};

const { AppModule } = await import("../dist/app.module.js");
const { AppUser } = await import("../dist/modules/users/user.entity.js");
const { Device } = await import("../dist/modules/devices/device.entity.js");
const app = await NestFactory.create(AppModule, { logger: false });
app.useBodyParser("raw", { type: "application/octet-stream", limit: 20 * 1024 * 1024 });
app.setGlobalPrefix("api/v1");
app.useGlobalPipes(
  new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
);
const users = [];
try {
  await app.listen(0, "127.0.0.1");
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
  const db = app.get(DataSource);
  async function account(role, owner) {
    const result = await call("/auth/register", {
      body: {
        username: "backup_" + randomBytes(10).toString("hex"),
        displayName: "کاربر تست بک‌آپ",
        password: "Backup-Strong-2026!",
      },
    });
    assert.equal(result.status, 201);
    users.push(result.body.user.id);
    await db
      .getRepository(AppUser)
      .update(result.body.user.id, { role, workspaceOwnerId: owner ?? null });
    return { id: result.body.user.id, token: result.body.accessToken };
  }
  const admin = await account("co_admin");
  const other = await account("pl_admin");
  const employee = await account("co_employee", admin.id);
  const credential = await call("/devices/credentials", {
    token: admin.token,
    body: {
      name: "Fixture",
      operation: "verify",
      username: "fixture",
      password: "fixture-password",
      hostKey: "ssh-ed25519 AAAA",
    },
  });
  assert.equal(credential.status, 201);
  const input = {
    name: "Backup Fixture",
    type: "linux_edge",
    vendor: "linux",
    host: "192.0.2.40",
    managementPort: 22,
    protocol: "ssh",
    environment: "lab",
    tags: [],
    credentialId: credential.body.id,
  };
  const registered = await call("/devices", { token: admin.token, body: input });
  assert.equal(registered.status, 201);
  const id = registered.body.id;
  const path = `/devices/${id}/backups`;
  assert.equal((await call(path)).status, 401);
  assert.equal((await call(path, { token: employee.token })).status, 403);
  assert.equal((await call(path, { token: other.token })).status, 404);
  assert.equal((await call(path, { token: admin.token })).body.profile.key, "linux");
  permissionRetry = true;
  const first = await call(path, { token: admin.token, method: "POST" });
  permissionRetry = false;
  assert.equal(first.status, 201);
  assert.equal(first.body.byteLength, archive.length);
  assert.equal(first.body.sha256, createHash("sha256").update(archive).digest("hex"));
  assert.equal(first.body.content, undefined);
  const [stored] = await db.query('SELECT "sealedContent" FROM "device_backups" WHERE "id" = $1', [
    first.body.id,
  ]);
  assert.equal(stored.sealedContent.equals(archive), false);
  const filePath = path + "/" + first.body.id;
  assert.equal((await call(filePath, { token: employee.token })).status, 403);
  assert.equal((await call(filePath, { token: other.token })).status, 404);
  const downloaded = await call(filePath, { token: admin.token });
  assert.equal(downloaded.status, 200);
  assert.deepEqual(Buffer.from(downloaded.body.content, "base64"), archive);
  const reviewPath = filePath + "/review";
  assert.equal((await call(reviewPath, { token: employee.token })).status, 403);
  assert.equal((await call(reviewPath, { token: other.token })).status, 404);
  const review = await call(reviewPath, { token: admin.token });
  assert.equal(review.status, 200);
  assert.ok(review.body.files.some((entry) => entry.path === "etc/hostname"));
  assert.equal(review.body.content, undefined);
  assert.equal(review.body.sealedContent, undefined);
  assert.equal(review.body.workspaceOwnerId, undefined);
  assert.ok(review.body.files.every((entry) => entry.content === undefined));
  async function upload(content, token = admin.token, name = "../fixture.tar.gz", deviceId = id) {
    const response = await fetch(base + `/devices/${deviceId}/backup-upload`, {
      method: "POST",
      headers: {
        authorization: "Bearer " + token,
        "content-type": "application/octet-stream",
        "x-backup-filename": encodeURIComponent(name),
      },
      body: content,
    });
    return { status: response.status, body: await response.json() };
  }
  assert.equal((await upload(archive, employee.token)).status, 403);
  assert.equal((await upload(archive, other.token)).status, 404);
  assert.equal((await upload(Buffer.from("incomplete"))).status, 400);
  assert.equal((await upload(Buffer.alloc(0))).status, 400);
  assert.equal((await upload(archive, admin.token, "..")).status, 400);
  assert.equal((await upload(Buffer.alloc(20 * 1024 * 1024 + 1))).status, 413);
  const uploaded = await upload(archive);
  assert.equal(uploaded.status, 201);
  assert.equal(uploaded.body.filename, "fixture.tar.gz");
  assert.equal(uploaded.body.origin, "uploaded");
  assert.equal(uploaded.body.content, undefined);
  const catalogPath = "/devices/backups-catalog";
  assert.equal((await call(catalogPath)).status, 401);
  assert.equal((await call(catalogPath, { token: employee.token })).status, 403);
  assert.equal((await call(catalogPath, { token: other.token })).body.total, 0);
  const catalog = (await call(catalogPath, { token: admin.token })).body;
  assert.equal(catalog.total, 2);
  assert.equal(catalog.deviceCount, 1);
  assert.equal(catalog.items[0].content, undefined);
  assert.equal(catalog.items[0].sealedContent, undefined);
  assert.equal(
    (await call(catalogPath + "?origin=uploaded", { token: admin.token })).body.total,
    1,
  );
  assert.equal(
    (await call(catalogPath + "?search=Backup%20Fixture", { token: admin.token })).body.total,
    2,
  );
  assert.equal((await call(catalogPath + "?search=%25", { token: admin.token })).body.total, 0);
  assert.equal((await call(catalogPath + "?origin=unknown", { token: admin.token })).status, 400);
  assert.equal(
    (await call(catalogPath + "?companyId=unknown", { token: admin.token })).status,
    400,
  );
  assert.equal((await call(catalogPath + "?page=0", { token: admin.token })).status, 400);
  const catalogCompany = await call("/devices/companies", {
    token: admin.token,
    body: { name: "Catalog fixture" },
  });
  assert.equal(catalogCompany.status, 201);
  await db.getRepository(Device).update(id, { companyId: catalogCompany.body.id });
  assert.equal((await call(catalogPath, { token: admin.token })).body.total, 0);
  await db.query('UPDATE "device_backups" SET "companyId" = $1 WHERE "deviceId" = $2', [
    catalogCompany.body.id,
    id,
  ]);
  assert.equal(
    (await call(catalogPath + "?companyId=" + catalogCompany.body.id, { token: admin.token })).body
      .total,
    2,
  );
  assert.equal(
    (await call(catalogPath + "?companyId=" + catalogCompany.body.id, { token: other.token })).body
      .total,
    0,
  );
  await db.getRepository(Device).update(id, { companyId: null });
  await db.query('UPDATE "device_backups" SET "companyId" = NULL WHERE "deviceId" = $1', [id]);
  const uploadedPath = path + "/" + uploaded.body.id;
  assert.equal(
    (await call(uploadedPath + "/review", { token: admin.token })).body.origin,
    "uploaded",
  );
  assert.deepEqual(
    Buffer.from((await call(uploadedPath, { token: admin.token })).body.content, "base64"),
    archive,
  );
  const [uploadedStored] = await db.query(
    'SELECT "sealedContent" FROM "device_backups" WHERE "id" = $1',
    [uploaded.body.id],
  );
  assert.equal(uploadedStored.sealedContent.equals(archive), false);
  assert.equal((await call(path + "?event=uploaded", { token: admin.token })).body.totalEvents, 1);
  await db.query(
    `INSERT INTO "device_backups" ("id", "deviceId", "companyId", "workspaceOwnerId", "filename", "sha256", "byteLength", "sealedContent", "deviceType", "origin")
    SELECT gen_random_uuid(), "deviceId", "companyId", "workspaceOwnerId", 'quota-fixture', "sha256", "byteLength", "sealedContent", "deviceType", 'uploaded' FROM "device_backups", generate_series(1, 99) WHERE "id" = $1`,
    [uploaded.body.id],
  );
  const catalogPage1 = (await call(catalogPath, { token: admin.token })).body;
  const catalogPage2 = (await call(catalogPath + "?page=2", { token: admin.token })).body;
  assert.equal(catalogPage1.total, 101);
  assert.equal(catalogPage1.items.length, 20);
  assert.equal(catalogPage2.items.length, 20);
  assert.equal(Number(catalogPage1.totalBytes), archive.length * 101);
  assert.equal(
    catalogPage1.items.some((a) => catalogPage2.items.some((b) => a.id === b.id)),
    false,
  );
  assert.equal((await upload(archive)).status, 409);
  await db.query(
    `DELETE FROM "device_backups" WHERE "deviceId" = $1 AND "filename" = 'quota-fixture'`,
    [id],
  );
  await db.getRepository(Device).update(id, { type: "cisco" });
  assert.equal((await call(uploadedPath + "/review", { token: admin.token })).status, 409);
  assert.equal((await upload(archive)).status, 400);
  await db.getRepository(Device).update(id, { type: "linux_edge" });
  await call(uploadedPath, { token: admin.token, method: "DELETE" });
  assert.equal((await call(uploadedPath + "/review", { token: admin.token })).status, 404);
  const deviceRepo = db.getRepository(Device);
  await call(`/devices/${id}`, { token: admin.token, method: "DELETE" });
  assert.equal((await call(filePath, { token: admin.token })).status, 404);
  assert.equal((await call(catalogPath, { token: admin.token })).body.total, 0);
  assert.equal(
    (await call(`/devices/${id}/restore`, { token: admin.token, method: "POST" })).status,
    201,
  );
  assert.equal((await call(filePath, { token: admin.token })).status, 200);
  transportResult = Buffer.from("truncated fixture");
  assert.equal((await call(path, { token: admin.token, method: "POST" })).status, 502);
  let listing = (await call(path, { token: admin.token })).body;
  assert.equal(listing.files.length, 1);
  assert.ok(listing.events.some((event) => event.action === "failed"));
  transportResult = archive;
  let release;
  const started = new Promise((resolve) => {
    startedTransport = resolve;
  });
  blockTransport = new Promise((resolve) => {
    release = resolve;
  });
  const pending = call(path, { token: admin.token, method: "POST" });
  await started;
  assert.equal((await call(path, { token: admin.token, method: "POST" })).status, 409);
  release();
  const second = await pending;
  assert.equal(second.status, 201);
  blockTransport = undefined;
  startedTransport = undefined;
  assert.equal((await call(filePath, { token: admin.token, method: "DELETE" })).status, 200);
  assert.equal((await call(filePath, { token: admin.token })).status, 404);
  assert.equal((await call(filePath, { token: admin.token, method: "DELETE" })).status, 404);
  listing = (await call(path, { token: admin.token })).body;
  assert.equal(listing.files.length, 1);
  assert.ok(listing.events.some((event) => event.action === "file_deleted"));
  await db.query('UPDATE "device_backups" SET "sealedContent" = $1 WHERE "id" = $2', [
    Buffer.from("tampered"),
    second.body.id,
  ]);
  assert.equal((await call(path + "/" + second.body.id, { token: admin.token })).status, 502);
  const initialTotal = (await call(path, { token: admin.token })).body.totalEvents;
  await db.query(
    `INSERT INTO "device_backup_events" ("deviceId", "actorName", "action")
     SELECT $1, 'Pagination fixture', 'failed' FROM generate_series(1, 25)`,
    [id],
  );
  const pageOne = (
    await call(path + "?page=1&event=failed&search=Pagination", { token: admin.token })
  ).body;
  const pageTwo = (
    await call(path + "?page=2&event=failed&search=Pagination", { token: admin.token })
  ).body;
  assert.equal(pageOne.totalEvents, 25);
  assert.equal(pageOne.events.length, 20);
  assert.equal(pageTwo.events.length, 5);
  assert.ok(
    pageOne.events.every((event) => !pageTwo.events.some((other) => other.id === event.id)),
  );
  assert.equal((await call(path + "?search=%25", { token: admin.token })).body.totalEvents, 0);
  assert.equal(
    (await call(path + "?search=Pagination&event=created", { token: admin.token })).body
      .totalEvents,
    0,
  );
  assert.equal((await call(path + "?page=0", { token: admin.token })).status, 400);
  assert.equal((await call(path + "?event=invalid", { token: admin.token })).status, 400);
  assert.equal((await call(path, { token: admin.token })).body.totalEvents, initialTotal + 25);
  const previewPath = `/devices/${id}/backup-history-preview`;
  const clearPath = `/devices/${id}/backup-history-clear`;
  assert.equal((await call(previewPath, { token: employee.token, body: {} })).status, 403);
  assert.equal((await call(previewPath, { token: other.token, body: {} })).status, 404);
  const selection = await call(previewPath, {
    token: admin.token,
    body: { search: "Pagination", event: "failed" },
  });
  assert.equal(selection.status, 201);
  assert.equal(selection.body.count, 25);
  const payload = JSON.parse(
    Buffer.from(selection.body.selectionToken.split(".")[1], "base64url").toString(),
  );
  delete payload.exp;
  delete payload.iat;
  const expired = new JwtService({
    secret: createHmac("sha256", process.env.JWT_SECRET)
      .update("backup-history-selection")
      .digest(),
  }).sign(payload, { algorithm: "HS256", expiresIn: -1 });
  assert.equal(
    (await call(clearPath, { token: admin.token, body: { selectionToken: expired } })).status,
    400,
  );

  await db.query(
    `INSERT INTO "device_backup_events" ("deviceId", "actorName", "action") VALUES ($1, 'Pagination newer', 'failed')`,
    [id],
  );
  assert.equal(
    (await call(clearPath, { token: admin.token, body: { selectionToken: "tampered" } })).status,
    400,
  );
  const cleared = await call(clearPath, {
    token: admin.token,
    body: { selectionToken: selection.body.selectionToken },
  });
  assert.equal(cleared.status, 201);
  assert.equal(cleared.body.deleted, 25);
  const remaining = (await call(path + "?search=Pagination&event=failed", { token: admin.token }))
    .body;
  assert.equal(remaining.totalEvents, 1);
  assert.equal((await call(path, { token: admin.token })).body.files.length, 1);
  assert.equal(
    (
      await call(clearPath, {
        token: admin.token,
        body: { selectionToken: selection.body.selectionToken },
      })
    ).body.deleted,
    0,
  );
  const singleSelection = await call(previewPath, {
    token: admin.token,
    body: { eventId: remaining.events[0].id },
  });
  assert.equal(singleSelection.body.count, 1);
  assert.equal(
    (
      await call(clearPath, {
        token: admin.token,
        body: { selectionToken: singleSelection.body.selectionToken },
      })
    ).body.deleted,
    1,
  );
  const [audit] = await db.query(
    `SELECT "id"::text FROM "device_backup_events" WHERE "deviceId" = $1 AND "action" = 'history_cleared' LIMIT 1`,
    [id],
  );
  assert.equal(
    (await call(previewPath, { token: admin.token, body: { eventId: audit.id } })).body.count,
    0,
  );
  const transferSelection = await call(previewPath, { token: admin.token, body: {} });
  assert.ok(transferSelection.body.count > 0);
  const target = await call("/devices/companies", {
    token: admin.token,
    body: { name: "مقصد بک‌آپ" },
  });
  assert.equal(target.status, 201);
  const transferred = await call(`/devices/${id}`, {
    token: admin.token,
    method: "PUT",
    body: { ...input, companyId: target.body.id },
  });
  assert.equal(transferred.status, 200);
  assert.equal(
    (
      await call(clearPath, {
        token: admin.token,
        body: { selectionToken: transferSelection.body.selectionToken },
      })
    ).status,
    409,
  );
  assert.equal((await call(path, { token: admin.token })).body.files.length, 0);
  assert.equal((await call(path + "/" + second.body.id, { token: admin.token })).status, 404);
  const current = await deviceRepo.findOneBy({ id });
  assert.equal(current.credentialId, null);
  console.log(
    "PASS: backup collection, validation, encryption, checksums, scope, archive/restore, concurrent request, deletion and transfer",
  );
} finally {
  if (users.length) await app.get(DataSource).getRepository(AppUser).delete(users);
  await app.close();
  rmSync(fixtureDir, { recursive: true, force: true });
}
