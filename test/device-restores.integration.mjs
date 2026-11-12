import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
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

let failSafety = false,
  failApply = false,
  applyCalls = 0,
  preflightCalls = 0;
let blocked, started;
transport.runSshCommand = async (_device, _credentials, command, options) => {
  if (command.includes("tar -czf")) {
    started?.();
    if (blocked) await blocked;
    return failSafety ? Buffer.from("broken tar") : archive;
  }
  assert.ok(command.includes("SOAR_ETC_RESTORE_V1"));
  assert.ok(command.startsWith("sudo -n python3 -c"));
  assert.equal(options.strictStderr, true);
  const payload = JSON.parse(options.stdin.toString());
  assert.ok(
    payload.entries.every((entry) => entry.path === "etc" || entry.path.startsWith("etc/")),
  );
  if (payload.intent === "preflight") preflightCalls++;
  if (payload.intent === "apply") {
    applyCalls++;
    if (failApply) throw Error("fixture write interrupted");
  }
  return Buffer.from(
    JSON.stringify({
      receiver: "SOAR_ETC_RESTORE_V1",
      intent: payload.intent,
      verified: true,
      entries: payload.entries.length,
    }),
  );
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
const accounts = [];
try {
  await app.listen(0, "127.0.0.1");
  const base = (await app.getUrl()) + "/api/v1";
  const db = app.get(DataSource);
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
        username: "restore_" + randomBytes(8).toString("hex"),
        password: "Restore-Strong-2026!",
        displayName: "کاربر تست بازیابی",
      },
    });
    assert.equal(result.status, 201);
    accounts.push(result.body.user.id);
    await db
      .getRepository(AppUser)
      .update(result.body.user.id, { role, workspaceOwnerId: owner ?? null });
    return { id: result.body.user.id, token: result.body.accessToken };
  }
  const admin = await account("co_admin"),
    other = await account("co_admin"),
    employee = await account("co_employee", admin.id);
  const credential = await call("/devices/credentials", {
    token: admin.token,
    body: {
      name: "restore-fixture",
      operation: "verify",
      username: "fixture",
      password: "fixture-password",
      hostKey: "ssh-ed25519 AAAA",
    },
  });
  assert.equal(credential.status, 201);
  const input = {
    name: "Restore Fixture",
    type: "linux_edge",
    vendor: "linux",
    host: "192.0.2.41",
    managementPort: 22,
    protocol: "ssh",
    environment: "lab",
    tags: [],
    credentialId: credential.body.id,
  };
  const registered = await call("/devices", { token: admin.token, body: input });
  assert.equal(registered.status, 201);
  const id = registered.body.id,
    path = `/devices/${id}`,
    previewPath = path + "/backup-restore-preview",
    jobsPath = path + "/backup-restores";
  const upload = await fetch(base + path + "/backup-upload", {
    method: "POST",
    headers: {
      authorization: "Bearer " + admin.token,
      "content-type": "application/octet-stream",
      "x-backup-filename": "restore.tar.gz",
    },
    body: archive,
  });
  assert.equal(upload.status, 201);
  const artifact = await upload.json();
  const body = { artifactId: artifact.id };
  assert.equal((await call(previewPath, { body })).status, 401);
  assert.equal((await call(previewPath, { token: employee.token, body })).status, 403);
  assert.equal((await call(previewPath, { token: other.token, body })).status, 404);
  assert.equal((await call(jobsPath, { token: other.token })).status, 404);
  const plan = await call(previewPath, { token: admin.token, body });
  assert.equal(plan.status, 201);
  assert.equal(plan.body.connectorInvoked, false);
  assert.equal(applyCalls, 0);
  assert.equal(preflightCalls, 1);
  assert.equal(plan.body.content, undefined);
  assert.equal(plan.body.binding, undefined);
  const confirmation = {
    intent: "execute",
    confirmation: "RESTORE BACKUP",
    fullEtcConfirmation: "RESTORE FULL ETC",
    sha256: plan.body.sha256,
  };
  const executePath = (planId) => jobsPath + "/" + planId + "/execute";
  assert.equal(
    (await call(executePath(plan.body.id), { token: admin.token, body: { intent: "execute" } }))
      .status,
    400,
  );
  assert.equal(
    (
      await call(executePath(plan.body.id), {
        token: admin.token,
        body: { ...confirmation, sha256: "0".repeat(64) },
      })
    ).status,
    409,
  );
  assert.equal(
    (await call(executePath(plan.body.id), { token: employee.token, body: confirmation })).status,
    403,
  );
  await db.getRepository(Device).update(id, { host: "192.0.2.42" });
  assert.equal(
    (await call(executePath(plan.body.id), { token: admin.token, body: confirmation })).status,
    409,
  );
  await db.getRepository(Device).update(id, { host: input.host });
  await db.query(
    `UPDATE "device_restore_plans" SET "expiresAt"=now()-interval '1 minute' WHERE "id"=$1`,
    [plan.body.id],
  );
  assert.equal(
    (await call(executePath(plan.body.id), { token: admin.token, body: confirmation })).status,
    409,
  );
  assert.equal(
    (await call(jobsPath, { token: admin.token })).body.items.find(
      (item) => item.id === plan.body.id,
    ).expired,
    true,
  );
  async function preview() {
    const result = await call(previewPath, { token: admin.token, body });
    assert.equal(result.status, 201);
    return result.body;
  }
  async function waitResult(planId) {
    for (let n = 0; n < 150; n++) {
      const result = (await call(jobsPath, { token: admin.token })).body.items.find(
        (item) => item.id === planId,
      );
      if (result.status !== "running") return result;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw Error("Restore did not finish");
  }
  const editor = db.createQueryRunner();
  await editor.connect();
  await editor.startTransaction();
  try {
    await editor.query('UPDATE "device_credentials" SET "name"=$2 WHERE "id"=$1', [
      credential.body.id,
      "editing fixture",
    ]);
    assert.equal((await call(previewPath, { token: admin.token, body })).status, 409);
  } finally {
    await editor.rollbackTransaction();
    await editor.release();
  }
  await db.getRepository(Device).update(id, { type: "pfsense" });
  assert.equal((await call(previewPath, { token: admin.token, body })).status, 400);
  await db.getRepository(Device).update(id, { type: "linux_edge" });
  const success = await preview();
  let release;
  const transportStarted = new Promise((resolve) => {
    started = resolve;
  });
  blocked = new Promise((resolve) => {
    release = resolve;
  });
  const claims = await Promise.all(
    [1, 2].map(() => call(executePath(success.id), { token: admin.token, body: confirmation })),
  );
  assert.deepEqual(claims.map((r) => r.status).sort(), [202, 409]);
  await transportStarted;
  const running = (await call(jobsPath, { token: admin.token })).body.items.find(
    (item) => item.id === success.id,
  );
  assert.equal(running.state, "taking_safety_backup");
  assert.equal(applyCalls, 0);
  release();
  blocked = undefined;
  started = undefined;
  const result = await waitResult(success.id);
  assert.equal(result.status, "succeeded");
  assert.equal(result.state, "files_verified_activation_required");
  assert.equal(result.connectorInvoked, true);
  assert.ok(result.safetyBackupId);
  assert.equal(applyCalls, 1);
  assert.equal(
    (await call(executePath(success.id), { token: admin.token, body: confirmation })).status,
    409,
  );
  assert.equal(
    (await call(path + "/backups/" + result.safetyBackupId, { token: admin.token })).status,
    200,
  );
  const [audit] = await db.query(
    'SELECT array_agg("action" ORDER BY "id") AS actions FROM "device_restore_events" WHERE "planId"=$1',
    [success.id],
  );
  assert.deepEqual(audit.actions, [
    "preview",
    "confirmed",
    "safety_backup",
    "apply_started",
    "result",
  ]);
  const before = await preview();
  failSafety = true;
  assert.equal(
    (await call(executePath(before.id), { token: admin.token, body: confirmation })).status,
    202,
  );
  const beforeResult = await waitResult(before.id);
  failSafety = false;
  assert.equal(beforeResult.state, "failed_before_apply");
  assert.equal(beforeResult.connectorInvoked, false);
  assert.equal(applyCalls, 1);
  const partial = await preview();
  failApply = true;
  assert.equal(
    (await call(executePath(partial.id), { token: admin.token, body: confirmation })).status,
    202,
  );
  const partialResult = await waitResult(partial.id);
  failApply = false;
  assert.equal(partialResult.state, "needs_review");
  assert.equal(partialResult.connectorInvoked, true);
  assert.ok(partialResult.safetyBackupId);
  assert.equal(applyCalls, 2);
  const changed = await preview();
  const changedStarted = new Promise((resolve) => {
    started = resolve;
  });
  blocked = new Promise((resolve) => {
    release = resolve;
  });
  assert.equal(
    (await call(executePath(changed.id), { token: admin.token, body: confirmation })).status,
    202,
  );
  await changedStarted;
  const changedCredential = await call("/devices/credentials/" + credential.body.id, {
    token: admin.token,
    method: "PUT",
    body: {
      name: "restore-fixture",
      operation: "verify",
      username: "fixture",
      password: "changed-fixture",
      hostKey: "ssh-ed25519 AAAA",
    },
  });
  assert.equal(changedCredential.status, 200);
  release();
  blocked = undefined;
  started = undefined;
  const changedResult = await waitResult(changed.id);
  assert.equal(changedResult.state, "failed_before_apply");
  assert.equal(applyCalls, 2);
  const revoked = await preview();
  const revokeStarted = new Promise((resolve) => {
    started = resolve;
  });
  blocked = new Promise((resolve) => {
    release = resolve;
  });
  assert.equal(
    (await call(executePath(revoked.id), { token: admin.token, body: confirmation })).status,
    202,
  );
  await revokeStarted;
  await db.getRepository(AppUser).update(admin.id, { role: "co_employee" });
  release();
  blocked = undefined;
  started = undefined;
  let revokedResult;
  for (let n = 0; n < 150; n++) {
    [revokedResult] = await db.query(
      'SELECT "state", "status", "connectorInvoked" FROM "device_restore_plans" WHERE "id"=$1',
      [revoked.id],
    );
    if (revokedResult.status !== "running") break;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(revokedResult.state, "failed_before_apply");
  assert.equal(revokedResult.connectorInvoked, false);
  assert.equal(applyCalls, 2);
  await db.getRepository(AppUser).update(admin.id, { role: "co_admin" });
  const corrupted = await preview();
  const [originalArtifact] = await db.query(
    'SELECT "sealedContent" FROM "device_backups" WHERE "id"=$1',
    [artifact.id],
  );
  await db.query('UPDATE "device_backups" SET "sealedContent"=$2 WHERE "id"=$1', [
    artifact.id,
    Buffer.from("corrupt"),
  ]);
  assert.equal(
    (await call(executePath(corrupted.id), { token: admin.token, body: confirmation })).status,
    502,
  );
  await db.query('UPDATE "device_backups" SET "sealedContent"=$2 WHERE "id"=$1', [
    artifact.id,
    originalArtifact.sealedContent,
  ]);
  const transferred = await preview();
  const company = await call("/devices/companies", {
    token: admin.token,
    body: { name: "Restore target" },
  });
  assert.equal(company.status, 201);
  await db.getRepository(Device).update(id, { companyId: company.body.id });
  assert.equal(
    (await call(executePath(transferred.id), { token: admin.token, body: confirmation })).status,
    409,
  );
  await db.getRepository(Device).update(id, { companyId: registered.body.companyId });
  const removed = await preview();
  await call(path + "/backups/" + artifact.id, { token: admin.token, method: "DELETE" });
  assert.equal(
    (await call(executePath(removed.id), { token: admin.token, body: confirmation })).status,
    404,
  );
  assert.equal(applyCalls, 2);
  await db.query(
    `UPDATE "device_restore_plans" SET "status"='running', "state"='applying', "connectorInvoked"=true, "startedAt"=now()-interval '11 minutes', "heartbeatAt"=now()-interval '11 minutes' WHERE "id"=$1`,
    [removed.id],
  );
  assert.equal(
    (await call(jobsPath, { token: admin.token })).body.items.find((item) => item.id === removed.id)
      .interrupted,
    true,
  );
  assert.equal(applyCalls, 2);
  console.log(
    "PASS: controlled Linux restore preview/confirm/safety backup/audit, one-shot claim, stale target/credential/company, interrupted apply and restart reporting",
  );
} finally {
  if (accounts.length) await app.get(DataSource).getRepository(AppUser).delete(accounts);
  await app.close();
  rmSync(fixtureDir, { recursive: true, force: true });
}
