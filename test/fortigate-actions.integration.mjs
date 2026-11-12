import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
import { fortigateSshFixture } from "./fixtures/fortigate-ssh-server.mjs";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js"),
  { DeviceActionsService } = require("../dist/modules/devices/device-actions.service.js");
const fixture = await fortigateSshFixture({ control: true }),
  users = [];
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
        username: "action_" + randomBytes(6).toString("hex"),
        password: "Actions-fixture-2026!",
        displayName: "آزمون کنترل رابط",
      },
    });
    assert.equal(r.status, 201);
    users.push(r.body.user.id);
    await db
      .getRepository(AppUser)
      .update(r.body.user.id, { role, workspaceOwnerId: owner ?? null });
    return { id: r.body.user.id, token: r.body.accessToken };
  }
  const admin = await account("co_admin"),
    employee = await account("co_employee", admin.id),
    other = await account("co_admin"),
    auth = { token: admin.token };
  await call("/devices/companies", auth);
  const credentialBody = {
      name: "Control SSH",
      operation: "verify",
      username: fixture.username,
      password: fixture.password,
      hostKey: fixture.hostKey,
    },
    credential = await call("/devices/credentials", { ...auth, body: credentialBody });
  assert.equal(credential.status, 201);
  const input = {
      name: "Forti control",
      type: "fortigate",
      vendor: "fortinet",
      host: fixture.host,
      managementPort: fixture.port,
      protocol: "ssh",
      environment: "lab",
      tags: [],
      companyId: admin.id,
      credentialId: credential.body.id,
    },
    created = await call("/devices", { ...auth, body: input });
  assert.equal(created.status, 201);
  const id = created.body.id,
    path = `/devices/${id}/actions`,
    alias = { action: "interface.alias", name: "lan", value: "Office Updated", vdom: "root" },
    actor = await db.getRepository(AppUser).findOneByOrFail({ id: admin.id }),
    service = app.get(DeviceActionsService);
  assert.equal((await call(path)).status, 401);
  assert.equal((await call(path, { token: employee.token })).status, 200);
  assert.equal((await call(path + "/preview", { token: employee.token, body: alias })).status, 403);
  assert.equal((await call(path, { token: other.token })).status, 404);
  await db.query(
    `INSERT INTO device_capability_cache("deviceId","companyId",binding,"leaseToken","leaseExpiresAt") VALUES ($1,$2,'old-binding','old-lease',now()+interval '1 minute')`,
    [id, admin.id],
  );
  await db.query(
    `INSERT INTO device_monitoring("deviceId","actorId",enabled,revision,"leaseToken","leaseExpiresAt") VALUES ($1,$2,true,'old-revision','old-lease',now()+interval '1 minute')`,
    [id, admin.id],
  );
  let preview = await call(path + "/preview", { ...auth, body: alias });
  assert.equal(preview.status, 201, JSON.stringify(preview.body));
  assert.equal(fixture.controlWrites.length, 0);
  assert.equal(preview.body.before.alias, "Office");
  assert.equal(preview.body.after.alias, "Office Updated");
  assert.equal(
    (
      await call(path + `/${preview.body.id}/execute`, {
        ...auth,
        body: { confirmed: false, intent: "execute" },
      })
    ).status,
    400,
  );
  let executed = await call(path + `/${preview.body.id}/execute`, {
    ...auth,
    body: { confirmed: true, intent: "execute" },
  });
  assert.equal(executed.status, 201);
  assert.equal(executed.body.status, "succeeded", JSON.stringify(executed.body));
  assert.equal(fixture.interfaceRows.lan.alias, "Office Updated");
  assert.equal(executed.body.verified, true);
  const [cacheAfter] = await db.query(
    `SELECT binding,"leaseToken" FROM device_capability_cache WHERE "deviceId"=$1`,
    [id],
  );
  assert.equal(cacheAfter.binding, null);
  assert.equal(cacheAfter.leaseToken, null);
  const [monitorAfter] = await db.query(
    `SELECT enabled,revision,"leaseToken" FROM device_monitoring WHERE "deviceId"=$1`,
    [id],
  );
  assert.equal(monitorAfter.enabled, false);
  assert.notEqual(monitorAfter.revision, "old-revision");
  assert.equal(monitorAfter.leaseToken, null);

  const sent = fixture.controlWrites.length;
  assert.equal(
    (
      await call(path + `/${preview.body.id}/execute`, {
        ...auth,
        body: { confirmed: true, intent: "execute" },
      })
    ).status,
    409,
  );
  assert.equal(fixture.controlWrites.length, sent);
  async function apply(body) {
    const p = await service.preview(actor, id, body);
    return service.execute(actor, id, p.id, { intent: "execute", confirmed: true });
  }
  assert.equal(
    (await apply({ action: "interface.role", name: "lan", value: "dmz", vdom: "root" })).status,
    "succeeded",
  );
  assert.equal(fixture.interfaceRows.lan.role, "dmz");
  const allowed = await call(`/devices/${id}/actions/preview`, {
    ...auth,
    body: { action: "interface.allowaccess", name: "lan", value: "https,ssh,ping", vdom: "root" },
  });
  assert.equal(allowed.status, 201, JSON.stringify(allowed.body));
  const access = await call(`/devices/${id}/actions/${allowed.body.id}/execute`, {
    ...auth,
    body: { intent: "execute", confirmed: true },
  });
  assert.equal(access.body.status, "succeeded");
  assert.equal(fixture.interfaceRows.lan.allowaccess, "https ssh ping");
  assert.equal(
    (await apply({ action: "interface.allowaccess", name: "lan", value: "", vdom: "root" })).status,
    "succeeded",
  );
  assert.equal(fixture.interfaceRows.lan.allowaccess, undefined);
  await assert.rejects(
    service.preview(actor, id, {
      action: "interface.allowaccess",
      name: "lan",
      value: "ssh;execute reboot",
    }),
    (e) => e.getStatus?.() === 400,
  );
  assert.equal(
    (await apply({ action: "interface.state", name: "lan", value: "down", vdom: "root" })).status,
    "succeeded",
  );
  assert.equal(fixture.interfaceRows.lan.status, "down");
  assert.equal(
    (await apply({ action: "interface.ip", name: "lan", value: "192.0.2.129/25", vdom: "root" }))
      .status,
    "succeeded",
  );
  assert.equal(fixture.interfaceRows.lan.ip, "192.0.2.129 255.255.255.128");
  assert.equal(
    (
      await apply({
        action: "interface.vlan",
        name: "vlan10",
        value: "198.51.100.1/24",
        vdom: "root",
        parent: "lan",
        vlanId: "10",
      })
    ).status,
    "succeeded",
  );
  assert.equal(fixture.interfaceRows.vlan10.vlanid, "10");
  assert.equal(fixture.interfaceRows.vlan10.alias, "firewall-log-analyzer managed vlan interface");
  await assert.rejects(
    service.preview(actor, id, {
      action: "interface.vlan",
      name: "vlan10",
      value: "198.51.100.1/24",
      vdom: "root",
      parent: "lan",
      vlanId: "10",
    }),
    (e) => e.getStatus?.() === 400,
  );
  const archived = await service.preview(actor, id, alias);
  await call(`/devices/${id}`, { ...auth, method: "DELETE" });
  await call(`/devices/${id}/restore`, { ...auth, body: {} });
  await assert.rejects(
    service.execute(actor, id, archived.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  const roleChanged = await service.preview(actor, id, alias);
  await db.getRepository(AppUser).update(admin.id, { role: "co_employee" });
  await assert.rejects(
    service.execute(actor, id, roleChanged.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 403,
  );
  await db.getRepository(AppUser).update(admin.id, { role: "co_admin" });
  await assert.rejects(
    service.execute(actor, id, roleChanged.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  const simultaneous = await service.preview(actor, id, { ...alias, value: "Concurrent" });
  const outcomes = await Promise.allSettled([
    service.execute(actor, id, simultaneous.id, { intent: "execute", confirmed: true }),
    service.execute(actor, id, simultaneous.id, { intent: "execute", confirmed: true }),
  ]);
  assert.equal(
    outcomes.filter((o) => o.status === "fulfilled" && o.value.status === "succeeded").length,
    1,
  );
  assert.equal(
    outcomes.filter((o) => o.status === "rejected" && o.reason.getStatus?.() === 409).length,
    1,
  );
  const originalStatus = fixture.outputs["get system status"];
  fixture.outputs["get system status"] = originalStatus
    .replace("Virtual domain configuration: enable", "Virtual domain configuration: disable")
    .replace(/Current virtual domain: root\n/, "");
  const disabledMode = await service.preview(actor, id, alias);
  assert.ok(disabledMode.id);
  fixture.outputs["get system status"] = originalStatus;
  const stale = await service.preview(actor, id, alias);
  fixture.interfaceRows.lan.alias = "Externally changed";
  await assert.rejects(
    service.execute(actor, id, stale.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  const changed = await service.preview(actor, id, alias);
  await call(`/devices/credentials/${credential.body.id}`, {
    ...auth,
    method: "PUT",
    body: credentialBody,
  });
  await assert.rejects(
    service.execute(actor, id, changed.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  const unknownVDOM = fixture.controlWrites.length;
  await assert.rejects(
    service.preview(actor, id, { ...alias, vdom: "does-not-exist" }),
    (e) => e.getStatus?.() === 400,
  );
  assert.equal(fixture.controlWrites.length, unknownVDOM);
  const malformed = await call(path + "/preview", {
    ...auth,
    body: { ...alias, value: 'bad"\nset status down' },
  });
  assert.equal(malformed.status, 400);
  assert.equal(
    (await call(path + "/preview", { ...auth, body: { ...alias, command: "reboot" } })).status,
    400,
  );
  const badExpiry = await service.preview(actor, id, alias);
  await db.query(
    "UPDATE device_action_plans SET \"expiresAt\"=now()-interval '1 minute' WHERE id=$1",
    [badExpiry.id],
  );
  await assert.rejects(
    service.execute(actor, id, badExpiry.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  fixture.mode("control-mismatch");
  assert.equal((await apply(alias)).status, "verification_failed");
  fixture.mode("control-failure");
  assert.equal((await apply(alias)).status, "failed");
  fixture.mode("control-disconnect");
  const pendingResult = await apply(alias);
  assert.equal(pendingResult.status, "verification_pending");
  fixture.mode("normal");
  const writesBeforeVerify = fixture.controlWrites.length;
  const pendingHistory = (await call(path, auth)).body.items.find(
    (item) => item.id === pendingResult.id,
  );
  assert.equal(pendingHistory.canVerify, true);
  assert.ok(pendingHistory.actorName);
  assert.equal(pendingHistory.targetName, "lan");
  assert.equal(pendingHistory.vdom, "root");
  assert.equal(
    (await call(path + `/${pendingResult.id}/verify`, { token: employee.token, body: {} })).status,
    403,
  );
  const checked = await call(path + `/${pendingResult.id}/verify`, { ...auth, body: {} });
  assert.equal(checked.status, 201);
  const verifiedPending = checked.body;
  assert.equal(verifiedPending.status, "succeeded");
  assert.equal(verifiedPending.verified, true);
  assert.equal(fixture.controlWrites.length, writesBeforeVerify);

  const transferred = await service.preview(actor, id, alias),
    company = await call("/devices/companies", { ...auth, body: { name: "Control company" } });
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
  await assert.rejects(
    service.execute(actor, id, transferred.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 404,
  );
  assert.deepEqual((await call(path, auth)).body.items, []);
  const history = await db.query('SELECT action FROM device_action_events WHERE "deviceId"=$1', [
    id,
  ]);
  assert.ok(history.some((e) => e.action === "succeeded"));
  assert.ok(history.some((e) => e.action === "failed"));
  const plans = await db.query('SELECT preview FROM device_action_plans WHERE "deviceId"=$1', [id]);
  assert.ok(!JSON.stringify(plans).includes(fixture.password));
  console.log(
    "FortiGate interface actions: actual SSH2 PTY, read-only preview, single confirm, alias/role/state/IP/VLAN, readback, no replay, stale config/credential/expiry/company guards, tenant/role validation, failed/mismatch/disconnect outcomes and audit passed.",
  );
} finally {
  fixture.release();
  if (db && users.length) await db.getRepository(AppUser).delete(users);
  if (app) await app.close();
  await fixture.close();
}
