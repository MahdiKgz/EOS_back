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
  { DeviceActionsService } = require("../dist/modules/devices/device-actions.service.js"),
  { fortiVdomActions } = require("../dist/modules/devices/fortigate-vdom.js");
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
        username: "object_" + randomBytes(6).toString("hex"),
        password: "Object-fixture-2026!",
        displayName: "آزمون اشیای FortiGate",
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
      name: "Object SSH",
      operation: "verify",
      username: fixture.username,
      password: fixture.password,
      hostKey: fixture.hostKey,
    },
    credential = await call("/devices/credentials", { ...auth, body: credentialBody });
  assert.equal(credential.status, 201);
  const device = {
      name: "Objects",
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
    created = await call("/devices", { ...auth, body: device });
  assert.equal(created.status, 201);
  const id = created.body.id,
    path = `/devices/${id}/actions`,
    actor = await db.getRepository(AppUser).findOneByOrFail({ id: admin.id }),
    service = app.get(DeviceActionsService);
  const covered = new Set();
  fixture.interfaceRows.port3 = { vdom: "root", ip: "198.51.100.1 255.255.255.0", status: "up" };
  async function plan(body, http = false) {
    if (!http) return service.preview(actor, id, { value: "", ...body });
    const r = await call(path + "/preview", { ...auth, body: { value: "", ...body } });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    return r.body;
  }
  async function apply(body) {
    const p = await plan(body, !covered.has(body.action)),
      result = await call(path + `/${p.id}/execute`, {
        ...auth,
        body: { intent: "execute", confirmed: true },
      });
    assert.equal(result.status, 201);
    assert.equal(result.body.status, "succeeded", JSON.stringify({ body, result: result.body }));
    covered.add(body.action);
    return p;
  }
  const startWrites = fixture.controlWrites.length;
  assert.equal(
    (
      await call(path + "/preview", {
        token: employee.token,
        body: { action: "vdom.create", name: "other", value: "" },
      })
    ).status,
    403,
  );
  assert.equal((await call(path, { token: other.token })).status, 404);
  for (const extra of [{ confirmed: true }, { confirmVdomCreate: { name: "branch" } }])
    assert.equal(
      (
        await call(path + "/preview", {
          ...auth,
          body: { action: "vdom.create", name: "branch", value: "", ...extra },
        })
      ).status,
      400,
    );
  const preview = await plan({ action: "vdom.create", name: "branch", vdom: "must-not-select" });
  assert.equal(preview.vdom, "global");
  assert.equal(fixture.controlWrites.length, startWrites);
  assert.equal(fixture.vdomConfirmations.length, 0);
  assert.ok(preview.commands.includes('edit "branch"'));
  assert.ok(!preview.commands.includes("y"));
  const nativeCreated = await apply({ action: "vdom.create", name: "branch" });
  assert.ok(fixture.controlTables["system vdom"].branch);
  assert.deepEqual(fixture.vdomConfirmations, ["branch"]);
  assert.equal(fixture.controlSystem["system global"]["edit-vdom-prompt"], "enable");
  assert.ok(!fixture.controlWrites.some((c) => c.includes("set edit-vdom-prompt")));
  assert.equal(
    (
      await call(path + `/${nativeCreated.id}/execute`, {
        ...auth,
        body: { intent: "execute", confirmed: true },
      })
    ).status,
    409,
  );
  await apply({
    action: "vdom.update",
    name: "branch",
    vdomShortName: "BR",
    vdomDescription: 'شرکت "نمونه"',
  });
  assert.equal(fixture.controlTables["system vdom"].branch["short-name"], "BR");
  assert.equal(fixture.controlTables["system vdom-property"].branch.description, 'شرکت "نمونه"');
  await apply({ action: "vdom.update", name: "branch", vdomDescription: "توضیح تازه" });
  assert.equal(fixture.controlTables["system vdom"].branch["short-name"], "BR");
  await apply({ action: "vdom.update", name: "branch", vdomShortName: "" });
  assert.equal(fixture.controlTables["system vdom"].branch["short-name"], undefined);
  assert.equal(fixture.controlTables["system vdom-property"].branch.description, "توضیح تازه");
  await apply({ action: "vdom.moveInterface", name: "port3", targetVdom: "branch" });
  assert.equal(fixture.interfaceRows.port3.vdom, "branch");
  assert.ok(!fixture.controlTables["system vdom"].port3);
  const deletion = await plan({ action: "vdom.delete", name: "branch" });
  assert.equal(deletion.checks["رابط‌های منتسب به VDOM"], "1");
  const refused = await service.execute(actor, id, deletion.id, {
    intent: "execute",
    confirmed: true,
  });
  assert.equal(refused.status, "failed");
  assert.ok(fixture.controlTables["system vdom"].branch);
  assert.equal(fixture.interfaceRows.port3.vdom, "branch");
  await apply({ action: "vdom.moveInterface", name: "port3", targetVdom: "root" });
  fixture.interfaceRows["ssl.branch"] = { vdom: "branch", type: "tunnel" };
  await apply({ action: "vdom.delete", name: "branch" });
  assert.equal(fixture.controlTables["system vdom"].branch, undefined);
  assert.equal(fixture.interfaceRows["ssl.branch"], undefined);
  assert.equal(fixture.controlTables["system vdom-property"].branch, undefined);
  assert.deepEqual([...covered].sort(), [...fortiVdomActions].sort());
  const builtIn = await plan({ action: "vdom.update", name: "root", vdomDescription: "ریشه" });
  assert.equal(
    (await service.execute(actor, id, builtIn.id, { intent: "execute", confirmed: true })).status,
    "succeeded",
  );
  for (const body of [
    { action: "vdom.create", name: "root" },
    { action: "vdom.create", name: "x".repeat(32) },
    { action: "vdom.update", name: "absent", vdomShortName: "A" },
    { action: "vdom.update", name: "tenant" },
    { action: "vdom.update", name: "tenant", vdomDescription: "bad\nend" },
    { action: "vdom.update", name: "tenant", vdomShortName: "x".repeat(12) },
    { action: "vdom.moveInterface", name: "absent", targetVdom: "root" },
    { action: "vdom.moveInterface", name: "port3", targetVdom: "absent" },
    { action: "vdom.moveInterface", name: "port3", targetVdom: "root" },
    { action: "vdom.delete", name: "root" },
  ])
    await assert.rejects(plan(body), (e) => e.getStatus?.() === 400);
  fixture.controlSystem["system global"]["management-vdom"] = "tenant";
  await assert.rejects(
    plan({ action: "vdom.delete", name: "tenant" }),
    (e) => e.getStatus?.() === 400,
  );
  fixture.controlSystem["system global"]["management-vdom"] = "root";
  const identity = fixture.outputs["get system status"];
  fixture.outputs["get system status"] = identity.replace(
    /Virtual domain configuration: enable/i,
    "Virtual domain configuration: disable",
  );
  await assert.rejects(
    plan({ action: "vdom.create", name: "disabled" }),
    (e) => e.getStatus?.() === 400,
  );
  fixture.outputs["get system status"] = identity;
  const waiting = await plan({ action: "vdom.create", name: "pending-created" });
  fixture.mode("control-incomplete-readback");
  const pending = await service.execute(actor, id, waiting.id, {
    intent: "execute",
    confirmed: true,
  });
  assert.equal(pending.status, "verification_pending");
  fixture.mode("normal");
  const writes = fixture.controlWrites.length,
    yes = fixture.vdomConfirmations.length;
  assert.equal((await service.verify(actor, id, waiting.id)).status, "succeeded");
  assert.equal(fixture.controlWrites.length, writes);
  assert.equal(fixture.vdomConfirmations.length, yes);
  const stale = await plan({ action: "vdom.update", name: "tenant", vdomShortName: "T" });
  fixture.controlTables["system vdom"].tenant["short-name"] = "external";
  const staleWrites = fixture.controlWrites.length;
  await assert.rejects(
    service.execute(actor, id, stale.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  assert.equal(fixture.controlWrites.length, staleWrites);
  const partial = await plan({
    action: "vdom.update",
    name: "tenant",
    vdomShortName: "partial",
    vdomDescription: "must-not-succeed",
  });
  fixture.mode("vdom-property-failure");
  const partialResult = await service.execute(actor, id, partial.id, {
    intent: "execute",
    confirmed: true,
  });
  assert.equal(partialResult.status, "failed");
  assert.equal(fixture.controlTables["system vdom"].tenant["short-name"], "partial");
  fixture.mode("normal");
  const denied = await plan({ action: "vdom.moveInterface", name: "lan", targetVdom: "tenant" });
  const moved = await service.execute(actor, id, denied.id, { intent: "execute", confirmed: true });
  assert.equal(moved.status, "failed");
  assert.notEqual(fixture.interfaceRows.lan.vdom, "tenant");
  const wrong = await plan({ action: "vdom.create", name: "wrong-question" });
  fixture.mode("vdom-wrong-question");
  const beforeYes = fixture.vdomConfirmations.length;
  assert.equal(
    (await service.execute(actor, id, wrong.id, { intent: "execute", confirmed: true })).status,
    "verification_pending",
  );
  assert.equal(fixture.vdomConfirmations.length, beforeYes);
  assert.equal(fixture.controlTables["system vdom"]["wrong-question"], undefined);
  fixture.mode("normal");
  const repeated = await plan({ action: "vdom.create", name: "repeated" });
  fixture.mode("vdom-repeat-question");
  assert.equal(
    (await service.execute(actor, id, repeated.id, { intent: "execute", confirmed: true })).status,
    "verification_pending",
  );
  assert.equal(fixture.vdomConfirmations.filter((v) => v === "repeated").length, 1);
  fixture.mode("normal");
  fixture.controlSystem["system global"]["edit-vdom-prompt"] = "disable";
  await apply({ action: "vdom.create", name: "without-prompt" });
  assert.ok(!fixture.vdomConfirmations.includes("without-prompt"));
  const refresh = await call(`/devices/${id}/capabilities/refresh`, { ...auth, body: {} });
  assert.equal(refresh.status, 201);
  const report = (await call(`/devices/${id}/capabilities`, auth)).body;
  assert.ok(
    report.latest.collection.tables
      .find((t) => t.key === "vdomProperties")
      .rows.some((r) => r.name === "root" && r.description === "ریشه"),
  );
  assert.ok(
    report.latest.collection.tables
      .find((t) => t.key === "vdoms")
      .rows.some((r) => r.name === "tenant" && r["short-name"] === "partial"),
  );
  const isolated = await plan({ action: "vdom.update", name: "tenant", vdomDescription: "scoped" });
  const company = await call("/devices/companies", { ...auth, body: { name: "VDOM isolated" } });
  await call(`/devices/${id}`, {
    ...auth,
    method: "PUT",
    body: { ...device, companyId: company.body.id },
  });
  await assert.rejects(
    service.execute(actor, id, isolated.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 404,
  );
  assert.deepEqual((await call(path, auth)).body.items, []);
  console.log(
    "Forti VDOM API: four actions via Nest/SSH, exact split native create confirmation once (no global toggle), real short-name/description update+clear/preservation, interface move vs VDOM creation, native dependency failure and built-in interface cleanup, fresh-session readback, pending read-only recovery, no overwrite/replay, stale config, unknown/repeated prompts, partial update failure, disabled mode/root/management checks, inventory and tenant/role/company boundaries passed.",
  );
} finally {
  fixture.release();
  if (db && users.length) await db.getRepository(AppUser).delete(users);
  if (app) await app.close();
  await fixture.close();
}
