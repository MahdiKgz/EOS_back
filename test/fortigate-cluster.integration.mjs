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
  {
    fortiClusterActions,
    parseFortiSdwan,
  } = require("../dist/modules/devices/fortigate-cluster.js");
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
    service = app.get(DeviceActionsService),
    common = { vdom: "root" };
  const covered = new Set();
  async function plan(body, http = false) {
    if (!http) return service.preview(actor, id, { ...common, value: "", ...body });
    const r = await call(path + "/preview", { ...auth, body: { ...common, value: "", ...body } });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    return r.body;
  }
  async function apply(body) {
    const p = await plan(body, !covered.has(body.action)),
      r = await call(path + `/${p.id}/execute`, {
        ...auth,
        body: { intent: "execute", confirmed: true },
      });
    assert.equal(r.status, 201);
    assert.equal(
      r.body.status,
      "succeeded",
      JSON.stringify({ action: body.action, result: r.body }),
    );
    covered.add(body.action);
    return { p, r: r.body };
  }
  const initialWrites = fixture.controlWrites.length;
  assert.equal(
    (
      await call(path + "/preview", {
        token: employee.token,
        body: { action: "ha.priority", name: "system", value: "", haPriority: "200" },
      })
    ).status,
    403,
  );
  assert.equal((await call(path, { token: other.token })).status, 404);
  const ha = await plan({
    action: "ha.configure",
    name: "system",
    haMode: "a-p",
    haGroup: "آزمایش HA",
  });
  assert.equal(fixture.controlWrites.length, initialWrites);
  assert.equal(ha.vdom, "global");
  assert.ok(ha.commands.includes("config global"));
  assert.ok(ha.checks["حالت فعلی HA"] === "standalone");
  assert.equal(ha.before.mode, "standalone");
  assert.ok(!JSON.stringify(ha).includes("ENC fixture-ha-secret"));
  const configured = await apply({
    action: "ha.configure",
    name: "system",
    haMode: "a-p",
    haGroup: "آزمایش HA",
  });
  assert.equal(fixture.controlSystem["system ha"].hbdev, "ha1 50 ha2 100");
  assert.equal(fixture.controlSystem["system ha"].password, "ENC fixture-ha-secret");
  assert.equal(configured.r.targetId, undefined);
  await apply({ action: "ha.priority", name: "system", haPriority: "255" });
  assert.equal(fixture.controlSystem["system ha"].priority, "255");
  await apply({ action: "ha.priority", name: "system", haPriority: "0" });
  assert.equal(fixture.controlSystem["system ha"].priority, "0");
  const zone = await apply({ action: "sdwanZone.create", name: "branch" });
  assert.ok(zone.p.message.includes("غیرفعال"));
  assert.equal(fixture.sdwan.status, "disable");
  assert.equal(fixture.controlTables["system vdom"].branch, undefined);
  fixture.interfaceRows.lan.vdom = "tenant";
  await assert.rejects(
    plan({
      action: "sdwanMember.create",
      name: "auto-member",
      dstInterface: "lan",
      sdwanZone: "branch",
    }),
    (e) => e.getStatus?.() === 400,
  );
  delete fixture.interfaceRows.lan.vdom;
  const member = await apply({
    action: "sdwanMember.create",
    name: "auto-member",
    dstInterface: "lan",
    sdwanZone: "branch",
    gateway: "192.0.2.254",
  });
  assert.equal(member.r.targetId, "300");
  assert.ok(member.p.commands.includes("edit 0"));
  assert.equal(fixture.sdwan.sections.members["300"].zone, "branch");
  const health = await apply({
    action: "sdwanHealth.create",
    name: "Ping-ISP",
    probeServer: "probe.example.com",
    sdwanMembers: "1, 300",
  });
  assert.equal(fixture.sdwan.sections["health-check"]["Ping-ISP"].members, "1 300");
  assert.equal(health.p.after.protocol, "ping");
  const rule = await apply({
    action: "sdwanRule.create",
    name: "BranchRule",
    sdwanMembers: "300,1",
    srcAddresses: "employees",
    dstAddresses: "office",
  });
  assert.equal(rule.r.targetId, "301");
  assert.equal(fixture.sdwan.sections.service["301"].name, "BranchRule");
  assert.equal(fixture.sdwan.sections.service["301"]["priority-members"], "300 1");
  assert.equal(fixture.sdwan.status, "disable");
  const refreshed = await call(`/devices/${id}/capabilities/refresh`, { ...auth, body: {} });
  assert.equal(refreshed.status, 201);
  const report = await call(`/devices/${id}/capabilities`, auth);
  const sdwanTables = report.body.latest.collection.tables.filter((t) =>
    ["sdwanZones", "sdwanMembers", "sdwanHealth", "sdwanRules"].includes(t.key),
  );
  assert.equal(sdwanTables.length, 4);
  assert.ok(sdwanTables.every((t) => t.state === "collected"));
  assert.equal(
    sdwanTables.find((t) => t.key === "sdwanMembers").rows.find((r) => r.id === "300").interface,
    "lan",
  );
  assert.equal(
    sdwanTables.find((t) => t.key === "sdwanHealth").rows[0].server,
    "probe.example.com",
  );
  assert.equal(
    sdwanTables.find((t) => t.key === "sdwanRules").rows[0]["priority-members"],
    "300, 1",
  );
  assert.equal(sdwanTables.find((t) => t.key === "sdwanRules").rows[0].name, "BranchRule");
  assert.ok(!JSON.stringify(sdwanTables).includes("__section"));
  assert.ok(!JSON.stringify(sdwanTables).includes("invocation="));
  assert.deepEqual([...covered].sort(), [...fortiClusterActions].sort());
  assert.equal(
    (
      await call(path + `/${rule.p.id}/execute`, {
        ...auth,
        body: { intent: "execute", confirmed: true },
      })
    ).status,
    409,
  );
  for (const body of [
    { action: "ha.priority", name: "system", haPriority: "256" },
    { action: "ha.configure", name: "system", haMode: "fake", haGroup: "x" },
    { action: "ha.configure", name: "system", haMode: "a-a", haGroup: "x\nend" },
    { action: "sdwanZone.create", name: "branch" },
    { action: "sdwanMember.create", name: "auto-member", dstInterface: "absent" },
    { action: "sdwanMember.create", name: "auto-member", dstInterface: "wan1" },
    { action: "sdwanHealth.create", name: "Ping-ISP", probeServer: "192.0.2.1" },
    { action: "sdwanHealth.create", name: "bad-host", probeServer: "bad..host" },
    { action: "sdwanHealth.create", name: "bad-ip", probeServer: "999.1.1.1" },
    {
      action: "sdwanHealth.create",
      name: "bad-members",
      probeServer: "192.0.2.1",
      sdwanMembers: "00,1",
    },
    { action: "sdwanRule.create", name: "no-member", sdwanMembers: "999" },
    {
      action: "sdwanRule.create",
      name: "bad-reference",
      sdwanMembers: "1",
      dstAddresses: "absent",
    },
    {
      action: "sdwanRule.create",
      name: "raw-cidr",
      sdwanMembers: "1",
      srcAddresses: "192.0.2.0/24",
    },
  ])
    await assert.rejects(plan(body), (e) => e.getStatus?.() === 400);
  fixture.mode("ha-status-partial");
  await assert.rejects(
    plan({ action: "ha.priority", name: "system", haPriority: "200" }),
    (e) => e.getStatus?.() === 400,
  );
  fixture.mode("normal");
  fixture.mode("nested-missing-next");
  await assert.rejects(
    plan({ action: "sdwanZone.create", name: "bad-structure" }),
    (e) => e.getStatus?.() === 400,
  );
  fixture.mode("normal");
  const stale = await plan({ action: "sdwanRule.create", name: "stale-rule", sdwanMembers: "1" });
  fixture.sdwan.sections.members["1"].status = "disable";
  const writes = fixture.controlWrites.length;
  await assert.rejects(
    service.execute(actor, id, stale.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  assert.equal(fixture.controlWrites.length, writes);
  fixture.sdwan.sections.members["1"].status = "enable";
  const pendingPlan = await plan({
    action: "ha.configure",
    name: "system",
    haMode: "a-a",
    haGroup: "Same cluster",
  });
  fixture.mode("ha-status-after-write");
  const pending = await service.execute(actor, id, pendingPlan.id, {
    intent: "execute",
    confirmed: true,
  });
  assert.equal(pending.status, "verification_pending");
  fixture.mode("normal");
  const attempts = fixture.controlWrites.length;
  assert.equal((await service.verify(actor, id, pendingPlan.id)).status, "succeeded");
  assert.equal(fixture.controlWrites.length, attempts);
  const pendingRule = await plan({
    action: "sdwanRule.create",
    name: "pending-rule",
    sdwanMembers: "1,300",
  });
  fixture.mode("control-incomplete-readback");
  assert.equal(
    (await service.execute(actor, id, pendingRule.id, { intent: "execute", confirmed: true }))
      .status,
    "verification_pending",
  );
  fixture.mode("normal");
  const readOnlyWrites = fixture.controlWrites.length;
  const recovered = await service.verify(actor, id, pendingRule.id);
  assert.equal(recovered.status, "succeeded");
  assert.ok(recovered.targetId);
  assert.equal(fixture.controlWrites.length, readOnlyWrites);
  const mismatch = await plan({ action: "ha.priority", name: "system", haPriority: "222" });
  fixture.mode("control-mismatch");
  assert.equal(
    (await service.execute(actor, id, mismatch.id, { intent: "execute", confirmed: true })).status,
    "verification_failed",
  );
  fixture.mode("normal");
  // A nested SLA block must never overwrite its parent health-check fields or become a member.
  const nested =
    'config system sdwan\nset status enable\nconfig health-check\nedit "parent"\nset server "192.0.2.1"\nconfig sla\nedit 1\nset server "wrong-child"\nnext\nend\nnext\nend\nend';
  const parsed = parseFortiSdwan(nested);
  assert.equal(parsed.filter((r) => r.settings.__section?.[0] === "health-check").length, 1);
  assert.deepEqual(parsed.find((r) => r.name === "parent").settings.server, ["192.0.2.1"]);
  const transferred = await plan({ action: "ha.priority", name: "system", haPriority: "201" });
  const company = await call("/devices/companies", { ...auth, body: { name: "Cluster isolated" } });
  await call(`/devices/${id}`, {
    ...auth,
    method: "PUT",
    body: { ...device, companyId: company.body.id },
  });
  await assert.rejects(
    service.execute(actor, id, transferred.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 404,
  );
  assert.deepEqual((await call(path, auth)).body.items, []);
  console.log(
    "Forti cluster API: 6 actions via HTTP/SSH, HA precheck/global mode/priority and preserved heartbeat/password, nested SD-WAN zones/members/health/manual-rule auto IDs and ordered priorities, no overwrite, existing references, four safe inventory tables, disabled mode retained, nested/incomplete rejection, freshness/no replay, pending read-only recovery and tenant/role/company boundaries passed.",
  );
} finally {
  fixture.release();
  if (db && users.length) await db.getRepository(AppUser).delete(users);
  if (app) await app.close();
  await fixture.close();
}
