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
  { fortiPolicyActions } = require("../dist/modules/devices/fortigate-policy.js");
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
  async function preview(body) {
    return service.preview(actor, id, { ...common, value: "", ...body });
  }
  const basePolicy = {
    action: "policy.create",
    name: "general",
    srcInterface: "lan",
    dstInterface: "wan1",
    value: "توضیح شبکه",
  };
  const initialWrites = fixture.controlWrites.length;
  assert.equal(
    (
      await call(path + "/preview", {
        token: employee.token,
        body: { ...basePolicy, vdom: "root" },
      })
    ).status,
    403,
  );
  assert.equal((await call(path, { token: other.token })).status, 404);
  assert.equal(
    (
      await call(path + "/preview", {
        ...auth,
        body: { ...basePolicy, vdom: "root", executionTag: "forged" },
      })
    ).status,
    400,
  );
  const first = await call(path + "/preview", { ...auth, body: { ...basePolicy, vdom: "root" } });
  assert.equal(first.status, 201, JSON.stringify(first.body));
  assert.equal(fixture.controlWrites.length, initialWrites);
  assert.ok(first.body.commands.includes("edit 0"));
  assert.ok(first.body.after.comments.includes(first.body.id));
  const firstRun = await call(path + `/${first.body.id}/execute`, {
    ...auth,
    body: { intent: "execute", confirmed: true },
  });
  assert.equal(firstRun.body.status, "succeeded");
  assert.equal(firstRun.body.targetId, "1000");
  assert.equal(fixture.controlTables["firewall policy"]["1000"].status, "disable");
  assert.equal(fixture.controlTables["firewall policy"]["1000"].nat, "disable");
  assert.equal((await call(path, auth)).body.items[0].targetId, "1000");
  assert.equal(
    (
      await call(path + `/${first.body.id}/execute`, {
        ...auth,
        body: { intent: "execute", confirmed: true },
      })
    ).status,
    409,
  );
  const actions = new Set([basePolicy.action]);
  async function apply(input) {
    const p = await preview(input),
      result = await service.execute(actor, id, p.id, { intent: "execute", confirmed: true });
    assert.equal(result.status, "succeeded", JSON.stringify({ input, result }));
    actions.add(input.action);
    return {
      preview: p,
      result,
      row: result.targetId ? fixture.controlTables["firewall policy"][result.targetId] : undefined,
    };
  }
  const internet = await apply({
    ...basePolicy,
    action: "policy.egress",
    name: "internet",
    value: "",
    sourceCidr: "192.0.2.0/24",
  });
  assert.equal(internet.row.nat, "enable");
  assert.equal(internet.row.status, "disable");
  const sourceName = internet.preview.after.__sourceName;
  assert.equal(
    fixture.controlTables["firewall address"][sourceName].subnet,
    "192.0.2.0 255.255.255.0",
  );
  const reused = await preview({ ...basePolicy, name: "source-reuse", sourceCidr: "192.0.2.0/24" });
  assert.ok(!reused.commands.includes("config firewall address"));
  fixture.controlTables["firewall address"][sourceName].subnet = "198.51.100.0 255.255.255.0";
  await assert.rejects(
    preview({ ...basePolicy, name: "collision", sourceCidr: "192.0.2.0/24" }),
    (e) => e.getStatus?.() === 400,
  );
  fixture.controlTables["firewall address"][sourceName].subnet = "192.0.2.0 255.255.255.0";
  await assert.rejects(
    preview({ ...basePolicy, name: "both", sourceCidr: "192.0.2.0/24", srcAddresses: "office" }),
    (e) => e.getStatus?.() === 400,
  );
  const deny = await apply({ ...basePolicy, action: "policy.deny", name: "deny", value: "" });
  assert.equal(deny.row.action, "deny");
  fixture.controlTables["firewall vip"].publicWeb = {
    extip: "198.51.100.8",
    mappedip: "192.0.2.8",
  };
  const dnat = await apply({
    ...basePolicy,
    action: "policy.dnat",
    name: "inbound",
    srcInterface: "wan1",
    dstInterface: "lan",
    dstAddresses: "publicWeb",
    value: "",
  });
  assert.equal(dnat.row.dstaddr, "publicWeb");
  await assert.rejects(
    preview({ ...basePolicy, action: "policy.dnat", name: "not-vip", dstAddresses: "office" }),
    (e) => e.getStatus?.() === 400,
  );
  const zone = await apply({
    ...basePolicy,
    action: "policy.zone",
    name: "zone-policy",
    srcInterface: "legacy",
    value: "",
  });
  assert.equal(zone.row.srcintf, "legacy");
  const enabledAtCreate = await apply({
    ...basePolicy,
    name: "enabled-policy",
    policyStatus: "enable",
    value: "",
  });
  assert.equal(enabledAtCreate.row.status, "enable");
  const savedInterface = internet.row.srcintf,
    savedComment = internet.row.comments;
  await apply({
    action: "policy.update",
    name: internet.result.targetId,
    value: "",
    dstAddresses: "office,all",
    services: "custom-http",
    nat: false,
    logTraffic: "utm",
  });
  assert.equal(internet.row.srcintf, savedInterface);
  // Fixture rows are replaced on next; read the current committed row.
  let current = fixture.controlTables["firewall policy"][internet.result.targetId];
  assert.equal(current.srcintf, savedInterface);
  assert.equal(current.comments, savedComment);
  assert.equal(current.service, "custom-http");
  assert.equal(current.logtraffic, "utm");
  assert.equal(current.nat, "disable");
  await apply({ action: "policy.enable", name: internet.result.targetId, value: "" });
  assert.equal(fixture.controlTables["firewall policy"][internet.result.targetId].status, "enable");
  await apply({ action: "policy.disable", name: internet.result.targetId, value: "" });
  assert.equal(
    fixture.controlTables["firewall policy"][internet.result.targetId].status,
    "disable",
  );
  await apply({
    action: "policy.comment",
    name: internet.result.targetId,
    value: "به‌روزرسانی شبکه",
  });
  assert.ok(
    fixture.controlTables["firewall policy"][internet.result.targetId].comments.includes(
      "به‌روزرسانی شبکه",
    ),
  );
  await apply({
    action: "policy.move",
    name: internet.result.targetId,
    value: "",
    position: "before",
    relativeTo: "10",
  });
  assert.equal(
    fixture.policyOrder[fixture.policyOrder.indexOf("10") - 1],
    internet.result.targetId,
  );
  await apply({
    action: "policy.move",
    name: internet.result.targetId,
    value: "",
    position: "after",
    relativeTo: "20",
  });
  assert.equal(
    fixture.policyOrder[fixture.policyOrder.indexOf("20") + 1],
    internet.result.targetId,
  );
  const unchanged = await preview({
    action: "policy.move",
    name: "10",
    value: "",
    position: "before",
    relativeTo: "20",
  });
  fixture.mode("control-mismatch");
  const mismatch = await service.execute(actor, id, unchanged.id, {
    intent: "execute",
    confirmed: true,
  });
  // This requested pair is already adjacent; use another move to test a missing change.
  assert.equal(mismatch.status, "succeeded");
  fixture.mode("normal");
  const wrongMove = await preview({
    action: "policy.move",
    name: "10",
    value: "",
    position: "after",
    relativeTo: internet.result.targetId,
  });
  fixture.mode("control-mismatch");
  assert.equal(
    (await service.execute(actor, id, wrongMove.id, { intent: "execute", confirmed: true })).status,
    "verification_failed",
  );
  fixture.mode("normal");
  await assert.rejects(
    preview({ action: "policy.delete", name: "10", value: "" }),
    (e) => e.getStatus?.() === 400,
  );
  await apply({ action: "policy.delete", name: deny.result.targetId, value: "" });
  assert.equal(fixture.controlTables["firewall policy"][deny.result.targetId], undefined);
  for (const bad of [
    { ...basePolicy, name: "missing-port", srcInterface: "missing" },
    { ...basePolicy, name: "missing-address", dstAddresses: "missing" },
    { ...basePolicy, name: "missing-service", services: "missing" },
    { ...basePolicy, name: "missing-schedule", schedule: "missing" },
    { ...basePolicy, name: "x".repeat(36) },
    { action: "policy.update", name: "1000", value: "" },
    { action: "policy.move", name: "10", relativeTo: "10", position: "after", value: "" },
    { action: "policy.move", name: "10", relativeTo: "9999", position: "after", value: "" },
    { action: "policy.comment", name: "10", value: 'bad"\nend' },
  ])
    await assert.rejects(preview(bad), (e) => e.getStatus?.() === 400);
  await assert.rejects(preview(basePolicy), (e) => e.getStatus?.() === 400);
  const stale = await preview({ ...basePolicy, name: "stale-source", srcAddresses: "office" });
  fixture.controlTables["firewall address"].office.subnet = "192.0.3.0 255.255.255.0";
  await assert.rejects(
    service.execute(actor, id, stale.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  const partial = await preview({ ...basePolicy, name: "partial", sourceCidr: "198.51.100.0/24" });
  fixture.mode("control-policy-failure");
  assert.equal(
    (await service.execute(actor, id, partial.id, { intent: "execute", confirmed: true })).status,
    "failed",
  );
  assert.ok(fixture.controlTables["firewall address"][partial.after.__sourceName]);
  assert.ok(
    !Object.values(fixture.controlTables["firewall policy"]).some((r) => r.name === "partial"),
  );
  fixture.mode("normal");
  const interrupted = await preview({ ...basePolicy, name: "interrupted" });
  fixture.mode("control-disconnect");
  assert.equal(
    (await service.execute(actor, id, interrupted.id, { intent: "execute", confirmed: true }))
      .status,
    "verification_pending",
  );
  fixture.mode("normal");
  const writes = fixture.controlWrites.length;
  const verified = await service.verify(actor, id, interrupted.id);
  assert.equal(verified.status, "succeeded");
  assert.ok(verified.targetId && verified.targetId !== "0");
  assert.equal(fixture.controlWrites.length, writes);
  assert.deepEqual([...actions].sort(), [...fortiPolicyActions].sort());
  const history = (await call(path, auth)).body.items;
  assert.ok(history.some((r) => r.targetId === verified.targetId));
  assert.ok(!JSON.stringify(history).includes(fixture.password));
  for (let n = 2000; n < 2260; n++) {
    const key = String(n);
    fixture.controlTables["firewall policy"][key] = { name: "bounded-" + n, status: "disable" };
    fixture.policyOrder.push(key);
  }
  await apply({ action: "policy.enable", name: "2259", value: "" });
  assert.equal(fixture.controlTables["firewall policy"]["2259"].status, "enable");
  const transferred = await preview({ ...basePolicy, name: "transfer" });
  const company = await call("/devices/companies", { ...auth, body: { name: "Policy isolated" } });
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
    "Forti policies: 11 registered actions over real Nest/SSH, auto ID + invocation readback, source CIDR/reuse/collision and partial failure, disabled/enabled defaults, references/freshness, partial update, real order/no-op/mismatch, managed delete, no replay, pending read-only verification and role/tenant/company boundaries passed.",
  );
} finally {
  fixture.release();
  if (db && users.length) await db.getRepository(AppUser).delete(users);
  if (app) await app.close();
  await fixture.close();
}
