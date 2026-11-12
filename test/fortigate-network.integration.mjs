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
  { fortiNetworkActions } = require("../dist/modules/devices/fortigate-network.js");
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
  const input = {
    action: "snat.create",
    name: "auto-snat",
    srcInterface: "lan",
    dstInterface: "wan1",
    sourceCidr: "192.0.2.0/24",
    value: "",
    vdom: "root",
  };
  const writesBefore = fixture.controlWrites.length;
  assert.equal((await call(path + "/preview", { token: employee.token, body: input })).status, 403);
  assert.equal((await call(path, { token: other.token })).status, 404);
  const initial = await call(path + "/preview", { ...auth, body: input });
  assert.equal(initial.status, 201, JSON.stringify(initial.body));
  assert.equal(fixture.controlWrites.length, writesBefore);
  assert.ok(initial.body.message.includes("غیرفعال"));
  assert.ok(initial.body.commands.includes("edit 0"));
  assert.ok(initial.body.commands.includes("config vdom"));
  assert.ok(initial.body.after["orig-addr"].startsWith("firewall-log-analyzer-src-"));
  const run = await call(path + `/${initial.body.id}/execute`, {
    ...auth,
    body: { intent: "execute", confirmed: true },
  });
  assert.equal(run.body.status, "succeeded", JSON.stringify(run.body));
  assert.equal(run.body.targetId, "800");
  assert.equal(fixture.controlSystem["system settings"]["central-nat"], "disable");
  assert.equal(
    fixture.controlTables["firewall central-snat-map"]["800"]["orig-addr"],
    initial.body.after.__sourceName,
  );
  assert.equal(
    (
      await call(path + `/${initial.body.id}/execute`, {
        ...auth,
        body: { intent: "execute", confirmed: true },
      })
    ).status,
    409,
  );
  const actions = new Set(["snat.create"]);
  async function apply(body) {
    let p, result;
    if (!actions.has(body.action)) {
      const planned = await call(path + "/preview", {
        ...auth,
        body: { vdom: "root", value: "", ...body },
      });
      assert.equal(planned.status, 201, JSON.stringify(planned.body));
      p = planned.body;
      const executed = await call(path + `/${p.id}/execute`, {
        ...auth,
        body: { intent: "execute", confirmed: true },
      });
      assert.equal(executed.status, 201);
      result = executed.body;
    } else {
      p = await preview(body);
      result = await service.execute(actor, id, p.id, { intent: "execute", confirmed: true });
    }
    assert.equal(result.status, "succeeded", JSON.stringify({ body, result }));
    actions.add(body.action);
    return { preview: p, result };
  }
  const named = await preview({
    ...input,
    sourceCidr: undefined,
    srcAddresses: "employees",
    dstAddresses: "office",
  });
  assert.ok(!named.commands.includes("config firewall address"));
  fixture.controlSystem["system settings"]["ngfw-mode"] = "policy-based";
  const implicit = await preview({ ...input, sourceCidr: undefined, srcAddresses: "office" });
  assert.ok(implicit.message.includes("فعال است"));
  fixture.controlSystem["system settings"]["ngfw-mode"] = "profile-based";
  fixture.controlSystem["system settings"]["central-nat"] = "enable";
  const enabled = await preview({ ...input, sourceCidr: undefined, srcAddresses: "office" });
  assert.ok(enabled.message.includes("فعال است"));
  fixture.controlSystem["system settings"]["central-nat"] = "disable";
  const beforeStale = fixture.controlWrites.length;
  await assert.rejects(
    service.execute(actor, id, enabled.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  assert.equal(fixture.controlWrites.length, beforeStale);
  const reuse = await preview(input);
  assert.ok(!reuse.commands.includes("config firewall address"));
  const route = await apply({
    action: "route.create",
    name: "auto-route",
    destinationCidr: "198.51.100.0/24",
    gateway: "192.0.2.254",
    dstInterface: "lan",
    value: "",
  });
  assert.equal(route.result.targetId, "500");
  assert.equal(fixture.controlTables["router static"]["500"].dst, "198.51.100.0 255.255.255.0");
  await apply({ action: "route.update", name: "500", gateway: "192.0.2.253", value: "" });
  assert.equal(fixture.controlTables["router static"]["500"].device, "lan");
  assert.equal(fixture.controlTables["router static"]["500"].dst, "198.51.100.0 255.255.255.0");
  const routeStale = await preview({
    action: "route.update",
    name: "500",
    gateway: "192.0.2.254",
    value: "",
  });
  fixture.interfaceRows.lan.alias = "Changed externally";
  await assert.rejects(
    service.execute(actor, id, routeStale.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  // Deletion of an explicitly selected existing route is supported without a managed-only tag.
  fixture.controlTables["router static"]["500"].comment = "existing operator route";
  await apply({ action: "route.delete", name: "500", value: "" });
  assert.equal(fixture.controlTables["router static"]["500"], undefined);
  const hostRoute = await apply({
    action: "route.create",
    name: "auto-route",
    destinationCidr: "198.51.100.8",
    gateway: "192.0.2.254",
    value: "",
  });
  assert.equal(
    fixture.controlTables["router static"][hostRoute.result.targetId].dst,
    "198.51.100.8 255.255.255.255",
  );
  const defaultRoute = await apply({
    action: "route.create",
    name: "auto-route",
    destinationCidr: "0.0.0.0/0",
    gateway: "192.0.2.254",
    value: "",
  });
  assert.equal(
    fixture.controlTables["router static"][defaultRoute.result.targetId].dst,
    "0.0.0.0 0.0.0.0",
  );
  const dns = await apply({
    action: "dns.update",
    name: "system",
    primaryDns: "198.51.100.53",
    secondaryDns: "198.51.100.54",
    value: "",
    vdom: "not-a-vdom",
  });
  assert.equal(dns.preview.vdom, "global");
  assert.ok(dns.preview.commands.includes("config global"));
  assert.equal(dns.preview.before.primary, "192.0.2.53");
  assert.equal(dns.result.targetId, undefined);
  assert.equal(fixture.controlSystem["system dns"].primary, "198.51.100.53");
  assert.equal(fixture.controlSystem["system dns"].protocol, "dot");
  assert.ok(fixture.controlScopes.includes("config global"));
  const ntp = await apply({
    action: "ntp.update",
    name: "system",
    ntpServer: "time.example.com",
    value: "",
  });
  assert.equal(ntp.preview.before.server, "old.ntp.local");
  assert.equal(fixture.controlSystem["system ntp"].type, "custom");
  assert.equal(fixture.controlSystem["system ntp"].ntpsync, "enable");
  assert.equal(fixture.controlSystem["system ntp"].syncinterval, "60");
  assert.equal(fixture.ntpServers["1"].server, "time.example.com");
  assert.equal(fixture.ntpServers["2"].server, "keep.ntp.local");
  const dnsStale = await preview({
    action: "dns.update",
    name: "system",
    primaryDns: "203.0.113.53",
    secondaryDns: "203.0.113.54",
    value: "",
  });
  fixture.controlSystem["system dns"].protocol = "cleartext";
  await assert.rejects(
    service.execute(actor, id, dnsStale.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  for (const bad of [
    { ...input, srcInterface: "missing" },
    { ...input, sourceCidr: undefined, srcAddresses: "missing" },
    { ...input, srcAddresses: "office" },
    { action: "route.create", name: "auto-route", destinationCidr: "bad", gateway: "192.0.2.254" },
    { action: "route.update", name: hostRoute.result.targetId, value: "" },
    { action: "route.update", name: hostRoute.result.targetId, dstInterface: "missing", value: "" },
    { action: "dns.update", name: "system", primaryDns: "bad", secondaryDns: "192.0.2.53" },
    { action: "ntp.update", name: "system", ntpServer: 'time.example.com"\nend' },
  ])
    await assert.rejects(preview(bad), (e) => e.getStatus?.() === 400);
  fixture.mode("control-read-failure");
  const readFailure = await call(path + "/preview", {
    ...auth,
    body: {
      action: "dns.update",
      name: "system",
      primaryDns: "192.0.2.53",
      secondaryDns: "192.0.2.54",
      value: "",
    },
  });
  assert.equal(readFailure.status, 502);
  fixture.mode("normal");
  const unknown = await preview({
    action: "route.update",
    name: hostRoute.result.targetId,
    gateway: "192.0.2.250",
    value: "",
  });
  fixture.mode("control-incomplete-readback");
  assert.equal(
    (await service.execute(actor, id, unknown.id, { intent: "execute", confirmed: true })).status,
    "verification_pending",
  );
  fixture.mode("normal");
  const writes = fixture.controlWrites.length;
  const checked = await call(path + `/${unknown.id}/verify`, { ...auth, body: {} });
  assert.equal(checked.status, 201);
  assert.equal(checked.body.status, "succeeded");
  assert.equal(fixture.controlWrites.length, writes);
  const mismatch = await preview({
    action: "dns.update",
    name: "system",
    primaryDns: "203.0.113.53",
    secondaryDns: "203.0.113.54",
    value: "",
  });
  fixture.mode("control-mismatch");
  assert.equal(
    (await service.execute(actor, id, mismatch.id, { intent: "execute", confirmed: true })).status,
    "verification_failed",
  );
  fixture.mode("normal");
  const interrupted = await preview({ ...input, sourceCidr: undefined, srcAddresses: "office" });
  fixture.mode("control-disconnect");
  assert.equal(
    (await service.execute(actor, id, interrupted.id, { intent: "execute", confirmed: true }))
      .status,
    "verification_pending",
  );
  fixture.mode("normal");
  const attempts = fixture.controlWrites.length;
  const verified = await service.verify(actor, id, interrupted.id);
  assert.equal(verified.status, "succeeded");
  assert.ok(verified.targetId && verified.targetId !== "0");
  assert.equal(fixture.controlWrites.length, attempts);
  assert.deepEqual([...actions].sort(), [...fortiNetworkActions].sort());
  const transferred = await preview({
    action: "route.update",
    name: hostRoute.result.targetId,
    gateway: "192.0.2.251",
    value: "",
  });
  const company = await call("/devices/companies", { ...auth, body: { name: "Network isolated" } });
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
    "Forti network API: 6 actions, SNAT mode/implicit mode and stable auto ID, source object reuse, scoped/global settings, route partial update/default/host/deletion and dependency freshness, DNS preservation, NTP custom/server1 preservation, invalid input/reference, read failure 502, incomplete/mismatched/pending readback, no replay, tenant/role/company boundaries passed.",
  );
} finally {
  fixture.release();
  if (db && users.length) await db.getRepository(AppUser).delete(users);
  if (app) await app.close();
  await fixture.close();
}
