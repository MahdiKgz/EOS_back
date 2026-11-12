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
    compileFortiObject,
    normalizedFortiField,
  } = require("../dist/modules/devices/fortigate-object-compiler.js");
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
  async function apply(body) {
    const p = await preview(body);
    const result = await service.execute(actor, id, p.id, { intent: "execute", confirmed: true });
    assert.equal(
      result.status,
      "succeeded",
      JSON.stringify({ action: body.action, status: result.status }),
    );
    assert.equal(result.verified, true);
    return p;
  }
  const input = {
    ...common,
    action: "address.create",
    name: "new-subnet",
    value: "198.51.100.0/24",
    addressType: "subnet",
  };
  assert.equal((await call(path + "/preview", { token: employee.token, body: input })).status, 403);
  assert.equal(
    (await call(`/devices/${id}/actions/preview`, { token: other.token, body: input })).status,
    404,
  );
  const before = fixture.controlWrites.length,
    initial = await call(path + "/preview", { ...auth, body: input });
  assert.equal(initial.status, 201, JSON.stringify(initial.body));
  assert.equal(fixture.controlWrites.length, before);
  assert.equal(initial.body.after.subnet, "198.51.100.0 255.255.255.0");
  const changed = await call(path + `/${initial.body.id}/execute`, {
    ...auth,
    body: { intent: "execute", confirmed: true },
  });
  assert.equal(changed.body.status, "succeeded");
  assert.equal(
    fixture.controlTables["firewall address"]["new-subnet"].subnet,
    "198.51.100.0 255.255.255.0",
  );
  await assert.rejects(preview(input), (e) => e.getStatus?.() === 400);
  await apply({
    action: "address.update",
    name: "new-subnet",
    value: "198.51.100.128/25",
    addressType: "subnet",
  });
  for (const [name, addressType, value, endIp] of [
    ["domain", "fqdn", "example.com"],
    ["wildcard", "wildcard-fqdn", "*.example.com"],
    ["range", "iprange", "198.51.100.2", "198.51.100.9"],
    ["country", "geography", "US"],
  ])
    await apply({ action: "address.create", name, addressType, value, endIp });
  await apply({ action: "addressGroup.create", name: "group-a", value: "office,new-subnet" });
  assert.equal(fixture.controlTables["firewall addrgrp"]["group-a"].member, "office new-subnet");
  await apply({ action: "addressGroup.add", name: "group-a", value: "domain" });
  assert.ok(fixture.controlTables["firewall addrgrp"]["group-a"].member.includes("domain"));
  await apply({ action: "addressGroup.remove", name: "group-a", value: "domain" });
  assert.ok(!fixture.controlTables["firewall addrgrp"]["group-a"].member.includes("domain"));
  await apply({ action: "addressGroup.create", name: "group-b", value: "group-a" });
  await assert.rejects(
    preview({ action: "addressGroup.add", name: "group-a", value: "group-b" }),
    (e) => e.getStatus?.() === 400,
  );
  await assert.rejects(
    preview({ action: "addressGroup.add", name: "group-a", value: "missing-object" }),
    (e) => e.getStatus?.() === 400,
  );
  const dependencyPreview = await preview({
    action: "addressGroup.add",
    name: "group-a",
    value: "domain",
  });
  fixture.controlTables["firewall address"].domain.fqdn = "changed.example.com";
  await assert.rejects(
    service.execute(actor, id, dependencyPreview.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  await apply({
    action: "service.create",
    name: "custom-service",
    value: "80,443,1000-1002",
    serviceProtocol: "TCP",
  });
  assert.equal(
    fixture.controlTables["firewall service custom"]["custom-service"].protocol,
    "TCP/UDP/SCTP",
  );
  await apply({
    action: "service.update",
    name: "custom-service",
    value: "53",
    serviceProtocol: "UDP",
  });
  assert.equal(
    fixture.controlTables["firewall service custom"]["custom-service"]["udp-portrange"],
    "53",
  );
  assert.equal(
    fixture.controlTables["firewall service custom"]["custom-service"]["tcp-portrange"],
    undefined,
  );
  await apply({
    action: "service.update",
    name: "custom-service",
    value: "443",
    udpPorts: "443,500-501",
    serviceProtocol: "TCP-UDP",
  });
  await apply({
    action: "serviceGroup.create",
    name: "service-group",
    value: "HTTPS,custom-service",
  });
  await apply({ action: "serviceGroup.add", name: "service-group", value: "DNS" });
  await apply({ action: "serviceGroup.remove", name: "service-group", value: "DNS" });
  await apply({ action: "serviceGroup.create", name: "service-group-b", value: "service-group" });
  await assert.rejects(
    preview({ action: "serviceGroup.add", name: "service-group", value: "service-group-b" }),
    (e) => e.getStatus?.() === 400,
  );
  await assert.rejects(
    preview({ action: "service.update", name: "HTTPS", value: "8443", serviceProtocol: "TCP" }),
    (e) => e.getStatus?.() === 400,
  );
  await apply({
    action: "schedule.create",
    name: "working",
    value: "monday,tuesday",
    start: "08:30",
    end: "17:45",
  });
  await apply({
    action: "schedule.update",
    name: "working",
    value: "wednesday",
    start: "09:00",
    end: "18:00",
  });
  assert.equal(fixture.controlTables["firewall schedule recurring"].working.day, "wednesday");
  await assert.rejects(
    preview({
      action: "schedule.update",
      name: "working",
      value: "monday",
      start: "25:00",
      end: "18:00",
    }),
    (e) => e.getStatus?.() === 400,
  );
  await apply({ action: "zone.create", name: "new-zone", value: "", intrazone: "deny" });
  await apply({ action: "zone.add", name: "new-zone", value: "lan" });
  await apply({ action: "zone.update", name: "new-zone", value: "lan,wan1", intrazone: "allow" });
  await apply({ action: "zone.remove", name: "new-zone", value: "wan1" });
  assert.equal(fixture.controlTables["system zone"]["new-zone"].intrazone, "allow");
  assert.equal(fixture.controlTables["system zone"]["new-zone"].interface, "lan");
  await apply({ action: "zone.remove", name: "new-zone", value: "lan" });
  assert.equal(fixture.controlTables["system zone"]["new-zone"].interface, undefined);
  await apply({ action: "zone.delete", name: "new-zone" });
  assert.equal(fixture.controlTables["system zone"]["new-zone"], undefined);
  await assert.rejects(
    preview({ action: "zone.delete", name: "legacy" }),
    (e) => e.getStatus?.() === 400,
  );
  await assert.rejects(
    preview({ action: "address.delete", name: "office" }),
    (e) => e.getStatus?.() === 400,
  );
  const deletion = await preview({ action: "address.delete", name: "range" });
  assert.equal(deletion.before["start-ip"], "198.51.100.2");
  fixture.mode("control-dependency");
  const denied = await service.execute(actor, id, deletion.id, {
    intent: "execute",
    confirmed: true,
  });
  assert.equal(denied.status, "failed");
  assert.ok(fixture.controlTables["firewall address"].range);
  fixture.mode("normal");
  await apply({ action: "address.delete", name: "range" });
  await apply({ action: "serviceGroup.remove", name: "service-group", value: "custom-service" });
  await apply({ action: "service.delete", name: "custom-service" });
  const vipInput = {
    action: "vip.create",
    name: "public-web",
    value: "",
    externalIp: "198.51.100.10",
    mappedIp: "192.0.2.10",
    externalPort: "8443",
    mappedPort: "443",
    parent: "lan",
  };
  const vipPreview = await call(path + "/preview", {
    ...auth,
    body: { ...vipInput, vdom: "root" },
  });
  assert.equal(vipPreview.status, 201, JSON.stringify(vipPreview.body));
  assert.equal(
    (await service.execute(actor, id, vipPreview.body.id, { intent: "execute", confirmed: true }))
      .status,
    "succeeded",
  );
  assert.equal(fixture.controlTables["firewall vip"]["public-web"].extintf, "lan");
  assert.equal(fixture.controlTables["firewall vip"]["public-web"].portforward, "enable");
  await assert.rejects(preview(vipInput), (e) => e.getStatus?.() === 400);
  await apply({ action: "vip.update", name: "public-web", value: "", mappedPort: "9443" });
  assert.equal(fixture.controlTables["firewall vip"]["public-web"].mappedport, "9443");
  assert.equal(fixture.controlTables["firewall vip"]["public-web"].extip, "198.51.100.10");
  await assert.rejects(
    preview({ action: "vip.update", name: "public-web", value: "" }),
    (e) => e.getStatus?.() === 400,
  );
  await assert.rejects(
    preview({ ...vipInput, name: "missing-interface", parent: "not-present" }),
    (e) => e.getStatus?.() === 400,
  );
  await assert.rejects(
    preview({ ...vipInput, name: "invalid-port", externalPort: "65536" }),
    (e) => e.getStatus?.() === 400,
  );
  assert.equal(
    (
      await call(path + "/preview", {
        ...auth,
        body: { ...vipInput, name: "invalid-dto", mappedPort: "80;end", vdom: "root" },
      })
    ).status,
    400,
  );
  const vipStale = await preview({ ...vipInput, name: "interface-changed" });
  fixture.interfaceRows.lan.alias = "External interface change";
  await assert.rejects(
    service.execute(actor, id, vipStale.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  await assert.rejects(
    preview({ action: "vipGroup.create", name: "invalid-group", value: "missing-vip" }),
    (e) => e.getStatus?.() === 400,
  );
  await apply({ action: "vipGroup.create", name: "vip-group", value: "public-web" });
  assert.equal(fixture.controlTables["firewall vipgrp"]["vip-group"].member, "public-web");
  const vipDelete = await preview({ action: "vip.delete", name: "public-web", value: "" });
  fixture.mode("control-dependency");
  assert.equal(
    (await service.execute(actor, id, vipDelete.id, { intent: "execute", confirmed: true })).status,
    "failed",
  );
  assert.ok(fixture.controlTables["firewall vip"]["public-web"]);
  fixture.mode("normal");
  // Simulate an operator removing the dependency on the equipment before a new preview.
  delete fixture.controlTables["firewall vipgrp"]["vip-group"];
  await apply({ action: "vip.delete", name: "public-web", value: "" });
  assert.equal(fixture.controlTables["firewall vip"]["public-web"], undefined);
  await apply({
    action: "ipPool.create",
    name: "source-pool",
    value: "198.51.100.20",
    endIp: "198.51.100.30",
  });
  await apply({ action: "ipPool.update", name: "source-pool", value: "", endIp: "198.51.100.25" });
  assert.equal(fixture.controlTables["firewall ippool"]["source-pool"].startip, "198.51.100.20");
  assert.equal(fixture.controlTables["firewall ippool"]["source-pool"].endip, "198.51.100.25");
  await assert.rejects(
    preview({ action: "ipPool.update", name: "source-pool", value: "198.51.100.26" }),
    (e) => e.getStatus?.() === 400,
  );
  await assert.rejects(
    preview({
      action: "ipPool.create",
      name: "invalid-range",
      value: "::1",
      endIp: "198.51.100.25",
    }),
    (e) => e.getStatus?.() === 400,
  );
  await apply({ action: "ipPool.delete", name: "source-pool", value: "" });
  assert.equal(fixture.controlTables["firewall ippool"]["source-pool"], undefined);
  const pendingPlan = await preview({
    action: "address.update",
    name: "domain",
    addressType: "fqdn",
    value: "pending.example.com",
  });
  fixture.mode("control-disconnect");
  const pending = await service.execute(actor, id, pendingPlan.id, {
    intent: "execute",
    confirmed: true,
  });
  assert.equal(pending.status, "verification_pending");
  fixture.mode("normal");
  const writes = fixture.controlWrites.length;
  assert.equal((await service.verify(actor, id, pendingPlan.id)).status, "succeeded");
  assert.equal(fixture.controlWrites.length, writes);
  assert.equal(normalizedFortiField("tcp-portrange", "81 80 1000-1001 1002"), "80-81 1000-1002");
  assert.throws(() => compileFortiObject({ ...input, name: 'bad"\nend' }));
  assert.throws(() =>
    compileFortiObject({ ...input, addressType: "fqdn", value: 'evil.com";delete all' }),
  );
  assert.ok(!JSON.stringify((await call(path, auth)).body).includes(fixture.password));
  const company = await call("/devices/companies", { ...auth, body: { name: "Objects isolated" } }),
    staleCompany = await preview({
      action: "address.update",
      name: "domain",
      addressType: "fqdn",
      value: "transfer.example.com",
    });
  await call(`/devices/${id}`, {
    ...auth,
    method: "PUT",
    body: { ...device, companyId: company.body.id },
  });
  await assert.rejects(
    service.execute(actor, id, staleCompany.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 404,
  );
  assert.deepEqual((await call(path, auth)).body.items, []);
  console.log(
    "Forti objects: all 26 registered object actions over real SSH; VIP partial updates, interface dependency, VIP group/reference failure, IP pool ranges, address variants, TCP/UDP fields, groups/dependency freshness/cycle, schedule, empty/nonempty zone, managed delete/reference failure, read-only preview, no overwrite, pending readback, validation and role/tenant/company boundaries passed.",
  );
} finally {
  fixture.release();
  if (db && users.length) await db.getRepository(AppUser).delete(users);
  if (app) await app.close();
  await fixture.close();
}
