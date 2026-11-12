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
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js"),
  { Device } = require("../dist/modules/devices/device.entity.js"),
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
    return { status: r.status, body: await r.json(), cache: r.headers.get("cache-control") };
  }
  async function account(role, owner) {
    const r = await call("/auth/register", {
      body: {
        username: "vendor_" + randomBytes(6).toString("hex"),
        password: "Vendor-fixture-2026!",
        displayName: "آزمون وندور",
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
  await call("/devices/companies", { token: other.token });
  const company = await call("/devices/companies", { ...auth, body: { name: "شرکت دوم وندورها" } });
  assert.equal(company.status, 201);
  const created = [];
  for (let i = 0; i < 23; i++) {
    const r = await call("/devices", {
      ...auth,
      body: {
        name: i === 0 ? "fixture 100%_ Cisco" : "fixture Cisco " + i,
        type: "cisco",
        vendor: i % 2 ? "Cisco" : "Cisco Systems",
        host: `192.0.2.${i + 1}`,
        managementPort: 22,
        protocol: "ssh",
        environment: "lab",
        companyId: i < 20 ? admin.id : company.body.id,
        tags: [],
      },
    });
    assert.equal(r.status, 201);
    created.push(r.body.id);
  }
  await db.getRepository(Device).update(created.slice(0, 2), {
    status: "online",
    verification: {
      checkedAt: new Date().toISOString(),
      identity: { privateField: "NEVER_VENDOR_RESPONSE" },
    },
  });
  const registrations = [
    { type: "linux_edge", vendor: "Cisco Linux appliance" },
    { type: "mikrotik", vendor: "Mikrotik RouterOS" },
    { type: "fortigate", vendor: "Fortinet" },
    { type: "generic_firewall", vendor: "Sophos Firewall" },
    { type: "esxi", vendor: "VMware" },
    { type: "pfsense", vendor: "Netgate" },
    { type: "nvr", vendor: "Cisco" },
  ];
  for (let i = 0; i < registrations.length; i++) {
    const r = await call("/devices", {
      ...auth,
      body: {
        name: "Other family " + i,
        ...registrations[i],
        host: `198.51.100.${i + 1}`,
        managementPort: 22,
        protocol: "ssh",
        environment: "lab",
        companyId: admin.id,
        tags: [],
      },
    });
    assert.equal(r.status, 201);
  }
  const foreign = await call("/devices", {
    token: other.token,
    body: {
      name: "Foreign Cisco",
      type: "cisco",
      vendor: "Cisco",
      host: "203.0.113.1",
      managementPort: 22,
      protocol: "ssh",
      environment: "lab",
      companyId: other.id,
      tags: [],
    },
  });
  assert.equal(foreign.status, 201);
  assert.equal((await call("/vendors")).status, 401);
  let r = await call("/vendors", auth);
  assert.equal(r.status, 200);
  assert.equal(r.cache, "private, no-store");
  assert.equal(r.body.items.length, 7);
  assert.equal(r.body.total, 7);
  assert.equal(
    Object.values(r.body.stats).reduce((s, n) => s + n, 0),
    7,
  );
  assert.equal(r.body.items.find((v) => v.key === "cisco").deviceCount, 23);
  assert.equal(r.body.items.find((v) => v.key === "linux").deviceCount, 1);
  assert.equal(
    (await call("/vendors?companyId=" + company.body.id, auth)).body.items.find(
      (v) => v.key === "cisco",
    ).deviceCount,
    3,
  );
  assert.equal((await call("/vendors?companyId=" + other.id, auth)).status, 404);
  assert.equal((await call("/vendors?companyId=" + randomUUID(), auth)).status, 404);
  assert.equal((await call("/vendors?companyId=invalid", auth)).status, 400);
  assert.equal((await call("/vendors?unknown=true", auth)).status, 400);
  assert.equal((await call("/vendors?search=%25", auth)).body.items.length, 0);
  r = await call("/vendors?search=Cisco", auth);
  assert.equal(r.body.items.length, 1);
  assert.equal(r.body.stats.partial, 7);
  assert.equal((await call("/vendors?state=unsupported", auth)).body.items.length, 0);
  assert.equal((await call("/vendors?state=invalid", auth)).status, 400);
  const detail = (query = "", token = admin.token) => call("/vendors/cisco" + query, { token });
  r = await detail();
  assert.equal(r.status, 200);
  assert.equal(r.body.stats.total, 23);
  assert.equal(r.body.stats.online, 2);
  assert.equal(r.body.devices.items.length, 20);
  assert.equal(r.body.devices.total, 23);
  assert.ok(!JSON.stringify(r.body).includes("NEVER_VENDOR_RESPONSE"));
  assert.ok(!JSON.stringify(r.body).includes("credentialId"));
  assert.ok(!JSON.stringify(r.body).includes("sealedCredentials"));
  assert.ok(!r.body.devices.items.some((d) => d.id === foreign.body.id));
  const second = await detail("?page=2");
  assert.equal(second.body.devices.items.length, 3);
  assert.equal(
    new Set([...r.body.devices.items, ...second.body.devices.items].map((d) => d.id)).size,
    23,
  );
  assert.equal((await detail("?search=" + encodeURIComponent("%_"))).body.devices.total, 1);
  assert.equal(
    (await detail("?search=" + encodeURIComponent("' OR 1=1 --"))).body.devices.total,
    0,
  );
  const filtered = await detail("?status=online");
  assert.equal(filtered.body.devices.total, 2);
  assert.equal(filtered.body.stats.total, 23);
  assert.equal((await detail("?companyId=" + company.body.id)).body.devices.total, 3);
  assert.equal((await detail("?companyId=" + other.id)).status, 404);
  assert.equal((await detail("?page=0")).status, 400);
  assert.equal((await detail("?pageSize=999")).status, 400);
  assert.equal((await detail("?unknown=yes")).status, 400);
  assert.equal((await detail("?pageSize=10")).body.devices.items.length, 10);
  assert.equal((await detail("", employee.token)).body.devices.total, 23);
  assert.equal((await detail("", other.token)).body.devices.total, 1);
  assert.equal((await call("/vendors/missing", auth)).status, 404);
  for (const vendor of (await call("/vendors", auth)).body.items) {
    assert.ok(vendor.registration.type);
    assert.ok(vendor.requirements.length);
    assert.ok(vendor.platforms.length);
    assert.ok(vendor.capabilities.length);
    for (const capability of vendor.capabilities.filter((c) =>
      ["planned", "unsupported"].includes(c.state),
    ))
      assert.equal(capability.executable, undefined);
    assert.ok(!JSON.stringify(vendor).includes("sourceRefs"));
  }
  assert.ok(r.body.vendor.platforms.some((p) => p.key === "cisco-nx-os" && p.state === "planned"));
  assert.ok(
    r.body.vendor.platforms.some((p) => p.key === "cisco-unknown" && p.state === "unsupported"),
  );
  assert.equal((await call(`/devices/${created[0]}`, { ...auth, method: "DELETE" })).status, 200);
  assert.equal((await detail()).body.devices.total, 22);
  assert.equal((await call(`/devices/${created[0]}/restore`, { ...auth, body: {} })).status, 201);
  assert.equal((await detail()).body.devices.total, 23);
  await db.getRepository(AppUser).update(employee.id, { allowedSections: ["security"] });
  assert.equal((await detail("", employee.token)).status, 403);
  assert.equal((await call("/vendors", { token: employee.token })).status, 403);
  console.log(
    "PASS vendor catalog: seven families, actual support states, safe platform metadata, scoped company counts, canonical type classification, literal search, status/pagination, employee read access, foreign workspace denial, archive/restore and secret-free projection",
  );
} finally {
  if (db && users.length) await db.getRepository(AppUser).delete(users);
  if (app) await app.close();
}
