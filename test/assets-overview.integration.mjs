import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import "reflect-metadata";
import { config } from "dotenv";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js"),
  { Device } = require("../dist/modules/devices/device.entity.js");
const app = await NestFactory.create(AppModule, { logger: false }),
  users = [];
app.setGlobalPrefix("api/v1");
app.useGlobalPipes(
  new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
);
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
    return {
      status: response.status,
      body: await response.json(),
      cache: response.headers.get("cache-control"),
    };
  }
  async function account(role, owner) {
    const result = await call("/auth/register", {
      body: {
        username: "overview_" + randomBytes(6).toString("hex"),
        password: "Overview-Fixture-2026!",
        displayName: "کاربر تست نمای کلی",
      },
    });
    assert.equal(result.status, 201);
    users.push(result.body.user.id);
    await db
      .getRepository(AppUser)
      .update(result.body.user.id, { role, workspaceOwnerId: owner ?? null });
    return { id: result.body.user.id, token: result.body.accessToken };
  }
  const admin = await account("co_admin"),
    other = await account("pl_admin"),
    employee = await account("co_employee", admin.id),
    auth = { token: admin.token },
    path = "/devices/assets-overview";
  assert.equal((await call(path)).status, 401);
  assert.equal((await call(path, auth)).body.total, 0);
  await call("/devices/companies", auth);
  const company = (
    await call("/devices/companies", { ...auth, body: { name: "شرکت دوم نمای کلی" } })
  ).body;
  const rows = [];
  for (let i = 0; i < 23; i++) {
    const type = ["linux_edge", "camera", "nvr", "dvr"][i % 4];
    rows.push(
      db.getRepository(Device).create({
        name: i === 0 ? "Literal 100%" : "Asset " + String(i).padStart(2, "0"),
        vendor: i === 0 ? "literal" : type,
        host: "192.0.2." + (10 + i),
        type,
        protocol: type === "linux_edge" ? "ssh" : "api",
        managementPort: type === "linux_edge" ? 22 : 80,
        workspaceOwnerId: admin.id,
        companyId: i % 2 ? company.id : admin.id,
        environment: "lab",
        tags: [],
        location: i === 2 ? "ساختمان مرکزی" : "انبار",
        status: i % 3 === 0 ? "online" : i % 3 === 1 ? "offline" : "unknown",
        verification: i % 2 ? null : { checkedAt: new Date().toISOString() },
        lastSeenAt: i % 3 === 0 ? new Date() : null,
      }),
    );
  }
  await db.getRepository(Device).save(rows);
  const hidden = await db
    .getRepository(Device)
    .save(
      db
        .getRepository(Device)
        .create({ ...rows[0], id: randomUUID(), name: "Archived hidden", deletedAt: new Date() }),
    );
  const first = await call(path, auth);
  assert.equal(first.status, 200);
  assert.match(first.cache, /no-store/);
  assert.equal(first.body.total, 23);
  assert.equal(first.body.items.length, 20);
  assert.deepEqual(first.body.stats, { total: 23, online: 8, attention: 15, unverified: 11 });
  assert.deepEqual(first.body.analytics.status, { online: 8, offline: 8, error: 0, unknown: 7 });
  assert.equal(
    first.body.analytics.types.reduce((sum, row) => sum + row.count, 0),
    23,
  );
  assert.equal(first.body.analytics.types.find((row) => row.key === "camera").count, 6);
  assert.equal(
    first.body.analytics.vendors.reduce((sum, row) => sum + row.count, 0),
    23,
  );
  assert.ok(first.body.items.some((row) => row.type === "camera"));
  assert.ok(
    first.body.items.every(
      (row) =>
        !Object.hasOwn(row, "sealedRecorderCredentials") &&
        !Object.hasOwn(row, "credentialId") &&
        !Object.hasOwn(row, "verification"),
    ),
  );
  const second = (await call(path + "?page=2", auth)).body;
  assert.equal(second.items.length, 3);
  assert.deepEqual(
    second.analytics,
    first.body.analytics,
    "charts use all inventory, not the current page",
  );
  assert.equal(new Set([...first.body.items, ...second.items].map((row) => row.id)).size, 23);
  assert.ok(!first.body.items.some((row) => row.id === hidden.id));
  assert.equal((await call(path + "?filter=online", auth)).body.total, 8);
  assert.equal((await call(path + "?filter=attention", auth)).body.total, 15);
  assert.equal((await call(path + "?filter=unverified", auth)).body.total, 11);
  const companyA = (await call(path + "?companyId=" + admin.id, auth)).body;
  assert.equal(companyA.total, 12);
  assert.equal(companyA.stats.unverified, 0);
  assert.deepEqual(companyA.analytics.status, { online: 4, offline: 4, error: 0, unknown: 4 });
  assert.equal(
    companyA.analytics.types.reduce((sum, row) => sum + row.count, 0),
    12,
  );
  assert.ok(companyA.items.every((row) => row.companyName === "شرکت اصلی"));
  const companyB = (await call(path + "?companyId=" + company.id + "&filter=unverified", auth))
    .body;
  assert.equal(companyB.total, 11);
  assert.equal(companyB.stats.total, 11);
  assert.equal((await call(path + "?search=" + encodeURIComponent("100%"), auth)).body.total, 1);
  assert.equal(
    (await call(path + "?search=" + encodeURIComponent("ساختمان مرکزی"), auth)).body.items[0].id,
    rows[2].id,
  );
  assert.equal((await call(path + "?search=192.0.2.10", auth)).body.total, 1);
  const deniedCompany = (await call(path + "?companyId=" + other.id, auth)).body;
  assert.equal(deniedCompany.total, 0);
  assert.deepEqual(deniedCompany.analytics.status, { online: 0, offline: 0, error: 0, unknown: 0 });
  assert.deepEqual(deniedCompany.analytics.types, []);
  assert.deepEqual(deniedCompany.analytics.vendors, []);
  assert.equal((await call(path, { token: other.token })).body.total, 0);
  assert.equal((await call(path, { token: employee.token })).body.total, 23);
  for (const query of [
    "page=0",
    "pageSize=100",
    "filter=madeup",
    "companyId=not-an-id",
    "secret=leak",
  ]) {
    assert.equal((await call(path + "?" + query, auth)).status, 400);
  }
  assert.equal((await call("/devices/" + rows[0].id, { ...auth, method: "DELETE" })).status, 200);
  assert.equal((await call(path, auth)).body.total, 22);
  assert.equal(
    (await call("/devices/" + rows[0].id + "/restore", { ...auth, body: {} })).status,
    201,
  );
  assert.equal((await call(path, auth)).body.total, 23);
  const distributionCompany = (
    await call("/devices/companies", { ...auth, body: { name: "شرکت نمودار سازنده" } })
  ).body;
  await db.getRepository(Device).save(
    Array.from({ length: 7 }, (_, index) =>
      db.getRepository(Device).create({
        name: "Vendor fixture " + index,
        vendor: "vendor-" + index,
        type: "generic_firewall",
        host: "192.0.2." + (180 + index),
        managementPort: 22,
        protocol: "ssh",
        environment: "lab",
        tags: [],
        workspaceOwnerId: admin.id,
        companyId: distributionCompany.id,
        status: index === 0 ? "error" : "unknown",
      }),
    ),
  );
  const distribution = (await call(path + "?companyId=" + distributionCompany.id, auth)).body;
  assert.equal(distribution.stats.total, 7);
  assert.equal(distribution.analytics.vendors.length, 5);
  assert.equal(
    distribution.analytics.vendors.reduce((sum, row) => sum + row.count, 0),
    5,
    "remaining two are represented as other vendors in the chart",
  );
  assert.equal(distribution.analytics.status.error, 1);
  assert.deepEqual(distribution.analytics.types, [{ key: "generic_firewall", count: 7 }]);
  assert.deepEqual(
    (await call(path + "?companyId=" + distributionCompany.id + "&search=missing", auth)).body
      .analytics,
    distribution.analytics,
    "search does not change company-level charts",
  );
  await db.getRepository(AppUser).update(employee.id, { allowedSections: ["reports"] });
  assert.equal((await call(path, { token: employee.token })).status, 403);
  console.log(
    "PASS: unified assets overview, camera/NVR/device inventory, scoped counts, company/status/verification filters, literal search, stable pagination, no secrets, archive/restore, role/workspace isolation and validation",
  );
} finally {
  if (users.length) await app.get(DataSource).getRepository(AppUser).delete(users);
  await app.close();
}
