import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import "reflect-metadata";
import { config } from "dotenv";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
import { onvifFixture } from "./fixtures/onvif-server.mjs";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js"),
  { Device } = require("../dist/modules/devices/device.entity.js");
const fixture = await onvifFixture(),
  users = [];
let app;
try {
  app = await NestFactory.create(AppModule, { logger: false });
  app.setGlobalPrefix("api/v1");
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
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
    return { status: response.status, body: await response.json() };
  }
  async function account(role, owner) {
    const result = await call("/auth/register", {
      body: {
        username: "camera_" + randomBytes(6).toString("hex"),
        password: "Camera-Fixture-2026!",
        displayName: "کاربر تست دوربین",
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
    other = await account("co_admin"),
    employee = await account("co_employee", admin.id),
    auth = { token: admin.token };
  const input = {
    name: "ورودی ساختمان",
    type: "camera",
    vendor: "fixture",
    host: fixture.host,
    managementPort: fixture.port,
    protocol: "api",
    environment: "lab",
    location: "طبقه اول",
    tags: [],
    companyId: admin.id,
  };
  const connection = {
    username: "fixture",
    password: "fixture-secret",
    https: false,
    onvifPath: "/custom/device_service",
    mode: "onvif",
  };
  const draft = (body) =>
    call("/devices/draft-connection", {
      ...auth,
      body: { device: input, recorder: body, saveRecorderConnection: true },
    });
  for (const path of [
    "//other/soap",
    "/../soap",
    "https://other/soap",
    "/soap?secret=1",
    "/soap#fragment",
    "/soap\\unsafe",
  ]) {
    assert.equal((await draft({ ...connection, onvifPath: path })).status, 400);
  }
  assert.equal((await draft({ ...connection, mode: "appweb" })).status, 400);
  assert.equal((await draft({ ...connection, password: "wrong-fixture-password" })).status, 502);
  const proof = await draft(connection);
  assert.equal(proof.status, 201, JSON.stringify(proof.body));
  assert.equal(proof.body.identity.Model, "Private Camera");
  const created = await call("/devices", {
    ...auth,
    body: { ...input, verificationToken: proof.body.verificationToken },
  });
  assert.equal(created.status, 201);
  const id = created.body.id,
    path = "/devices/" + id;
  assert.equal(created.body.sealedRecorderCredentials, undefined);
  assert.equal(created.body.verification.identity.Manufacturer, "Fixture");
  const channelsPath = path + "/connection-channels";
  assert.equal((await call(channelsPath, auth)).body.primary.supported, true);
  assert.equal((await call(channelsPath, auth)).body.secondary, null);
  assert.equal(
    (await call(channelsPath + "/test-primary", { ...auth, body: {} })).body.connected,
    true,
  );
  assert.equal(
    (await call(channelsPath + "/test-primary", { token: employee.token, body: {} })).status,
    403,
  );
  const active = (await call("/devices?category=recorder&companyId=" + admin.id, auth)).body;
  assert.equal(active.total, 1);
  assert.equal(active.stats.total, 1);
  assert.equal(active.items[0].type, "camera");
  assert.equal((await call("/devices?category=network", auth)).body.total, 0);
  assert.equal(
    (await call("/devices?category=recorder&companyId=" + other.id, auth)).body.total,
    0,
  );
  assert.equal(
    (await call(path + "/inspect-recorder", { token: employee.token, body: {} })).status,
    403,
  );
  assert.equal(
    (await call(path + "/inspect-recorder", { token: other.token, body: {} })).status,
    404,
  );
  const report = await call(path + "/inspect-recorder", { ...auth, body: {} });
  assert.equal(report.status, 201);
  assert.equal(report.body.profiles[0].width, 1920);
  assert.equal(report.body.profiles[0].audioEncoding, "AAC");
  assert.equal(JSON.stringify(report.body).includes("fixture-secret"), false);
  const snapshot = await call(path + "/recorder-snapshot", { ...auth, body: { token: "main" } });
  assert.equal(snapshot.status, 201);
  assert.deepEqual(Buffer.from(snapshot.body.jpeg, "base64"), fixture.jpeg);
  assert.equal(
    (await call(path + "/verify-recorder-stream", { ...auth, body: { token: "main" } })).status,
    201,
  );
  fixture.setMedia2(true);
  assert.equal(
    (await call(path + "/inspect-recorder", { ...auth, body: {} })).body.profiles[0].encoding,
    "H264",
  );
  assert.equal(
    (await call(path + "/recorder-snapshot", { ...auth, body: { token: "main" } })).status,
    201,
  );
  const saved = await db
    .getRepository(Device)
    .findOne({ where: { id }, select: { id: true, sealedRecorderCredentials: true } });
  assert.ok(saved.sealedRecorderCredentials);
  assert.equal(saved.sealedRecorderCredentials.includes("fixture-secret"), false);
  assert.equal(
    (
      await call(path + "/verify-recorder", {
        ...auth,
        body: { useSaved: true, onvifPath: "/custom/device_service" },
      })
    ).status,
    400,
  );
  assert.equal(
    (await call(path + "/verify-recorder", { ...auth, body: { useSaved: true } })).status,
    201,
  );
  fixture.setFailed(true);
  assert.equal((await call(path + "/inspect-recorder", { ...auth, body: {} })).status, 502);
  fixture.setFailed(false);
  assert.equal((await call(path + "/inspect-recorder", { ...auth, body: {} })).status, 201);
  await db.query(
    'INSERT INTO "device_checks" ("deviceId","host","status","latencyMs","checkedAt") VALUES ($1,$2,\'online\',1,clock_timestamp())',
    [id, fixture.host],
  );
  const history = (await call(path + "/history", auth)).body;
  assert.equal((await call(path, { ...auth, method: "DELETE" })).status, 200);
  assert.equal((await call("/devices?category=recorder", auth)).body.total, 0);
  assert.equal((await call(path + "/inspect-recorder", { ...auth, body: {} })).status, 404);
  assert.equal(
    (await call("/devices?category=recorder&inventory=archived", { token: employee.token })).body
      .items[0].id,
    id,
  );
  const copy = await call("/devices", { ...auth, body: input });
  assert.equal(copy.status, 201);
  assert.equal((await call(path + "/restore", { ...auth, body: {} })).status, 409);
  await call("/devices/" + copy.body.id, { ...auth, method: "DELETE" });
  assert.equal((await call(path + "/restore", { ...auth, body: {} })).status, 201);
  assert.deepEqual((await call(path + "/history", auth)).body, history);
  assert.equal((await call(path + "/inspect-recorder", { ...auth, body: {} })).status, 201);
  const destination = (
    await call("/devices/companies", { ...auth, body: { name: "شرکت مقصد دوربین" } })
  ).body;
  assert.equal(
    (await call(path, { ...auth, method: "PUT", body: { ...input, companyId: other.id } })).status,
    404,
  );
  assert.equal(
    (await call(path, { ...auth, method: "PUT", body: { ...input, companyId: destination.id } }))
      .status,
    200,
  );
  assert.equal((await call(path + "/inspect-recorder", { ...auth, body: {} })).status, 404);
  assert.equal(
    (await call("/devices?category=recorder&companyId=" + admin.id, auth)).body.total,
    0,
  );
  assert.equal(
    (await call("/devices?category=recorder&companyId=" + destination.id, auth)).body.items[0].id,
    id,
  );
  assert.ok(
    fixture.requests.some(
      (req) => req.path === "/custom/device_service" && req.operation === "GetDeviceInformation",
    ),
  );
  assert.ok(
    fixture.requests.some(
      (req) => req.path === "/custom/media_service" && req.operation === "GetProfiles",
    ),
  );
  assert.ok(fixture.requests.some((req) => req.operation === "DESCRIBE" && req.authorized));
  console.log(
    "PASS: independent SOAP/HTTP/RTSP camera fixture, custom ONVIF path, WSSE password digest, Media/Media2, pinned snapshot/stream targets, encrypted saved credentials, role/workspace/company filters, archive/re-register/restore and transfer cleanup",
  );
} finally {
  if (app) {
    if (users.length) await app.get(DataSource).getRepository(AppUser).delete(users);
    await app.close();
  }
  await fixture.close();
}
