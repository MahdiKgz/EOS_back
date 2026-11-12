import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import "reflect-metadata";
import { config } from "dotenv";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
import { esxiSoapFixture } from "./fixtures/esxi-soap-server.mjs";
import { networkApiFixture } from "./fixtures/network-api-server.mjs";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js");
const soap = await esxiSoapFixture(),
  rest = await networkApiFixture(),
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
        username: "secondary_api_" + randomBytes(5).toString("hex"),
        password: "Secondary-Api-Fixture-2026!",
        displayName: "تست کانال API ثانویه",
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
  await call("/devices/companies", auth);
  const credentialPath = "/devices/api-credentials",
    credentialBody = {
      name: "Secondary ESXi",
      username: soap.username,
      password: soap.password,
      caCertificate: soap.ca,
    };
  const credential = await call(credentialPath, { ...auth, body: credentialBody });
  assert.equal(credential.status, 201);
  const credentialId = credential.body.id;
  const input = {
    name: "ESXi primary SSH",
    type: "esxi",
    vendor: "vmware",
    host: "192.0.2.10",
    managementPort: 22,
    protocol: "ssh",
    companyId: admin.id,
    environment: "lab",
    tags: [],
  };
  const created = await call("/devices", { ...auth, body: input });
  assert.equal(created.status, 201);
  const id = created.body.id,
    path = `/devices/${id}/connection-channels`;
  const state = async () => (await call(path, auth)).body;
  const configure = async (config) =>
    call(path, {
      ...auth,
      method: "PUT",
      body: { ...config, revision: (await state()).secondary?.revision },
    });
  const config = {
    method: "soap_api",
    host: soap.host,
    port: soap.port,
    credentialId,
    priority: 1,
  };
  assert.ok((await state()).availableMethods.includes("soap_api"));
  assert.equal(
    (await call(path, { token: employee.token, method: "PUT", body: config })).status,
    403,
  );
  assert.equal((await call(path, { token: other.token })).status, 404);
  const foreign = await call(credentialPath, { token: other.token, body: credentialBody });
  assert.equal((await configure({ ...config, credentialId: foreign.body.id })).status, 404);
  assert.equal((await configure(config)).status, 200);
  let metadata = await state();
  assert.equal(metadata.primary.method, "ssh");
  assert.equal(metadata.primary.port, 22);
  assert.equal(metadata.secondary.host, soap.host);
  assert.equal(metadata.secondary.port, soap.port);
  assert.equal(metadata.secondary.enabled, false);
  assert.equal(metadata.secondary.credentialId, credentialId);
  const test = () => call(path + "/test-secondary", { ...auth, body: {} });
  let result = await test();
  assert.equal(result.status, 201, JSON.stringify(result.body));
  assert.equal(result.body.connected, true);
  assert.equal(result.body.inventory.kind, "esxi");
  assert.equal(result.body.inventory.cpuPercent, 12.5);
  assert.equal(result.body.inventory.vms.length, 2);
  assert.equal(soap.sessions.size, 0);
  metadata = await state();
  assert.equal(metadata.secondary.status, "verified");
  assert.equal(metadata.secondary.lastTestAt, result.body.checkedAt);
  assert.equal(metadata.secondary.revision, result.body.revision);
  assert.equal(metadata.preferred, "observability");
  assert.equal(metadata.primary.status, "configured");
  assert.equal((await call(`/devices/${id}`, auth)).body.verification, null);
  assert.equal(metadata.history[0].method, "soap_api");
  assert.ok(!JSON.stringify(result.body).includes(soap.password));
  assert.equal(
    (
      await call(path + "/state", {
        ...auth,
        method: "PUT",
        body: { enabled: false, revision: metadata.secondary.revision },
      })
    ).body.secondary.enabled,
    false,
  );
  assert.equal(
    (
      await call(path + "/state", {
        ...auth,
        method: "PUT",
        body: { enabled: true, revision: metadata.secondary.revision },
      })
    ).body.secondary.enabled,
    true,
  );
  const edit = (body) =>
    call(credentialPath + "/" + credentialId, { ...auth, method: "PUT", body });
  await edit({ ...credentialBody, caCertificate: "" });
  metadata = await state();
  assert.equal(metadata.secondary.status, "configured");
  assert.equal(metadata.secondary.enabled, false);
  assert.equal(
    (
      await call(path + "/state", {
        ...auth,
        method: "PUT",
        body: { enabled: true, revision: metadata.secondary.revision },
      })
    ).status,
    409,
  );
  result = await test();
  assert.equal(result.status, 201);
  assert.equal(result.body.connected, false);
  assert.equal(result.body.errorCode, "ESXI_TLS_OR_NETWORK");
  assert.equal(result.body.inventory, undefined);
  metadata = await state();
  assert.equal(metadata.secondary.status, "error");
  assert.ok(metadata.secondary.lastSuccessAt);
  await edit(credentialBody);
  assert.equal((await test()).body.connected, true);
  const observed = soap.pause(),
    pending = test();
  await Promise.race([
    observed,
    new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error("SOAP fixture was not queried")), 8000);
      timer.unref();
    }),
  ]);
  assert.equal((await test()).status, 409);
  metadata = await state();
  assert.equal(metadata.secondary.testing, true);
  assert.equal(
    (
      await call(path + "/state", {
        ...auth,
        method: "PUT",
        body: { enabled: false, revision: metadata.secondary.revision },
      })
    ).status,
    409,
  );
  assert.equal((await configure({ ...config, priority: 2 })).status, 200);
  soap.release();
  assert.equal((await pending).status, 409);
  assert.equal((await state()).secondary.enabled, false);
  assert.equal(soap.sessions.size, 0);
  assert.equal((await test()).body.connected, true);
  const savedRevision = (await state()).secondary.revision;
  assert.equal((await configure(config)).status, 200);
  assert.equal(
    (await call(path, { ...auth, method: "PUT", body: { ...config, revision: savedRevision } }))
      .status,
    409,
  );
  for (let i = 0; i < 3; i++) assert.equal((await test()).body.connected, true);
  metadata = await state();
  assert.equal(metadata.history.length, 5);
  assert.equal(metadata.secondary.status, "verified");
  await call(`/devices/${id}`, { ...auth, method: "DELETE" });
  assert.equal((await test()).status, 404);
  await call(`/devices/${id}/restore`, { ...auth, body: {} });
  assert.equal((await state()).secondary.status, "verified");
  const company = (
    await call("/devices/companies", { ...auth, body: { name: "شرکت انتقال کانال ثانویه" } })
  ).body;
  assert.equal(
    (
      await call(`/devices/${id}`, {
        ...auth,
        method: "PUT",
        body: { ...input, companyId: company.id },
      })
    ).status,
    200,
  );
  metadata = await state();
  assert.equal(metadata.secondary.credentialId, null);
  assert.equal(metadata.secondary.needsCredential, true);
  assert.equal(metadata.secondary.enabled, false);
  assert.equal((await test()).status, 404);
  assert.equal((await configure(config)).status, 200);
  assert.equal((await test()).body.connected, true);
  await call(credentialPath + "/" + credentialId, { ...auth, method: "DELETE" });
  assert.equal((await state()).secondary.needsCredential, true);
  assert.equal((await state()).secondary.enabled, false);
  const restCredential = await call(credentialPath, {
    ...auth,
    body: {
      name: "Secondary RouterOS",
      username: rest.username,
      password: rest.password,
      caCertificate: rest.ca,
    },
  });
  const mikrotik = await call("/devices", {
    ...auth,
    body: {
      ...input,
      name: "MikroTik primary SSH",
      type: "mikrotik",
      vendor: "mikrotik",
      host: "192.0.2.20",
    },
  });
  assert.equal(mikrotik.status, 201);
  const restPath = `/devices/${mikrotik.body.id}/connection-channels`,
    restConfig = {
      method: "rest_api",
      host: rest.host,
      port: rest.port,
      credentialId: restCredential.body.id,
      priority: 2,
    };
  assert.ok((await call(restPath, auth)).body.availableMethods.includes("rest_api"));
  assert.equal(
    (await call(restPath, { ...auth, method: "PUT", body: { ...restConfig, method: "soap_api" } }))
      .status,
    400,
  );
  assert.equal((await call(restPath, { ...auth, method: "PUT", body: restConfig })).status, 200);
  const restResult = await call(restPath + "/test-secondary", { ...auth, body: {} });
  assert.equal(restResult.status, 201, JSON.stringify(restResult.body));
  assert.equal(restResult.body.connected, true);
  assert.equal(restResult.body.inventory.kind, "mikrotik");
  assert.equal(restResult.body.inventory.interfaceCounters[0].rxBytes, 123456);
  assert.equal((await call(`/devices/${mikrotik.body.id}`, auth)).body.verification, null);
  assert.ok(rest.calls.every((entry) => entry.method === "GET"));
  console.log(
    "PASS secondary API: independent HTTPS SOAP/REST on separate hosts/ports, reusable private credentials, returned inventory tied to revision/time, priority/toggle, stale proof/credential changes, concurrent reconfiguration, tenant/role boundaries, archive/restore, transfer and 5-result retention",
  );
} finally {
  soap.release();
  rest.release();
  for (const id of users.reverse()) await db?.getRepository(AppUser).delete(id);
  await app?.close();
  await soap.close();
  await rest.close();
}
