import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import "reflect-metadata";
import { config } from "dotenv";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
import { esxiSoapFixture } from "./fixtures/esxi-soap-server.mjs";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js");
const fixture = await esxiSoapFixture(),
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
        username: "esxi_" + randomBytes(6).toString("hex"),
        password: "Esxi-Fixture-2026!",
        displayName: "تست SOAP",
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
  const credentialBody = {
      name: "ESXi fixture",
      username: fixture.username,
      password: fixture.password,
      caCertificate: fixture.ca,
    },
    credentialPath = "/devices/api-credentials";
  assert.equal((await call(credentialPath)).status, 401);
  assert.equal(
    (
      await call(credentialPath, {
        ...auth,
        body: { ...credentialBody, caCertificate: "-----BEGIN PRIVATE KEY-----invalid" },
      })
    ).status,
    400,
  );
  const saved = await call(credentialPath, { ...auth, body: credentialBody });
  assert.equal(saved.status, 201);
  const credentialId = saved.body.id;
  assert.deepEqual(Object.keys(saved.body).sort(), ["id", "name", "username"]);
  assert.equal((await call(credentialPath, { token: other.token })).body.length, 0);
  assert.equal(
    (
      await call(credentialPath + "/" + credentialId, {
        token: other.token,
        method: "PUT",
        body: credentialBody,
      })
    ).status,
    404,
  );
  const sealed = (
    await db.query(`SELECT "sealedCredentials" FROM "device_api_credentials" WHERE "id"=$1`, [
      credentialId,
    ])
  )[0].sealedCredentials;
  assert.ok(!sealed.includes(fixture.password) && !sealed.includes(fixture.ca));
  const input = {
    name: "ESXi fixture host",
    type: "esxi",
    vendor: "vmware",
    host: fixture.host,
    managementPort: fixture.port,
    protocol: "api",
    companyId: admin.id,
    apiCredentialId: credentialId,
    environment: "lab",
    tags: [],
  };
  const draft = () => call("/devices/draft-connection", { ...auth, body: { device: input } });
  let proof = await draft();
  assert.equal(proof.status, 201, JSON.stringify(proof.body));
  assert.equal(proof.body.identity.FirmwareVersion, "8.0.3 build-24022510");
  assert.equal(fixture.sessions.size, 0);
  assert.ok(fixture.calls.includes("Logout"));
  assert.equal(
    (
      await call("/devices", {
        ...auth,
        body: { ...input, host: "192.0.2.8", verificationToken: proof.body.verificationToken },
      })
    ).status,
    400,
  );
  const created = await call("/devices", {
    ...auth,
    body: { ...input, verificationToken: proof.body.verificationToken },
  });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const path = "/devices/" + created.body.id;
  assert.equal(created.body.verification.identity.Model, "Fixture Server");
  assert.equal(
    (await call(path + "/esxi-inventory", { token: other.token, body: {} })).status,
    404,
  );
  assert.equal(
    (await call(path + "/esxi-inventory", { token: employee.token, body: {} })).status,
    403,
  );
  const report = await call(path + "/esxi-inventory", { ...auth, body: {} });
  assert.equal(report.status, 201, JSON.stringify(report.body));
  assert.equal(report.body.cpuPercent, 12.5);
  assert.equal(report.body.memoryPercent, 25);
  assert.equal(report.body.vms.length, 2);
  assert.equal(report.body.datastores[0].freeBytes, 53687091200);
  assert.equal(report.body.physicalNics[0].speedMb, 1000);
  assert.equal(report.body.vmkernelNics[0].ip, "192.0.2.10");
  assert.equal(report.body.services[0].key, "TSM-SSH");
  assert.equal(report.body.portGroups[0].vlanId, 20);
  assert.equal(report.body.sensors[0].reading, -5.5);
  assert.ok(!JSON.stringify(report.body).includes(fixture.password));
  assert.ok(!JSON.stringify(report.body).includes("vmware_soap_session"));
  assert.equal(fixture.sessions.size, 0);
  assert.equal((await call(path + "/connection-channels", auth)).body.primary.supported, true);
  assert.equal(
    (await call(path + "/connection-channels/test-primary", { ...auth, body: {} })).body.connected,
    true,
  );
  async function edit(body) {
    return call(credentialPath + "/" + credentialId, { ...auth, method: "PUT", body });
  }
  await edit({ ...credentialBody, password: "wrong-fixture-password" });
  assert.equal((await call(path, auth)).body.verification, null);
  assert.equal((await draft()).status, 502);
  await edit({ ...credentialBody, caCertificate: "" });
  assert.equal((await draft()).body.code, "ESXI_TLS_OR_NETWORK");
  await edit(credentialBody);
  fixture.mode("vcenter");
  assert.equal((await draft()).body.code, "ESXI_NOT_STANDALONE");
  fixture.mode("dtd");
  assert.equal((await draft()).body.code, "ESXI_XML_DTD_FORBIDDEN");
  fixture.mode("normal");
  proof = await draft();
  await edit({ ...credentialBody, name: "Edited after proof" });
  assert.equal(
    (
      await call("/devices", {
        ...auth,
        body: { ...input, verificationToken: proof.body.verificationToken },
      })
    ).status,
    400,
  );
  // A slow real SOAP response lets authorization/configuration change during I/O.
  const observed = fixture.pause(),
    pending = call(path + "/esxi-inventory", { ...auth, body: {} });
  await Promise.race([
    observed,
    new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error("ESXi fixture was not queried")), 8000);
      timer.unref();
    }),
  ]);
  assert.equal((await call(path + "/esxi-inventory", { ...auth, body: {} })).status, 409);
  await edit(credentialBody);
  fixture.release();
  assert.equal((await pending).status, 409);
  assert.equal((await call(path, auth)).body.verification, null);
  assert.equal(fixture.sessions.size, 0);
  const company = (await call("/devices/companies", { ...auth, body: { name: "شرکت دوم SOAP" } }))
    .body;
  assert.equal(
    (await call(path, { ...auth, method: "PUT", body: { ...input, companyId: company.id } }))
      .status,
    200,
  );
  assert.equal((await call(path, auth)).body.apiCredentialId, null);
  assert.equal(
    (
      await call(path + "/api-credential", {
        token: employee.token,
        method: "PUT",
        body: { credentialId },
      })
    ).status,
    403,
  );
  assert.equal(
    (await call(path + "/api-credential", { ...auth, method: "PUT", body: { credentialId } }))
      .status,
    200,
  );
  assert.equal((await call(path + "/esxi-inventory", { ...auth, body: {} })).status, 201);
  await call(path, { ...auth, method: "DELETE" });
  assert.equal((await call(path + "/esxi-inventory", { ...auth, body: {} })).status, 404);
  await call(path + "/restore", { ...auth, body: {} });
  await call(credentialPath + "/" + credentialId, { ...auth, method: "DELETE" });
  const detached = (await call(path, auth)).body;
  assert.equal(detached.apiCredentialId, null);
  assert.equal(detached.verification, null);
  // Employee registration uses their own credential within the shared company workspace.
  const employeeCredential = await call(credentialPath, {
    token: employee.token,
    body: credentialBody,
  });
  const employeeInput = {
    ...input,
    apiCredentialId: employeeCredential.body.id,
  };
  await call(path, { ...auth, method: "DELETE" });
  const employeeProof = await call("/devices/draft-connection", {
    token: employee.token,
    body: { device: employeeInput },
  });
  assert.equal(employeeProof.status, 201);
  assert.equal(
    (
      await call("/devices", {
        token: employee.token,
        body: { ...employeeInput, verificationToken: employeeProof.body.verificationToken },
      })
    ).status,
    201,
  );
  console.log(
    "PASS ESXi: independent HTTPS/SOAP fixture, verified CA, login/logout, host/VM/datastore/network/sensor discovery, encrypted reusable credentials, draft proof, revocation races, tenant/role/company/archive boundaries",
  );
} finally {
  fixture.release();
  for (const id of users.reverse()) await db?.getRepository(AppUser).delete(id);
  await app?.close();
  await fixture.close();
}
