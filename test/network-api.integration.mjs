import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import "reflect-metadata";
import { config } from "dotenv";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
import { networkApiFixture } from "./fixtures/network-api-server.mjs";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js");
const fixture = await networkApiFixture(),
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
        username: "network_api_" + randomBytes(6).toString("hex"),
        password: "Network-Api-Fixture-2026!",
        displayName: "تست API شبکه",
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
      name: "Network API",
      username: fixture.username,
      password: fixture.password,
      caCertificate: fixture.ca,
    };
  const credential = await call(credentialPath, { ...auth, body: credentialBody });
  assert.equal(credential.status, 201);
  const credentialId = credential.body.id;
  const baseInput = {
    name: "MikroTik REST fixture",
    type: "mikrotik",
    vendor: "mikrotik",
    host: fixture.host,
    managementPort: fixture.port,
    protocol: "api",
    companyId: admin.id,
    apiCredentialId: credentialId,
    environment: "lab",
    tags: [],
  };
  async function draft(input, token = admin.token) {
    return call("/devices/draft-connection", { token, body: { device: input } });
  }
  let proof = await draft(baseInput);
  assert.equal(proof.status, 201, JSON.stringify(proof.body));
  assert.equal(proof.body.identity.FirmwareVersion, "7.20.1 (stable)");
  const created = await call("/devices", {
    ...auth,
    body: { ...baseInput, verificationToken: proof.body.verificationToken },
  });
  assert.equal(created.status, 201);
  const path = "/devices/" + created.body.id,
    inspect = path + "/api-inventory";
  assert.equal((await call(inspect, { token: employee.token, body: {} })).status, 403);
  assert.equal((await call(inspect, { token: other.token, body: {} })).status, 404);
  const beforeWrongKind = fixture.calls.length;
  assert.equal((await call(inspect, { ...auth, body: { kind: "sophos" } })).status, 400);
  assert.equal((await call(inspect, { ...auth, body: { kind: "invalid" } })).status, 400);
  assert.equal(fixture.calls.length, beforeWrongKind);
  let report = await call(inspect, { ...auth, body: {} });
  assert.equal(report.status, 201, JSON.stringify(report.body));
  assert.equal(report.body.kind, "mikrotik");
  assert.equal(report.body.cpuLoad, 15);
  assert.equal(report.body.memoryTotal, 134217728);
  assert.equal(report.body.sections.routes[0].gateway, "192.0.2.254");
  assert.equal(report.body.sections.arp[0].interface, "ether1");
  assert.equal(report.body.interfaceCounters.length, 1);
  assert.equal(report.body.interfaceCounters[0].rxBytes, 123456);
  assert.ok(!JSON.stringify(report.body).includes(fixture.password));
  assert.ok(!JSON.stringify(report.body).includes("NEVER_RETURN"));
  assert.ok(report.body.sections.logs[0].message.includes("[redacted]"));
  assert.equal((await call(path + "/esxi-inventory", { ...auth, body: {} })).status, 400);
  assert.equal(
    (await call(path + "/connection-channels/test-primary", { ...auth, body: {} })).body.connected,
    true,
  );
  fixture.mode("partial");
  report = await call(inspect, { ...auth, body: {} });
  assert.equal(report.status, 201);
  assert.equal(report.body.warnings[0].section, "logs");
  assert.equal(report.body.sections.logs.length, 0);
  fixture.mode("unknownFields");
  report = await call(inspect, { ...auth, body: {} });
  assert.equal(report.body.warnings[0].code, "MIKROTIK_INVALID_RESPONSE");
  fixture.mode("shape");
  assert.equal((await draft(baseInput)).body.code, "MIKROTIK_INVALID_RESPONSE");
  fixture.mode("malformed");
  assert.equal((await draft(baseInput)).body.code, "MIKROTIK_INVALID_JSON");
  fixture.mode("fakeIdentity");
  assert.equal((await draft(baseInput)).body.code, "MIKROTIK_IDENTITY_UNCONFIRMED");
  fixture.mode("redirect");
  assert.equal((await draft(baseInput)).body.code, "API_HTTP_ERROR");
  fixture.mode("normal");
  const sophosInput = {
    ...baseInput,
    name: "Sophos XML fixture",
    type: "generic_firewall",
    vendor: "sophos",
  };
  proof = await draft(sophosInput);
  assert.equal(proof.status, 201, JSON.stringify(proof.body));
  assert.equal(proof.body.identity.ApiVersion, "2000.1");
  const sophos = await call("/devices", {
    ...auth,
    body: { ...sophosInput, verificationToken: proof.body.verificationToken },
  });
  assert.equal(sophos.status, 201);
  const sophosPath = "/devices/" + sophos.body.id,
    sophosInspect = sophosPath + "/api-inventory";
  report = await call(sophosInspect, { ...auth, body: {} });
  assert.equal(report.status, 201, JSON.stringify(report.body));
  assert.equal(report.body.kind, "sophos");
  assert.equal(report.body.interfaces[0].name, "Port <2> & local");
  assert.equal(report.body.interfaces[0].operationalStatus, "up");
  assert.equal(report.body.interfaces[0].administrativeStatus, "down");
  assert.equal(report.body.zones[0], "LAN");
  assert.equal(report.body.gateways.length, 0);
  assert.equal(report.body.firewallRules[0].status, "enabled");
  assert.equal(report.body.services[0].ports[0], "443");
  assert.equal(report.body.vpnConnections[0].runtimeState, "unknown");
  assert.deepEqual(report.body.vpnProfiles[0].phase1Encryption, ["AES256"]);
  assert.equal(report.body.collectedModules.length, 8);
  assert.ok(!JSON.stringify(report.body).includes("NEVER_RETURN"));
  fixture.mode("partial");
  report = await call(sophosInspect, { ...auth, body: {} });
  assert.equal(report.status, 201);
  assert.equal(report.body.collectionWarnings.length, 1);
  assert.ok(!report.body.collectedModules.includes("VPNProfile"));
  fixture.mode("missing");
  assert.equal((await draft(sophosInput)).body.code, "SOPHOS_DISCOVERY_UNAVAILABLE");
  fixture.mode("dtd");
  assert.equal((await draft(sophosInput)).body.code, "SOPHOS_INVALID_XML");
  fixture.mode("normal");
  const edit = (body) =>
    call(credentialPath + "/" + credentialId, { ...auth, method: "PUT", body });
  await edit({ ...credentialBody, password: "wrong-fixture-password" });
  assert.equal((await draft(baseInput)).body.code, "API_AUTH_FAILED");
  assert.equal((await draft(sophosInput)).body.code, "SOPHOS_AUTH_FAILED");
  await edit({ ...credentialBody, caCertificate: "" });
  assert.equal((await draft(baseInput)).body.code, "API_TLS_OR_NETWORK");
  assert.equal((await draft(sophosInput)).body.code, "API_TLS_OR_NETWORK");
  assert.equal(
    (await edit({ ...credentialBody, tlsFingerprint: fixture.fingerprint })).status,
    400,
  );
  assert.equal(
    (
      await edit({
        ...credentialBody,
        caCertificate: "",
        tlsFingerprint: "SHA256:" + fixture.fingerprint,
      })
    ).status,
    200,
  );
  assert.equal((await draft(sophosInput)).status, 201);
  assert.equal((await draft(baseInput)).body.code, "API_TLS_PIN_NOT_SUPPORTED");
  await edit({ ...credentialBody, caCertificate: "", tlsFingerprint: "0".repeat(64) });
  const count = fixture.calls.length;
  assert.equal((await draft(sophosInput)).body.code, "SOPHOS_TLS_FINGERPRINT_MISMATCH");
  assert.equal(fixture.calls.length, count);
  await edit(credentialBody);
  // Required resource response arrives after a tenant mutation, so its old proof must be discarded.
  const observed = fixture.pause("mikrotik"),
    pending = call(inspect, { ...auth, body: {} });
  await Promise.race([
    observed,
    new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error("Fixture was not queried")), 8000);
      timer.unref();
    }),
  ]);
  assert.equal((await call(inspect, { ...auth, body: {} })).status, 409);
  await call(path, { ...auth, method: "DELETE" });
  fixture.release();
  assert.equal((await pending).status, 409);
  await call(path + "/restore", { ...auth, body: {} });
  const company = (await call("/devices/companies", { ...auth, body: { name: "شرکت API دوم" } }))
    .body;
  assert.equal(
    (
      await call(sophosPath, {
        ...auth,
        method: "PUT",
        body: { ...sophosInput, companyId: company.id },
      })
    ).status,
    200,
  );
  assert.equal((await call(sophosPath, auth)).body.apiCredentialId, null);
  await call(credentialPath + "/" + credentialId, { ...auth, method: "DELETE" });
  assert.equal((await call(path, auth)).body.apiCredentialId, null);
  assert.equal((await call(path, auth)).body.verification, null);
  assert.ok(
    fixture.calls
      .filter((item) => item.path.startsWith("/rest/"))
      .every((item) => item.method === "GET"),
  );
  console.log(
    "PASS network API: independent verified HTTPS REST/XML, RouterOS inventory/counters/neighbors, per-module Sophos discovery and partial failures, CDATA/entities, secret projection, CA/pin with no HTTP on mismatch, auth/identity errors, tenancy/roles, archive race and company transfer",
  );
} finally {
  fixture.release();
  for (const id of users.reverse()) await db?.getRepository(AppUser).delete(id);
  await app?.close();
  await fixture.close();
}
