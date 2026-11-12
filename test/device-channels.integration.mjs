import assert from "node:assert/strict";
import { randomBytes, generateKeyPairSync } from "node:crypto";
import { createSocket } from "node:dgram";
import { once } from "node:events";
import { createRequire } from "node:module";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
import snmp from "net-snmp";
import ssh2 from "ssh2";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js");
const users = [],
  clients = new Set();
let app,
  db,
  agent,
  ssh,
  held = false,
  requests = [],
  observed;
function release() {
  held = false;
  for (const request of requests.splice(0)) request.done();
}
try {
  // An actual authPriv UDP agent, not a stubbed collector. It uses net-snmp on both ends.
  const reserve = createSocket("udp4");
  reserve.bind(0, "127.0.0.1");
  await once(reserve, "listening");
  const port = reserve.address().port;
  await new Promise((resolve) => reserve.close(resolve));
  agent = snmp.createAgent(
    { address: "127.0.0.1", port, accessControlModelType: snmp.AccessControlModelType.Simple },
    () => {},
  );
  const secret = {
    username: "fixture_snmp",
    authProtocol: "SHA256",
    authPassword: "fixture-auth-2026",
    privacyPassword: "fixture-privacy-2026",
  };
  const { pollSnmpv3 } = require("../dist/modules/devices/snmpv3.js");
  agent.getAuthorizer().addUser({
    name: secret.username,
    level: snmp.SecurityLevel.authPriv,
    authProtocol: snmp.AuthProtocols.sha256,
    authKey: secret.authPassword,
    privProtocol: snmp.PrivProtocols.aes,
    privKey: secret.privacyPassword,
  });
  for (const [name, oid, type, value] of [
    ["sysName", "1.3.6.1.2.1.1.5", snmp.ObjectType.OctetString, "fixture-switch"],
    ["sysUpTime", "1.3.6.1.2.1.1.3", snmp.ObjectType.TimeTicks, 9876500],
    ["ifNumber", "1.3.6.1.2.1.2.1", snmp.ObjectType.Integer, 24],
  ]) {
    agent.getMib().registerProvider({
      name,
      oid,
      type: snmp.MibProviderType.Scalar,
      scalarType: type,
      maxAccess: snmp.MaxAccess["read-only"],
      handler: (request) => {
        if (held) {
          requests.push(request);
          observed?.();
        } else request.done();
      },
    });
    agent.getMib().setScalarValue(name, value);
  }
  const shaSecret = { ...secret, username: "fixture_sha", authProtocol: "SHA" };
  agent.getAuthorizer().addUser({
    name: shaSecret.username,
    level: snmp.SecurityLevel.authPriv,
    authProtocol: snmp.AuthProtocols.sha,
    authKey: shaSecret.authPassword,
    privProtocol: snmp.PrivProtocols.aes,
    privKey: shaSecret.privacyPassword,
  });
  assert.equal((await pollSnmpv3("127.0.0.1", port, shaSecret)).interfaceCount, 24);
  await assert.rejects(
    pollSnmpv3("127.0.0.1", port, { ...shaSecret, privacyPassword: "wrong-privacy-password" }),
  );
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
  });
  const parsed = ssh2.utils.parseKey(privateKey),
    hostKey = parsed.type + " " + parsed.getPublicSSH().toString("base64");
  ssh = new ssh2.Server({ hostKeys: [privateKey] }, (client) => {
    clients.add(client);
    client.on("error", () => {});
    client.on("close", () => clients.delete(client));
    client.on("authentication", (ctx) =>
      ctx.method === "password" && ctx.username === "fixture" && ctx.password === "fixture-password"
        ? ctx.accept()
        : ctx.reject(),
    );
    client.on("ready", () =>
      client.on("session", (accept) =>
        accept().on("exec", (accept, reject, info) => {
          if (info.command !== "vmware -v") {
            reject();
            return;
          }
          const stream = accept();
          stream.write("VMware ESXi 8.0.3 build-24022510\n");
          stream.exit(0);
          stream.end();
        }),
      ),
    );
  });
  ssh.listen(0, "127.0.0.1");
  await once(ssh, "listening");
  app = await NestFactory.create(AppModule, { logger: false });
  app.setGlobalPrefix("api/v1");
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
  await app.listen(0, "127.0.0.1");
  db = app.get(DataSource);
  const base = (await app.getUrl()) + "/api/v1";
  async function call(path, { token, body, method = body === undefined ? "GET" : "POST" } = {}) {
    const res = await fetch(base + path, {
      method,
      headers: {
        ...(token ? { authorization: "Bearer " + token } : {}),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: await res.json(), cache: res.headers.get("cache-control") };
  }
  async function account(role, owner) {
    const res = await call("/auth/register", {
      body: {
        username: "channels_" + randomBytes(6).toString("hex"),
        password: "Channels-Fixture-2026!",
        displayName: "تست کانال اتصال",
      },
    });
    assert.equal(res.status, 201);
    users.push(res.body.user.id);
    await db
      .getRepository(AppUser)
      .update(res.body.user.id, { role, workspaceOwnerId: owner ?? null });
    return { id: res.body.user.id, token: res.body.accessToken };
  }
  const admin = await account("co_admin"),
    foreign = await account("co_admin"),
    employee = await account("co_employee", admin.id),
    auth = { token: admin.token };
  await call("/devices/companies", auth);
  const input = {
    name: "Channel fixture",
    type: "cisco",
    vendor: "cisco",
    host: "127.0.0.1",
    managementPort: 22,
    protocol: "ssh",
    environment: "lab",
    tags: [],
    companyId: admin.id,
  };
  const created = await call("/devices", { ...auth, body: input });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const id = created.body.id,
    path = `/devices/${id}/connection-channels`,
    credentialPath = "/devices/snmp-credentials";
  assert.equal((await call(path)).status, 401);
  assert.equal((await call(path, { token: foreign.token })).status, 404);
  assert.equal(
    (
      await call(credentialPath, {
        ...auth,
        body: { name: "bad", ...secret, authPassword: "short" },
      })
    ).status,
    400,
  );
  const saved = await call(credentialPath, { ...auth, body: { name: "SNMP Fixture", ...secret } });
  assert.equal(saved.status, 201, JSON.stringify(saved.body));
  assert.deepEqual(
    Object.keys(saved.body).sort(),
    ["id", "name", "username", "authProtocol"].sort(),
  );
  const encrypted = (
    await db.query(`SELECT "sealedCredentials" FROM "device_snmp_credentials" WHERE "id"=$1`, [
      saved.body.id,
    ])
  )[0].sealedCredentials;
  assert.ok(
    !encrypted.includes(secret.authPassword) && !encrypted.includes(secret.privacyPassword),
  );
  assert.equal((await call(credentialPath, { token: foreign.token })).body.length, 0);
  assert.equal(
    (await call(`${credentialPath}/${saved.body.id}`, { token: foreign.token, method: "DELETE" }))
      .status,
    404,
  );
  const config = { method: "snmpv3", credentialId: saved.body.id, port, priority: 2 };
  assert.equal(
    (await call(path, { token: employee.token, method: "PUT", body: config })).status,
    403,
  );
  const outside = await call(credentialPath, {
    token: foreign.token,
    body: { name: "Other", ...secret },
  });
  assert.equal(
    (
      await call(path, {
        ...auth,
        method: "PUT",
        body: { ...config, credentialId: outside.body.id },
      })
    ).status,
    404,
  );
  let configured = await call(path, { ...auth, method: "PUT", body: config });
  assert.equal(configured.status, 200, JSON.stringify(configured.body));
  assert.equal(configured.body.secondary.enabled, false);
  assert.equal((await call(path, { ...auth, method: "PUT", body: config })).status, 409);
  assert.equal(configured.body.primary.status, "configured");
  assert.match(configured.cache, /no-store/);
  assert.equal(
    (
      await call(path + "/state", {
        ...auth,
        method: "PUT",
        body: { enabled: true, revision: configured.body.secondary.revision },
      })
    ).status,
    409,
  );
  const test = () => call(path + "/test-secondary", { ...auth, body: {} });
  let result = await test();
  assert.equal(result.status, 201, JSON.stringify(result.body));
  assert.equal(result.body.connected, true, JSON.stringify(result.body));
  let state = (await call(path, auth)).body;
  assert.equal(state.secondary.status, "verified");
  assert.equal(state.secondary.enabled, true);
  assert.equal(state.primary.status, "configured");
  assert.equal(state.preferred, "observability");
  assert.deepEqual(state.secondary.telemetry, {
    sysName: "fixture-switch",
    uptimeSeconds: 98765,
    interfaceCount: 24,
  });
  for (let i = 0; i < 5; i++) assert.equal((await test()).body.connected, true);
  state = (await call(path, auth)).body;
  assert.equal(state.history.length, 5);
  const [count] = await db.query(
    `SELECT count(*)::integer AS count FROM "device_channel_tests" WHERE "deviceId"=$1`,
    [id],
  );
  assert.equal(count.count, 5);
  assert.ok(!JSON.stringify(state).includes(secret.authPassword));
  assert.ok(!JSON.stringify(state).includes("verifiedBinding"));
  result = await call(path + "/state", {
    ...auth,
    method: "PUT",
    body: { enabled: false, revision: state.secondary.revision },
  });
  assert.equal(result.body.secondary.enabled, false);
  assert.equal(result.body.secondary.status, "verified");
  assert.equal(
    (
      await call(path + "/state", {
        ...auth,
        method: "PUT",
        body: { enabled: true, revision: state.secondary.revision },
      })
    ).body.secondary.enabled,
    true,
  );
  // Credential edits invalidate old proof immediately, and a wrong authPriv key cannot pass.
  await call(`${credentialPath}/${saved.body.id}`, {
    ...auth,
    method: "PUT",
    body: { name: "SNMP Fixture", ...secret, authPassword: "wrong-auth-password" },
  });
  state = (await call(path, auth)).body;
  assert.equal(state.secondary.enabled, false);
  assert.equal(state.secondary.telemetry, null);
  assert.equal(state.secondary.status, "configured");
  result = await test();
  assert.equal(result.body.connected, false);
  assert.match(result.body.errorCode, /^SNMP_/);
  state = (await call(path, auth)).body;
  assert.equal(state.secondary.status, "error");
  assert.ok(state.secondary.lastSuccessAt);
  assert.equal(state.secondary.enabled, false);
  await call(`${credentialPath}/${saved.body.id}`, {
    ...auth,
    method: "PUT",
    body: { name: "SNMP Fixture", ...secret },
  });
  assert.equal((await test()).body.connected, true);
  // Revocation during in-flight I/O must discard the result, not recreate a proof.
  let duplicateChecked = false;
  async function pausedTest(mutate) {
    held = true;
    const seen = new Promise((resolve) => {
      observed = resolve;
    });
    const pending = test();
    await Promise.race([
      seen,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("SNMP fixture not queried")), 6000),
      ),
    ]);
    if (!duplicateChecked) {
      assert.equal((await test()).status, 409);
      const active = (await call(path, auth)).body.secondary;
      assert.equal(
        (
          await call(path + "/state", {
            ...auth,
            method: "PUT",
            body: { enabled: false, revision: active.revision },
          })
        ).status,
        409,
      );
      duplicateChecked = true;
    }
    await mutate();
    release();
    observed = undefined;
    const outcome = await pending;
    assert.ok([403, 404, 409].includes(outcome.status), JSON.stringify(outcome));
  }
  await pausedTest(async () => {
    await call(`${credentialPath}/${saved.body.id}`, {
      ...auth,
      method: "PUT",
      body: { name: "Updated during test", ...secret },
    });
  });
  assert.equal((await call(path, auth)).body.secondary.enabled, false);
  await test();
  await pausedTest(async () => {
    await call(`/devices/${id}`, { ...auth, method: "DELETE" });
  });
  assert.equal((await call(path, auth)).status, 404);
  assert.equal((await call(`/devices/${id}/restore`, { ...auth, body: {} })).status, 201);
  await test();
  await pausedTest(async () => {
    await db.getRepository(AppUser).update(admin.id, { role: "co_employee" });
  });
  await db.getRepository(AppUser).update(admin.id, { role: "co_admin" });
  const company = (
    await call("/devices/companies", { ...auth, body: { name: "شرکت انتقال کانال" } })
  ).body;
  await pausedTest(async () => {
    const transfer = await call(`/devices/${id}`, {
      ...auth,
      method: "PUT",
      body: { ...input, companyId: company.id },
    });
    assert.equal(transfer.status, 200);
  });
  state = (await call(path, auth)).body;
  assert.equal(state.secondary.credentialId, null);
  assert.equal(state.secondary.needsCredential, true);
  assert.equal(state.secondary.enabled, false);
  assert.equal(
    (
      await call(path, {
        ...auth,
        method: "PUT",
        body: { ...config, priority: 1, revision: state.secondary.revision },
      })
    ).status,
    200,
  );
  assert.equal((await test()).body.connected, true);
  assert.equal(
    (await call(`${credentialPath}/${saved.body.id}`, { ...auth, method: "DELETE" })).status,
    200,
  );
  state = (await call(path, auth)).body;
  assert.equal(state.secondary.enabled, false);
  assert.equal(state.secondary.needsCredential, true);
  assert.equal((await test()).status, 404);
  // ESXi's API endpoint must not be reused as its secondary SSH port.
  const esxi = await call("/devices", {
    ...auth,
    body: {
      ...input,
      name: "ESXi secondary",
      type: "esxi",
      vendor: "vmware",
      protocol: "api",
      managementPort: 443,
    },
  });
  assert.equal(esxi.status, 201);
  const sshSecret = (
    await call("/devices/credentials", {
      ...auth,
      body: {
        name: "SSH fixture",
        username: "fixture",
        hostKey,
        password: "fixture-password",
        operation: "verify",
      },
    })
  ).body;
  const esxiPath = `/devices/${esxi.body.id}/connection-channels`;
  assert.equal(
    (
      await call(esxiPath, {
        ...auth,
        method: "PUT",
        body: { method: "ssh", credentialId: sshSecret.id, port: ssh.address().port, priority: 2 },
      })
    ).status,
    200,
  );
  const sshTest = await call(esxiPath + "/test-secondary", { ...auth, body: {} });
  assert.equal(sshTest.status, 201, JSON.stringify(sshTest.body));
  assert.equal(sshTest.body.connected, true, JSON.stringify(sshTest.body));
  const esxiState = (await call(esxiPath, auth)).body;
  assert.equal(esxiState.primary.port, 443);
  assert.equal(esxiState.secondary.enabled, true);
  assert.equal(esxiState.primary.status, "configured");
  assert.equal((await call(esxiPath + "/test-primary", { ...auth, body: {} })).status, 400);
  assert.equal((await call(path, { token: employee.token })).status, 200);
  console.log(
    "PASS channels: real authPriv SHA-256/AES UDP, SSH ESXi on separate port, encrypted personal credentials, fresh binding, 5-test retention, roles/tenancy, archive/transfer/revocation races",
  );
} finally {
  release();
  for (const id of users.reverse()) await db?.getRepository(AppUser).delete(id);
  await app?.close();
  agent?.close();
  for (const client of clients) client.end();
  if (ssh) await new Promise((resolve) => ssh.close(resolve));
}
