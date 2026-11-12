import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
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
  { fortiAdminActions } = require("../dist/modules/devices/fortigate-admin.js");
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
    if (r.status === 429) {
      await new Promise((resolve) =>
        setTimeout(
          resolve,
          Math.max(1000, Number(r.headers.get("retry-after") ?? 60) * 1000 + 100),
        ),
      );
      return call(path, { token, body, method });
    }
    return { status: r.status, body: await r.json() };
  }
  async function account(role, owner) {
    const r = await call("/auth/register", {
      body: {
        username: "admtest_" + randomBytes(6).toString("hex"),
        password: "Fixture-auth-2026!",
        displayName: "آزمون مدیریت",
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
  const credential = await call("/devices/credentials", {
    ...auth,
    body: {
      name: "Admin SSH",
      operation: "verify",
      username: fixture.username,
      password: fixture.password,
      hostKey: fixture.hostKey,
    },
  });
  assert.equal(credential.status, 201);
  const device = {
    name: "Admin fixture",
    type: "fortigate",
    vendor: "fortinet",
    host: fixture.host,
    managementPort: fixture.port,
    protocol: "ssh",
    environment: "lab",
    tags: [],
    companyId: admin.id,
    credentialId: credential.body.id,
  };
  const created = await call("/devices", { ...auth, body: device });
  assert.equal(created.status, 201);
  const id = created.body.id,
    path = `/devices/${id}/actions`,
    secrets = "/devices/action-secrets",
    actor = await db.getRepository(AppUser).findOneByOrFail({ id: admin.id }),
    service = app.get(DeviceActionsService);
  const password = 'Synthetic "secret" \\ admin تست 2026!',
    secretBody = { name: "Local admin", purpose: "admin_password", value: password };
  assert.equal((await call(secrets)).status, 401);
  const saved = await call(secrets, { ...auth, body: secretBody });
  assert.equal(saved.status, 201);
  let secret = saved.body;
  assert.deepEqual(Object.keys(secret).sort(), ["id", "name", "purpose", "revision"]);
  const stored = (
    await db.query(`SELECT * FROM device_action_secrets WHERE id=$1`, [secret.id])
  )[0];
  assert.ok(!stored.sealedValue.includes(password));
  assert.deepEqual((await call(secrets, { token: other.token })).body, []);
  assert.equal(
    (
      await call(secrets + "/" + secret.id, {
        token: other.token,
        method: "PUT",
        body: { ...secretBody, revision: secret.revision },
      })
    ).status,
    404,
  );
  assert.equal(
    (await call(secrets + "/" + secret.id, { ...auth, method: "PUT", body: secretBody })).status,
    409,
  );
  assert.equal(
    (
      await call(secrets + "/" + secret.id, {
        ...auth,
        method: "DELETE",
        body: { revision: randomBytes(16).toString("hex") },
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await call(secrets, {
        ...auth,
        body: { ...secretBody, name: "invalid", value: "line\nbreak" },
      })
    ).status,
    400,
  );
  const employeeSecret = await call(secrets, {
    token: employee.token,
    body: { ...secretBody, name: "Employee private" },
  });
  assert.equal(employeeSecret.status, 201);
  assert.equal((await call(secrets, auth)).body.length, 1);
  const newInput = {
    action: "admin.create",
    name: "new-admin",
    value: "",
    adminProfile: "limited",
    accountVdoms: "root,tenant",
    adminSecretId: secret.id,
  };
  const before = fixture.controlWrites.length;
  assert.equal(
    (await call(path + "/preview", { token: employee.token, body: newInput })).status,
    403,
  );
  assert.equal((await call(path + "/preview", { token: other.token, body: newInput })).status, 404);
  assert.equal(
    (
      await call(path + "/preview", {
        ...auth,
        body: { ...newInput, adminSecretId: employeeSecret.body.id },
      })
    ).status,
    404,
  );
  assert.equal(
    (await call(path + "/preview", { ...auth, body: { ...newInput, password } })).status,
    400,
  );
  assert.equal(
    (await call(path + "/preview", { ...auth, body: { ...newInput, secretFingerprint: "spoof" } }))
      .status,
    400,
  );
  const p = await call(path + "/preview", { ...auth, body: newInput });
  assert.equal(p.status, 201, JSON.stringify(p.body));
  assert.equal(fixture.controlWrites.length, before);
  assert.equal(p.body.vdom, "global");
  assert.ok(p.body.commands.includes("config global"));
  assert.ok(!JSON.stringify(p.body).includes(password));
  assert.equal(p.body.after.__password, "configured");
  const plan = (await db.query(`SELECT * FROM device_action_plans WHERE id=$1`, [p.body.id]))[0];
  assert.ok(!JSON.stringify(plan).includes(password));
  const result = await call(path + `/${p.body.id}/execute`, {
    ...auth,
    body: { intent: "execute", confirmed: true },
  });
  assert.equal(result.body.status, "succeeded", JSON.stringify(result.body));
  assert.equal(
    fixture.controlTables["system admin"]["new-admin"].password,
    "ENC " + createHash("sha256").update(password).digest("hex"),
  );
  assert.equal(
    (
      await call(path + `/${p.body.id}/execute`, {
        ...auth,
        body: { intent: "execute", confirmed: true },
      })
    ).status,
    409,
  );
  assert.ok(!JSON.stringify((await call(path, auth)).body).includes(password));
  const covered = new Set(["admin.create"]);
  async function preview(body) {
    if (covered.has(body.action)) return service.preview(actor, id, { value: "", ...body });
    const r = await call(path + "/preview", { ...auth, body: { value: "", ...body } });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    return r.body;
  }
  async function apply(body) {
    const p = await preview(body),
      r = await call(path + `/${p.id}/execute`, {
        ...auth,
        body: { intent: "execute", confirmed: true },
      });
    assert.equal(
      r.body.status,
      "succeeded",
      JSON.stringify({ action: body.action, result: r.body }),
    );
    covered.add(body.action);
    return p;
  }
  const trust = await apply({
    action: "admin.trusthost",
    name: "new-admin",
    value: "198.51.100.23",
  });
  assert.equal(trust.after.trusthost1, "198.51.100.23 255.255.255.255");
  const https = await apply({
    action: "management.httpsPort",
    name: "system",
    value: "8443",
    vdom: "invalid",
  });
  assert.equal(https.before["admin-sport"], "443");
  assert.equal(fixture.controlSystem["system global"]["admin-sport"], "8443");
  for (const value of ["telnet", "ssh-v1", "ssh-password", "scp"])
    await apply({ action: "management.disableService", name: "system", value });
  assert.equal(fixture.controlSystem["system global"]["admin-scp"], "disable");
  const api = await apply({
    action: "apiUser.create",
    name: "automation",
    adminProfile: "prof_admin",
    accountVdoms: "root",
  });
  assert.ok(api.message.includes("تولید یا نمایش داده نمی‌شود"));
  assert.equal(fixture.controlTables["system api-user"].automation["api-key"], undefined);
  const writes = fixture.controlWrites.length;
  const unsupported = await call(path + "/preview", {
    ...auth,
    body: { action: "admin.disable", name: "new-admin", value: "" },
  });
  assert.equal(unsupported.status, 400);
  assert.ok(unsupported.body.message.includes("۸"));
  assert.equal(fixture.controlWrites.length, writes);
  const v7 = fixture.outputs["get system status"];
  fixture.outputs["get system status"] = v7.replace(/v7\.\d+\.\d+/, "v8.0.0");
  await apply({ action: "admin.disable", name: "new-admin" });
  assert.equal(
    fixture.controlTables["system admin"]["new-admin"]["disallowed-login-methods"],
    "console gui ssh telnet",
  );
  fixture.outputs["get system status"] = v7;
  for (const body of [
    { ...newInput, name: "operator" },
    { ...newInput, name: "bad-profile", adminProfile: "absent" },
    { ...newInput, name: "bad-vdom", accountVdoms: "absent" },
    { action: "admin.trusthost", name: "absent", value: "192.0.2.1" },
    { action: "management.disableService", name: "system", value: "http" },
    { action: "management.httpsPort", name: "system", value: "65536" },
    { action: "admin.delete", name: 'bad"\nend', value: "" },
  ])
    await assert.rejects(service.preview(actor, id, body), (e) => e.getStatus?.() === 400);
  const deletePlan = await apply({ action: "admin.delete", name: "new-admin" });
  assert.ok(!JSON.stringify(deletePlan.before).includes("ENC"));
  assert.equal(fixture.controlTables["system admin"]["new-admin"], undefined);
  const pendingPlan = await service.preview(actor, id, { ...newInput, name: "pending-account" });
  fixture.mode("control-incomplete-readback");
  const pending = await service.execute(actor, id, pendingPlan.id, {
    intent: "execute",
    confirmed: true,
  });
  assert.equal(pending.status, "verification_pending");
  fixture.mode("normal");
  const beforeVerify = fixture.controlWrites.length;
  const recovered = await service.verify(actor, id, pendingPlan.id);
  assert.equal(recovered.status, "succeeded");
  assert.equal(fixture.controlWrites.length, beforeVerify);
  const raced = await service.preview(actor, id, { ...newInput, name: "race-account" });
  const originalTarget = service.target,
    nextRevision = randomUUID(),
    beforeRace = fixture.controlWrites.length;
  let targetCalls = 0;
  service.target = async function (...args) {
    const target = await originalTarget.apply(this, args);
    if (++targetCalls === 2)
      await db.query(`UPDATE device_action_secrets SET revision=$2 WHERE id=$1`, [
        secret.id,
        nextRevision,
      ]);
    return target;
  };
  try {
    const blocked = await service.execute(actor, id, raced.id, {
      intent: "execute",
      confirmed: true,
    });
    assert.equal(blocked.status, "failed");
    assert.equal(blocked.connectorInvoked, false);
    assert.equal(blocked.verified, false);
  } finally {
    service.target = originalTarget;
  }
  secret = { ...secret, revision: nextRevision };
  assert.equal(fixture.controlWrites.length, beforeRace);
  assert.equal(
    (await db.query(`SELECT status FROM device_action_plans WHERE id=$1`, [raced.id]))[0].status,
    "failed",
  );
  const stale = await preview({ ...newInput, name: "stale-secret" });
  const updated = await call(secrets + "/" + secret.id, {
    ...auth,
    method: "PUT",
    body: { ...secretBody, value: "Changed-fixture-only!", revision: secret.revision },
  });
  assert.equal(updated.status, 200);
  secret = updated.body;
  const attempts = fixture.controlWrites.length;
  await assert.rejects(
    service.execute(actor, id, stale.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 409,
  );
  assert.equal(fixture.controlWrites.length, attempts);
  // Ownership/purpose are AEAD-bound, so copied ciphertext cannot be used through another secret.
  const copied = await call(secrets, {
    ...auth,
    body: { ...secretBody, name: "Copied ciphertext" },
  });
  await db.query(`UPDATE device_action_secrets SET "sealedValue"=$2 WHERE id=$1`, [
    copied.body.id,
    stored.sealedValue,
  ]);
  assert.equal(
    (
      await call(path + "/preview", {
        ...auth,
        body: { ...newInput, name: "bad-envelope", adminSecretId: copied.body.id },
      })
    ).status,
    409,
  );
  const psk = await call(secrets, {
    ...auth,
    body: { ...secretBody, name: "Wrong purpose", purpose: "ipsec_psk" },
  });
  assert.equal(
    (
      await call(path + "/preview", {
        ...auth,
        body: { ...newInput, name: "bad-purpose", adminSecretId: psk.body.id },
      })
    ).status,
    404,
  );
  const deletedPreview = await preview({ ...newInput, name: "deleted-secret" });
  assert.equal(
    (
      await call(secrets + "/" + secret.id, {
        ...auth,
        method: "DELETE",
        body: { revision: saved.body.revision },
      })
    ).status,
    409,
  );
  assert.equal(
    (
      await call(secrets + "/" + secret.id, {
        ...auth,
        method: "DELETE",
        body: { revision: secret.revision },
      })
    ).status,
    200,
  );
  await assert.rejects(
    service.execute(actor, id, deletedPreview.id, { intent: "execute", confirmed: true }),
    (e) => e.getStatus?.() === 404,
  );
  assert.deepEqual([...covered].sort(), [...fortiAdminActions].sort());
  console.log(
    "Forti admin API: 7 actions, local encrypted-password execution without disclosure, personal revisioned AEAD vault, existing profiles/VDOMs, global HTTPS/native service settings, API config without key, native FortiOS8 disable and explicit v7 refusal, trusthost/delete, stale/deleted secret rejection, second-phase secret race without write, pending read-only recovery and tenant/role boundaries passed.",
  );
} finally {
  fixture.release();
  if (db && users.length) await db.getRepository(AppUser).delete(users);
  if (app) await app.close();
  await fixture.close();
}
