import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
import { ciscoSshFixture } from "./fixtures/cisco-ssh-server.mjs";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js"),
  { DeviceCapabilitiesService } = require("../dist/modules/devices/device-capabilities.service.js"),
  { DevicesService } = require("../dist/modules/devices/devices.service.js");
const fixture = await ciscoSshFixture({ userExec: true, enablePassword: "enable-owned-test" }),
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
        username: "enable_" + randomBytes(6).toString("hex"),
        password: "Enable-fixture-2026!",
        displayName: "آزمون دسترسی Cisco",
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
  const cred = await call("/devices/credentials", {
    ...auth,
    body: {
      name: "SSH",
      operation: "verify",
      username: fixture.username,
      password: fixture.password,
      hostKey: fixture.hostKey,
    },
  });
  assert.equal(cred.status, 201);
  const enable = await call("/devices/cisco-enable-credentials", {
    ...auth,
    body: { name: "Enable", password: "enable-owned-test" },
  });
  assert.equal(enable.status, 201);
  assert.deepEqual(Object.keys(enable.body).sort(), ["id", "name"]);
  assert.equal((await call("/devices/cisco-enable-credentials")).status, 401);
  assert.deepEqual(
    (await call("/devices/cisco-enable-credentials", { token: employee.token })).body,
    [],
  );
  assert.equal(
    (
      await call(`/devices/cisco-enable-credentials/${enable.body.id}`, {
        token: other.token,
        method: "PUT",
        body: { name: "Foreign", password: "new" },
      })
    ).status,
    404,
  );
  const encrypted = (
    await db.query('SELECT "sealedSecret" FROM cisco_enable_credentials WHERE id=$1', [
      enable.body.id,
    ])
  )[0].sealedSecret;
  assert.ok(!encrypted.includes("enable-owned-test"));
  const input = {
    name: "Cisco enable fixture",
    type: "cisco",
    vendor: "Cisco",
    protocol: "ssh",
    host: fixture.host,
    managementPort: fixture.port,
    environment: "lab",
    tags: [],
    companyId: admin.id,
    credentialId: cred.body.id,
  };
  const initial = await call("/devices", { ...auth, body: input });
  assert.equal(initial.status, 201);
  const id = initial.body.id,
    path = `/devices/${id}/cisco-access`,
    caps = `/devices/${id}/capabilities`;
  let settings = (await call(path, auth)).body;
  assert.equal(settings.compatibilityProfile, "modern");
  assert.equal(settings.enableConfigured, false);
  let result = await call(caps + "/refresh", { ...auth, body: {} });
  assert.equal(result.status, 502);
  assert.equal(result.body.code, "CISCO_ENABLE_REQUIRED");
  const actorForAccess = await db.getRepository(AppUser).findOneByOrFail({ id: admin.id }),
    terminal = app.get(
      require("../dist/modules/devices/device-terminal.service.js").DeviceTerminalService,
    );
  const selected = { compatibilityProfile: "modern", enableCredentialId: enable.body.id };
  assert.equal(
    (await call(path, { token: employee.token, method: "PUT", body: selected })).status,
    403,
  );
  assert.equal((await call(path, { token: other.token })).status, 404);
  result = await call(path, { ...auth, method: "PUT", body: selected });
  assert.equal(result.status, 200);
  settings = result.body;
  assert.ok(settings.revision);
  assert.equal(settings.history[0].action, "profile_changed");
  assert.equal((await call(path, { ...auth, method: "PUT", body: selected })).status, 409);
  const masked = (await call(path, { token: employee.token })).body;
  assert.equal(masked.enableCredentialId, null);
  assert.equal(masked.needsOwnCredential, true);
  assert.ok(!JSON.stringify(masked).includes(enable.body.id));
  result = await call(caps + "/refresh", { ...auth, body: {} });
  assert.equal(result.status, 201);
  assert.equal((await call(caps, auth)).body.ready, true);
  // Proof of registration includes the separate secret and explicit compatibility choice.
  let draft = await call("/devices/draft-connection", {
    ...auth,
    body: {
      device: {
        ...input,
        name: "Verified registration",
        host: "localhost",
        ciscoProfile: selected,
      },
    },
  });
  assert.equal(draft.status, 201);
  assert.equal(draft.body.verified, true);
  assert.equal(
    (
      await call("/devices", {
        ...auth,
        body: {
          ...input,
          name: "Changed profile",
          ciscoProfile: { ...selected, compatibilityProfile: "legacy_cisco" },
          verificationToken: draft.body.verificationToken,
        },
      })
    ).status,
    400,
  );
  const terminalBefore = await terminal.target(
    { user: actorForAccess, session: { id: "test" } },
    id,
  );
  result = await call(`/devices/cisco-enable-credentials/${enable.body.id}`, {
    ...auth,
    method: "PUT",
    body: { name: "Enable renewed", password: "enable-owned-test" },
  });
  assert.equal(result.status, 200);
  const terminalAfter = await terminal.target(
    { user: actorForAccess, session: { id: "test" } },
    id,
  );
  assert.notEqual(terminalBefore.revision, terminalAfter.revision);
  let report = (await call(caps, auth)).body;
  assert.equal(report.ready, false);
  assert.equal(report.stale, true);
  assert.equal(
    (
      await call("/devices", {
        ...auth,
        body: {
          ...input,
          name: "Changed secret",
          ciscoProfile: selected,
          verificationToken: draft.body.verificationToken,
        },
      })
    ).status,
    400,
  );
  draft = await call("/devices/draft-connection", {
    ...auth,
    body: {
      device: {
        ...input,
        name: "Verified registration",
        host: "localhost",
        ciscoProfile: selected,
      },
    },
  });
  assert.equal(draft.status, 201);
  const verified = await call("/devices", {
    ...auth,
    body: {
      ...input,
      name: "Verified registration",
      host: "localhost",
      ciscoProfile: selected,
      verificationToken: draft.body.verificationToken,
    },
  });
  assert.equal(verified.status, 201);
  assert.ok(verified.body.verification);
  assert.equal(
    (await call(`/devices/${verified.body.id}/cisco-access`, auth)).body.enableConfigured,
    true,
  );
  // Running collection cannot commit after a configuration change.
  const actor = await db.getRepository(AppUser).findOneByOrFail({ id: admin.id }),
    service = app.get(DeviceCapabilitiesService),
    observed = fixture.pause("show processes cpu"),
    pending = service.refresh(actor, id);
  const settled = pending.then(
    () => ({ success: true }),
    (error) => ({ error }),
  );
  await observed;
  const current = (await call(path, auth)).body;
  result = await call(path, {
    ...auth,
    method: "PUT",
    body: { ...selected, compatibilityProfile: "legacy_cisco", revision: current.revision },
  });
  assert.equal(result.status, 200);
  fixture.release();
  const race = await settled;
  assert.equal(race.error?.getStatus?.(), 409);
  // Employees can register an equipment in an assigned company using their own two credentials.
  const employeeAuth = { token: employee.token },
    ownEnable = await call("/devices/cisco-enable-credentials", {
      ...employeeAuth,
      body: { name: "Employee enable", password: "enable-owned-test" },
    }),
    ownSsh = await call("/devices/credentials", {
      ...employeeAuth,
      body: {
        name: "Employee SSH",
        operation: "verify",
        username: fixture.username,
        password: fixture.password,
        hostKey: fixture.hostKey,
      },
    });
  assert.equal(ownEnable.status, 201);
  assert.equal(ownSsh.status, 201);
  const employeeInput = {
    ...input,
    name: "Employee registered",
    managementPort: fixture.port === 65535 ? 65534 : fixture.port + 1,
    credentialId: ownSsh.body.id,
    ciscoProfile: { compatibilityProfile: "modern", enableCredentialId: ownEnable.body.id },
  };
  result = await call("/devices", { ...employeeAuth, body: employeeInput });
  assert.equal(result.status, 201);
  assert.equal(
    (await call(`/devices/${result.body.id}/cisco-access`, employeeAuth)).body.enableConfigured,
    true,
  );
  assert.equal(
    (
      await call("/devices", {
        ...employeeAuth,
        body: { ...employeeInput, name: "Foreign enable", ciscoProfile: selected },
      })
    ).status,
    404,
  );
  // Explicit settings change expires restore plans through the same source fingerprint.
  const restores = app.get(
      require("../dist/modules/devices/device-restores.service.js").DeviceRestoresService,
    ),
    device = await app.get(DevicesService).get(actor, id),
    before = await restores.binding(db.manager, device);
  settings = (await call(path, auth)).body;
  await call(path, { ...auth, method: "PUT", body: { ...selected, revision: settings.revision } });
  assert.notEqual(before, await restores.binding(db.manager, device));
  result = await call(`/devices/cisco-enable-credentials/${enable.body.id}`, {
    ...auth,
    method: "DELETE",
  });
  assert.equal(result.status, 200);
  settings = (await call(path, auth)).body;
  assert.equal(settings.enableConfigured, false);
  assert.equal(settings.history[0].action, "enable_credential_deleted");
  assert.ok(!JSON.stringify(settings).includes("enable-owned-test"));
  assert.equal((await call(caps, auth)).body.ready, false);
  assert.equal((await call(`/devices/${verified.body.id}`, auth)).body.verification, null);
  // Audit is bounded and scoped to the current company.
  for (let n = 0; n < 52; n++) {
    settings = (await call(path, auth)).body;
    assert.equal(
      (
        await call(path, {
          ...auth,
          method: "PUT",
          body: {
            compatibilityProfile: "modern",
            enableCredentialId: null,
            revision: settings.revision,
          },
        })
      ).status,
      200,
    );
  }
  settings = (await call(path, auth)).body;
  assert.equal(settings.history.length, 50);
  console.log(
    "Cisco access API: personal encrypted enable credentials, roles/tenant isolation, real EXEC escalation, registration proof freshness, configuration race, employee onboarding, restore binding, invalidation, audit retention passed.",
  );
} finally {
  fixture.release();
  if (db && users.length) await db.getRepository(AppUser).delete(users);
  if (app) await app.close();
  await fixture.close();
}
