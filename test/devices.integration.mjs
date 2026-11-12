import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
const { AppModule } = await import("../dist/app.module.js");
const { AppUser } = await import("../dist/modules/users/user.entity.js");
const { Device } = await import("../dist/modules/devices/device.entity.js");
const app = await NestFactory.create(AppModule, { logger: false });
app.setGlobalPrefix("api/v1");
app.useGlobalPipes(
  new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
);
const users = [];
try {
  await app.listen(0, "127.0.0.1");
  const base = (await app.getUrl()) + "/api/v1";
  const call = async (path, { body, token, method = body === undefined ? "GET" : "POST" } = {}) => {
    const response = await fetch(base + path, {
      method,
      headers: {
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...(token ? { authorization: "Bearer " + token } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  };
  const userRepo = app.get(DataSource).getRepository(AppUser),
    deviceRepo = app.get(DataSource).getRepository(Device);
  async function account(suffix, role, owner) {
    const response = await call("/auth/register", {
      body: {
        username: `devicecheck_${Date.now()}_${suffix}`,
        displayName: "کاربر تست تجهیزات",
        password: "Device-Check-4286!",
      },
    });
    assert.equal(response.status, 201);
    users.push(response.body.user.id);
    await userRepo.update(response.body.user.id, { role, workspaceOwnerId: owner ?? null });
    return { id: response.body.user.id, token: response.body.accessToken };
  }
  const admin = await account("admin", "co_admin"),
    other = await account("other", "pl_admin"),
    employee = await account("employee", "co_employee", admin.id);
  const input = {
    name: "Alpha Router",
    vendor: "MikroTik",
    type: "mikrotik",
    host: "router.example.test",
    managementPort: 22,
    protocol: "ssh",
    environment: "lab",
    tags: ["مرکزی"],
  };
  assert.equal((await call("/devices")).status, 401);
  assert.equal((await call("/devices", { token: employee.token, body: input })).status, 403);
  for (const extra of [
    { status: "online" },
    { workspaceOwnerId: other.id },
    { password: "secret" },
  ])
    assert.equal(
      (await call("/devices", { token: admin.token, body: { ...input, ...extra } })).status,
      400,
    );
  for (const invalid of [
    { host: "999.1.2.3" },
    { host: "https://example.com" },
    { managementPort: 0 },
    { managementPort: 65536 },
    { type: "invalid" },
  ])
    assert.equal(
      (await call("/devices", { token: admin.token, body: { ...input, ...invalid } })).status,
      400,
    );
  const created = await call("/devices", { token: admin.token, body: input });
  assert.equal(created.status, 201);
  const id = created.body.id;
  assert.equal(created.body.status, "unknown");
  assert.equal(
    (
      await call("/devices", {
        token: admin.token,
        body: { ...input, host: "ROUTER.EXAMPLE.TEST", vendor: "MIKROTIK" },
      })
    ).status,
    409,
  );
  assert.equal((await call(`/devices/${id}`, { token: other.token })).status, 404);
  assert.equal(
    (await call(`/devices/${id}`, { token: other.token, body: input, method: "PUT" })).status,
    404,
  );
  assert.equal(
    (await call(`/devices/${id}`, { token: other.token, method: "DELETE" })).status,
    404,
  );
  assert.equal((await call("/devices", { token: other.token })).body.total, 0);
  assert.equal((await call("/devices", { token: employee.token })).body.total, 1);
  const recorder = await call("/devices", {
    token: admin.token,
    body: {
      ...input,
      name: "Beta Recorder",
      location: "  ورودی ساختمان  ",
      vendor: "Hikvision",
      type: "nvr",
      host: "2001:db8::5",
      protocol: "api",
      managementPort: 443,
    },
  });
  assert.equal(recorder.status, 201);
  assert.equal(recorder.body.location, "ورودی ساختمان");
  assert.deepEqual(
    (
      await call("/devices?search=" + encodeURIComponent("ورودی ساختمان"), { token: admin.token })
    ).body.items.map((item) => item.id),
    [recorder.body.id],
  );
  assert.equal(
    (
      await call("/devices", {
        token: admin.token,
        body: { ...input, verificationToken: "untrusted" },
      })
    ).status,
    400,
  );
  const recorderProof = { username: "fixture", password: "fixture", https: false };
  for (const [deviceId, account, expected] of [
    [id, admin, 400],
    [recorder.body.id, employee, 403],
    [recorder.body.id, other, 404],
    [recorder.body.id, admin, 400],
  ]) {
    assert.equal(
      (
        await call(`/devices/${deviceId}/verify-recorder`, {
          token: account.token,
          body: recorderProof,
        })
      ).status,
      expected,
    );
  }
  assert.equal(
    (await call(`/devices/${recorder.body.id}`, { token: admin.token })).body.verification,
    null,
  );
  process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
  const recorderPath = `/devices/${recorder.body.id}/verify-recorder`;
  assert.equal(
    (await call(recorderPath, { token: admin.token, body: { useSaved: true } })).status,
    404,
  );
  assert.equal(
    (
      await call(recorderPath, {
        token: admin.token,
        body: { ...recorderProof, useSaved: true },
      })
    ).status,
    400,
  );
  const sshPath = `/devices/${id}/linux-ssh`;
  const savedSshRequest = { operation: "verify", useSaved: true };
  assert.equal((await call(sshPath, { body: savedSshRequest })).status, 401);
  assert.equal((await call(sshPath, { token: employee.token, body: savedSshRequest })).status, 403);
  assert.equal((await call(sshPath, { token: other.token, body: savedSshRequest })).status, 404);
  assert.equal((await call(sshPath, { token: admin.token, body: savedSshRequest })).status, 404);
  if (process.env.TEST_DEVICE_SSH_FIXTURE) {
    const fixture = JSON.parse(readFileSync(process.env.TEST_DEVICE_SSH_FIXTURE, "utf8"));
    process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
    await deviceRepo.update(id, {
      host: "127.0.0.1",
      managementPort: fixture.port,
      type: "linux_edge",
    });
    const draft = {
      device: {
        ...input,
        vendor: "fixture-linux",
        host: "127.0.0.1",
        managementPort: fixture.port,
        type: "linux_edge",
      },
      credentials: {
        operation: "verify",
        username: "fixture",
        ...(fixture.password ? { password: fixture.password } : { privateKey: fixture.identity }),
        hostKey: fixture.key,
      },
    };
    assert.equal(
      (await call("/devices/draft-connection", { token: employee.token, body: draft })).status,
      403,
    );
    const beforeDraft = (await call("/devices", { token: admin.token })).body.total;
    const draftResult = await call("/devices/draft-connection", {
      token: admin.token,
      body: draft,
    });
    assert.equal(draftResult.status, 201);
    assert.equal(draftResult.body.verified, true);
    assert.equal((await call("/devices", { token: admin.token })).body.total, beforeDraft);
    const proof = draftResult.body.verificationToken;
    const testedDevice = { ...draft.device, name: "Verified fixture" };
    assert.equal(
      (
        await call("/devices", {
          token: admin.token,
          body: { ...testedDevice, host: "192.0.2.123", verificationToken: proof },
        })
      ).status,
      400,
    );
    const registered = await call("/devices", {
      token: admin.token,
      body: { ...testedDevice, verificationToken: proof },
    });
    assert.equal(registered.status, 201);
    assert.equal(registered.body.verification.checkedAt, draftResult.body.checkedAt);
    const changed = await call(`/devices/${registered.body.id}`, {
      token: admin.token,
      method: "PUT",
      body: { ...testedDevice, managementPort: fixture.port === 22 ? 23 : 22 },
    });
    assert.equal(changed.status, 200);
    assert.equal(changed.body.verification, null);
    await deviceRepo.delete(registered.body.id);
    const setup = await call(sshPath, {
      token: admin.token,
      body: {
        operation: "verify",
        saveConnection: true,
        username: "fixture",
        ...(fixture.password ? { password: fixture.password } : { privateKey: fixture.identity }),
        hostKey: fixture.key,
      },
    });
    assert.equal(setup.status, 201);
    assert.equal(setup.body.saved, true);
    assert.equal(
      (await call(`/devices/${id}`, { token: admin.token })).body.verification.checkedAt,
      setup.body.checkedAt,
    );
    const [profile] = await app
      .get(DataSource)
      .query('SELECT "sealedCredentials" FROM "device_ssh_profiles" WHERE "deviceId" = $1', [id]);
    assert.ok(profile.sealedCredentials && !profile.sealedCredentials.includes("PRIVATE KEY"));
    const verified = await call(sshPath, { token: admin.token, body: savedSshRequest });
    assert.equal(verified.status, 201);
    assert.equal(verified.body.output, "Linux");
    assert.equal(
      (await call(`/devices/${id}`, { token: admin.token })).body.verification.checkedAt,
      verified.body.checkedAt,
    );
    await deviceRepo.update(id, { managementPort: fixture.port === 22 ? 23 : 22 });
    assert.equal((await call(sshPath, { token: admin.token, body: savedSshRequest })).status, 409);
    await deviceRepo.update(id, {
      host: input.host,
      managementPort: input.managementPort,
      type: input.type,
    });
    console.log("PASS: verified SSH setup, encrypted credentials, reuse, and endpoint binding");
  }
  const historyPath = `/devices/${id}/history`;
  assert.equal((await call(historyPath, { token: other.token })).status, 404);
  assert.deepEqual((await call(historyPath, { token: employee.token })).body, []);
  const testPath = `/devices/${id}/test-connection`;
  assert.equal((await call(testPath, { method: "POST" })).status, 401);
  assert.equal((await call(testPath, { method: "POST", token: employee.token })).status, 403);
  assert.equal((await call(testPath, { method: "POST", token: other.token })).status, 404);
  if (process.env.TEST_DEVICE_ICMP === "1") {
    await deviceRepo.update(id, { host: "127.0.0.1" });
    const ping = await call(testPath, { method: "POST", token: admin.token });
    assert.equal(ping.status, 201);
    assert.equal(ping.body.reachable, true);
    assert.equal(ping.body.status, "online");
    assert.equal(typeof ping.body.latencyMs, "number");
    const saved = await call(`/devices/${id}`, { token: admin.token });
    assert.equal(saved.body.status, "online");
    assert.equal(saved.body.lastSeenAt, ping.body.lastSeenAt);
    const history = await call(historyPath, { token: employee.token });
    assert.equal(history.status, 200);
    assert.equal(history.body.length, 1);
    assert.equal(history.body[0].host, "127.0.0.1");
    assert.equal(history.body[0].checkedAt, ping.body.checkedAt);
    assert.equal(history.body[0].latencyMs, ping.body.latencyMs);
    await deviceRepo.update(id, { host: input.host });
  } else {
    await deviceRepo.update(id, { status: "online", lastSeenAt: new Date() });
  }
  const list = await call("/devices?sort=name&direction=asc&pageSize=1", { token: admin.token });
  assert.equal(list.status, 200);
  assert.equal(list.body.total, 2);
  assert.equal(list.body.items[0].id, id);
  assert.deepEqual(list.body.stats, { total: 2, online: 1, needsReview: 0, unknown: 1 });
  assert.equal(
    (await call("/devices?search=%D9%85%D8%B1%DA%A9%D8%B2%DB%8C", { token: admin.token })).body
      .total,
    2,
  );
  assert.equal((await call("/devices?search=%25", { token: admin.token })).body.total, 0);
  assert.equal(
    (await call("/devices?category=recorder", { token: admin.token })).body.items[0].id,
    recorder.body.id,
  );
  assert.equal((await call("/devices?status=online", { token: admin.token })).body.total, 1);
  for (const query of [
    "page=0",
    "pageSize=101",
    "sort=passwordHash",
    "direction=DROP",
    "status=madeup",
  ])
    assert.equal((await call("/devices?" + query, { token: admin.token })).status, 400);
  const updated = await call(`/devices/${id}`, {
    token: admin.token,
    body: { ...input, host: "192.0.2.11" },
    method: "PUT",
  });
  assert.equal(updated.status, 200);
  assert.equal(updated.body.status, "unknown");
  assert.equal(updated.body.lastSeenAt, null);
  assert.equal(
    (await call(`/devices/${id}`, { token: employee.token, method: "DELETE" })).status,
    403,
  );
  assert.equal(
    (await call(`/devices/${id}`, { token: admin.token, method: "DELETE" })).status,
    200,
  );
  assert.equal((await call(`/devices/${id}`, { token: admin.token })).status, 404);
  assert.equal((await call("/devices", { token: admin.token })).body.stats.total, 1);
  assert.equal(
    (await call("/devices", { token: admin.token, body: { ...input, host: "192.0.2.11" } })).status,
    201,
  );
  const archived = "/devices?inventory=archived";
  const restorePath = `/devices/${id}/restore`;
  assert.deepEqual(
    (await call(archived, { token: employee.token })).body.items.map((item) => item.id),
    [id],
  );
  assert.equal((await call(archived, { token: other.token })).body.total, 0);
  assert.equal((await call(restorePath, { token: employee.token, method: "POST" })).status, 403);
  assert.equal((await call(restorePath, { token: other.token, method: "POST" })).status, 404);
  assert.equal((await call(restorePath, { token: admin.token, method: "POST" })).status, 409);
  assert.equal((await call(archived, { token: admin.token })).body.total, 1);
  const active = (await call("/devices", { token: admin.token })).body.items.find(
    (item) => item.host === "192.0.2.11",
  );
  assert.equal(
    (await call(`/devices/${active.id}`, { token: admin.token, method: "DELETE" })).status,
    200,
  );
  assert.equal((await call(restorePath, { token: admin.token, method: "POST" })).status, 201);
  assert.equal((await call(`/devices/${id}`, { token: admin.token })).body.id, id);
  assert.equal((await call(restorePath, { token: admin.token, method: "POST" })).status, 404);
  const eventsPath = `/devices/${id}/inventory-events`;
  assert.equal((await call(eventsPath, { token: other.token })).status, 404);
  const events = await call(eventsPath, { token: admin.token });
  assert.deepEqual(
    events.body.map((event) => event.action),
    ["restored", "archived"],
  );
  assert.ok(events.body.every((event) => event.actorName === "کاربر تست تجهیزات"));
  const employeeCompanies = await call("/devices/companies", { token: employee.token });
  const otherCompanies = await call("/devices/companies", { token: other.token });
  assert.equal(employeeCompanies.status, 200);
  assert.equal(employeeCompanies.body[0].id, admin.id);
  assert.equal(otherCompanies.body[0].id, other.id);
  const destination = await call("/devices/companies", {
    token: admin.token,
    body: { name: "شرکت مقصد تست" },
  });
  assert.equal(destination.status, 201);
  const recorderInventory = "/devices?category=recorder";
  const ownedRecorderList = await call(recorderInventory + "&companyId=" + admin.id, {
    token: admin.token,
  });
  assert.equal(ownedRecorderList.body.total, 1);
  assert.equal(ownedRecorderList.body.stats.total, 1);
  assert.equal(
    (await call(recorderInventory + "&companyId=" + other.id, { token: admin.token })).body.stats
      .total,
    0,
  );
  assert.equal(
    (await call(recorderInventory + "&companyId=invalid", { token: admin.token })).status,
    400,
  );
  const retainedVerification = {
    checkedAt: new Date().toISOString(),
    identity: { Manufacturer: "fixture" },
  };
  await deviceRepo.update(recorder.body.id, {
    sealedRecorderCredentials: "retained-fixture-vault",
    verification: retainedVerification,
  });
  const retainedEvents = (
    await call(`/devices/${recorder.body.id}/history`, { token: admin.token })
  ).body;
  assert.equal(
    (await call(`/devices/${recorder.body.id}`, { token: admin.token, method: "DELETE" })).status,
    200,
  );
  assert.equal((await call(recorderInventory, { token: admin.token })).body.total, 0);
  const archivedRecorders = await call(
    recorderInventory + "&inventory=archived&companyId=" + admin.id,
    { token: employee.token },
  );
  assert.deepEqual(
    archivedRecorders.body.items.map((item) => item.id),
    [recorder.body.id],
  );
  assert.equal(archivedRecorders.body.stats.total, 1);
  assert.equal(
    (await call(recorderInventory + "&inventory=archived", { token: other.token })).body.total,
    0,
  );
  assert.equal(
    (await call(`/devices/${recorder.body.id}/restore`, { token: employee.token, method: "POST" }))
      .status,
    403,
  );
  const retained = await deviceRepo.findOne({
    where: { id: recorder.body.id },
    withDeleted: true,
    select: { id: true, sealedRecorderCredentials: true, verification: true },
  });
  assert.equal(retained.sealedRecorderCredentials, "retained-fixture-vault");
  assert.deepEqual(retained.verification, retainedVerification);
  assert.equal(
    (await call(`/devices/${recorder.body.id}/restore`, { token: admin.token, method: "POST" }))
      .status,
    201,
  );
  assert.equal(
    (await call(recorderInventory, { token: admin.token })).body.items[0].id,
    recorder.body.id,
  );
  assert.deepEqual(
    (await call(`/devices/${recorder.body.id}/history`, { token: admin.token })).body,
    retainedEvents,
  );
  const recorderTransferPath = `/devices/${recorder.body.id}`;
  const recorderUpdate = {
    ...input,
    name: "Beta Recorder",
    vendor: "Hikvision",
    type: "nvr",
    host: "2001:db8::5",
    protocol: "api",
    managementPort: 443,
  };
  await deviceRepo.update(recorder.body.id, {
    sealedRecorderCredentials: "fixture-sealed-value",
    verification: { checkedAt: new Date().toISOString() },
  });
  assert.equal(
    (
      await call(recorderTransferPath, {
        token: admin.token,
        method: "PUT",
        body: { ...recorderUpdate, companyId: otherCompanies.body[0].id },
      })
    ).status,
    404,
  );
  const moved = await call(recorderTransferPath, {
    token: admin.token,
    method: "PUT",
    body: { ...recorderUpdate, companyId: destination.body.id },
  });
  assert.equal(moved.status, 200);
  assert.equal(moved.body.companyId, destination.body.id);
  assert.equal(moved.body.location, "ورودی ساختمان");
  assert.equal(moved.body.verification, null);
  assert.equal(moved.body.sealedRecorderCredentials, undefined);
  const movedRecord = await deviceRepo.findOne({
    where: { id: recorder.body.id },
    select: { id: true, sealedRecorderCredentials: true },
  });
  assert.equal(movedRecord.sealedRecorderCredentials, null);
  const draftPath = "/devices/registration-draft";
  const draftBody = {
    companyId: destination.body.id,
    category: "network",
    values: {
      name: "پیش‌نویس",
      vendor: "linux",
      type: "linux_edge",
      host: "",
      managementPort: 22,
      protocol: "ssh",
      environment: "lab",
      tagsText: "",
    },
  };
  const draftSaved = await call(draftPath, { token: admin.token, method: "PUT", body: draftBody });
  assert.equal(draftSaved.status, 200);
  assert.deepEqual((await call(draftPath, { token: employee.token })).body, { draft: null });
  assert.equal(
    (await call(draftPath, { token: admin.token })).body.draft.values.name,
    draftBody.values.name,
  );
  assert.equal(
    (
      await call(draftPath, {
        token: admin.token,
        method: "PUT",
        body: { ...draftBody, values: { ...draftBody.values, password: "unexpected" } },
      })
    ).status,
    400,
  );
  const newerDraft = await call(draftPath, { token: admin.token, method: "PUT", body: draftBody });
  assert.equal(newerDraft.status, 200);
  await call(`${draftPath}?revision=${draftSaved.body.revision}`, {
    token: admin.token,
    method: "DELETE",
  });
  assert.equal(
    (await call(draftPath, { token: admin.token })).body.draft.revision,
    newerDraft.body.revision,
  );
  const duplicateDraftRegistration = await call("/devices", {
    token: admin.token,
    body: {
      ...recorderUpdate,
      companyId: destination.body.id,
      draftRevision: newerDraft.body.revision,
    },
  });
  assert.equal(duplicateDraftRegistration.status, 409);
  assert.equal(
    (await call(draftPath, { token: admin.token })).body.draft.revision,
    newerDraft.body.revision,
  );
  const staleDraftRegistration = await call("/devices", {
    token: admin.token,
    body: { ...input, host: "192.0.2.80", draftRevision: draftSaved.body.revision },
  });
  assert.equal(staleDraftRegistration.status, 201);
  assert.equal(
    (await call(draftPath, { token: admin.token })).body.draft.revision,
    newerDraft.body.revision,
  );
  const resumedRegistration = await call("/devices", {
    token: admin.token,
    body: { ...input, host: "192.0.2.81", draftRevision: newerDraft.body.revision },
  });
  assert.equal(resumedRegistration.status, 201);
  assert.deepEqual((await call(draftPath, { token: admin.token })).body, { draft: null });
  const employeeCredential = await call("/devices/credentials", {
    token: employee.token,
    body: {
      operation: "verify",
      name: "Temporary credential",
      username: "fixture",
      hostKey: "ssh-ed25519 AAAA",
      privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----",
    },
  });
  assert.equal(employeeCredential.status, 201);
  assert.deepEqual(Object.keys(employeeCredential.body).sort(), ["id", "name", "username"]);
  assert.deepEqual((await call("/devices/credentials", { token: other.token })).body, []);
  const employeeDevice = {
    ...input,
    type: "linux_edge",
    host: "192.0.2.50",
    companyId: employeeCompanies.body[0].id,
    credentialId: employeeCredential.body.id,
    accessRoute: "direct",
  };
  assert.equal(
    (
      await call("/devices", {
        token: employee.token,
        body: { ...employeeDevice, companyId: otherCompanies.body[0].id },
      })
    ).status,
    404,
  );
  assert.equal(
    (
      await call("/devices", {
        token: admin.token,
        body: employeeDevice,
      })
    ).status,
    404,
  );
  const attached = await call("/devices", { token: employee.token, body: employeeDevice });
  assert.equal(attached.status, 201);
  assert.equal(attached.body.companyId, employeeDevice.companyId);
  assert.equal(attached.body.credentialId, employeeCredential.body.id);
  assert.equal(
    (
      await call(`/devices/credentials/${employeeCredential.body.id}`, {
        token: employee.token,
        method: "DELETE",
      })
    ).status,
    200,
  );
  assert.equal(
    (await call(`/devices/${attached.body.id}`, { token: employee.token })).body.credentialId,
    null,
  );
  await userRepo.update(employee.id, { allowedSections: ["reports"] });
  assert.equal((await call("/devices", { token: employee.token })).status, 403);
  console.log(
    "PASS: authenticated inventory CRUD, workspace isolation, employee permissions, duplicate prevention, validation, status integrity, search, filters, sorting, pagination, statistics and soft archive.",
  );
} finally {
  if (users.length) await app.get(DataSource).getRepository(AppUser).delete(users);
  await app.close();
}
