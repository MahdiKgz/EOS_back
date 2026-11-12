import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
import "reflect-metadata";
import { config } from "dotenv";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url);
const { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js"),
  { Device } = require("../dist/modules/devices/device.entity.js");
const { DeviceTerminalService } = require("../dist/modules/devices/device-terminal.service.js");
const server = spawn("python3", ["test/fixtures/terminal-server.py"], {
  stdio: ["ignore", "pipe", "pipe"],
});
server.stderr.on("data", () => {});
const lines = createInterface({ input: server.stdout });
const users = [];
let app, db;
const wait = async (check) => {
  for (let i = 0; i < 120; i++) {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  assert.fail("Terminal fixture condition timed out");
};
try {
  const [line] = await once(lines, "line", { signal: AbortSignal.timeout(10000) }),
    fixture = JSON.parse(line);
  app = await NestFactory.create(AppModule, { logger: false });
  app.setGlobalPrefix("api/v1");
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
  await app.listen(0, "127.0.0.1");
  db = app.get(DataSource);
  const base = (await app.getUrl()) + "/api/v1";
  const service = app.get(DeviceTerminalService);
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
    const username = "terminal_" + randomBytes(6).toString("hex"),
      password = randomBytes(24).toString("base64") + "Aa1!";
    const result = await call("/auth/register", {
      body: { username, password, displayName: "کاربر تست ترمینال" },
    });
    assert.equal(result.status, 201);
    users.push(result.body.user.id);
    await db
      .getRepository(AppUser)
      .update(result.body.user.id, { role, workspaceOwnerId: owner ?? null });
    return { id: result.body.user.id, token: result.body.accessToken, username, password };
  }
  const admin = await account("co_admin"),
    other = await account("co_admin"),
    employee = await account("co_employee", admin.id),
    auth = { token: admin.token };
  const credentialBody = {
    name: "terminal-fixture",
    operation: "verify",
    username: "fixture",
    password: "fixture-secret",
    hostKey: fixture.hostKey,
  };
  const credential = (await call("/devices/credentials", { ...auth, body: credentialBody })).body;
  const deviceBody = {
    name: "Terminal fixture",
    type: "linux_edge",
    vendor: "linux",
    host: "127.0.0.1",
    managementPort: fixture.port,
    protocol: "ssh",
    environment: "lab",
    tags: [],
    credentialId: credential.id,
  };
  const created = await call("/devices", { ...auth, body: deviceBody });
  assert.equal(created.status, 201);
  const device = created.body,
    path = `/devices/${device.id}/terminal`;
  assert.equal((await call(path)).status, 401);
  assert.equal((await call(path, { token: employee.token })).status, 403);
  assert.equal((await call(path, { token: other.token })).status, 404);
  const metadata = (await call(path, auth)).body;
  assert.equal(metadata.credentialsConfigured, true);
  assert.match(metadata.fingerprint, /^SHA256:/);
  assert.equal(metadata.password, undefined);
  const preview = async () => {
    const result = await call(path + "/preview", { ...auth, body: {} });
    assert.equal(result.status, 201);
    return result.body;
  };
  const open = async (p) =>
    call(path + "/sessions", {
      ...auth,
      body: { previewId: p.previewId, intent: "execute", confirmed: true, cols: 80, rows: 24 },
    });
  let p = await preview();
  assert.equal(service.runtime.active(), 0, "preview must not open an SSH shell");
  assert.equal(
    (
      await call(path + "/sessions", {
        ...auth,
        body: { previewId: p.previewId, intent: "execute", confirmed: false, cols: 80, rows: 24 },
      })
    ).status,
    400,
  );
  const opened = await open(p);
  assert.equal(opened.status, 201, JSON.stringify(opened.body));
  const sid = opened.body.id,
    sessionPath = path + "/sessions/" + sid;
  assert.equal((await open(p)).status, 409, "preview is one-shot");
  const anotherLogin = await call("/auth/login", {
    body: { username: admin.username, password: admin.password },
  });
  assert.equal(anotherLogin.status, 200);
  assert.equal(
    (await call(sessionPath, { token: anotherLogin.body.accessToken })).status,
    404,
    "same user in another login cannot attach",
  );
  assert.equal((await call(sessionPath, { token: other.token })).status, 404);
  assert.equal((await call(sessionPath + "?cursor=-1", auth)).status, 400);
  assert.equal(
    (await call(sessionPath + "/input", { ...auth, body: { sequence: 2, data: "pwd\r" } })).status,
    409,
  );
  assert.equal(
    (await call(sessionPath + "/input", { ...auth, body: { sequence: 1, data: "cd /tmp\r" } }))
      .status,
    201,
  );
  assert.equal(
    (await call(sessionPath + "/input", { ...auth, body: { sequence: 2, data: "pwd\r" } })).status,
    201,
  );
  await wait(async () =>
    Buffer.from((await call(sessionPath, auth)).body.data ?? "", "base64")
      .toString()
      .includes("/tmp"),
  );
  assert.equal(
    (
      await call(sessionPath + "/input", {
        ...auth,
        body: { sequence: 2, data: "must-not-replay\r" },
      })
    ).status,
    409,
  );
  assert.equal(
    (await call(sessionPath + "/resize", { ...auth, body: { cols: 100, rows: 30 } })).status,
    201,
  );
  await wait(async () =>
    Buffer.from((await call(sessionPath, auth)).body.data ?? "", "base64")
      .toString()
      .includes("window:100x30"),
  );
  assert.equal(
    (await call(sessionPath + "/input", { ...auth, body: { sequence: 3, data: "\u0003" } })).status,
    201,
  );
  await wait(async () =>
    Buffer.from((await call(sessionPath, auth)).body.data ?? "", "base64")
      .toString()
      .includes("^C"),
  );
  assert.equal(
    (await call(sessionPath + "/input", { ...auth, body: { sequence: 4, data: "burst\r" } }))
      .status,
    201,
  );
  await wait(async () => (await call(sessionPath, auth)).body.truncated);
  let cursor = 0,
    size = 0;
  while (true) {
    const r = (await call(sessionPath + "?cursor=" + cursor, auth)).body;
    cursor = r.cursor;
    size += Buffer.from(r.data, "base64").length;
    if (!r.hasMore) break;
  }
  assert.ok(size <= 256 * 1024);
  assert.equal((await call(sessionPath + "/close", { ...auth, body: {} })).status, 201);
  assert.equal((await call(sessionPath + "/close", { ...auth, body: {} })).status, 201);
  await wait(
    async () =>
      (await call(path, auth)).body.events.filter((e) => e.action === "closed").length === 1,
  );
  const events = (await call(path, auth)).body.events;
  assert.equal(events.length, 3);
  const eventText = JSON.stringify(events);
  assert.equal(eventText.includes("cd /tmp"), false);
  assert.equal(eventText.includes("fixture-secret"), false);
  assert.equal(eventText.includes("must-not-replay"), false);
  p = await preview();
  service.previews.get(p.previewId).expires = Date.now() - 1;
  assert.equal((await open(p)).status, 409);
  p = await preview();
  await db.getRepository(Device).update(device.id, { name: "Changed target" });
  assert.equal((await open(p)).status, 409);
  p = await preview();
  await call("/devices/credentials/" + credential.id, {
    ...auth,
    method: "PUT",
    body: { ...credentialBody, password: "incorrect-fixture-password" },
  });
  assert.equal((await open(p)).status, 409);
  p = await preview();
  const denied = await open(p);
  assert.equal(denied.status, 502);
  assert.equal(denied.body.code, "SSH_AUTH_FAILED");
  await call("/devices/credentials/" + credential.id, {
    ...auth,
    method: "PUT",
    body: { ...credentialBody, hostKey: fixture.wrongHostKey },
  });
  p = await preview();
  assert.equal((await open(p)).body.code, "SSH_HOST_KEY_MISMATCH");
  await call("/devices/credentials/" + credential.id, {
    ...auth,
    method: "PUT",
    body: credentialBody,
  });
  p = await preview();
  const archivedSession = await open(p);
  assert.equal(archivedSession.status, 201);
  await call("/devices/" + device.id, { ...auth, method: "DELETE" });
  assert.equal((await call(path + "/sessions/" + archivedSession.body.id, auth)).status, 409);
  assert.equal(service.runtime.active(), 0);
  await call("/devices/" + device.id + "/restore", { ...auth, body: {} });
  p = await preview();
  assert.equal((await open(p)).status, 201);
  await db.getRepository(AppUser).update(admin.id, { role: "co_employee" });
  await wait(() => service.runtime.active() === 0);
  assert.equal((await call(path, auth)).status, 403);
  await db.getRepository(AppUser).update(admin.id, { role: "co_admin" });
  p = await preview();
  assert.equal((await open(p)).status, 201);
  await call("/auth/logout", { ...auth, body: {} });
  await wait(() => service.runtime.active() === 0);
  console.log(
    "PASS: real ssh2 client + independent Paramiko PTY, shell state, input replay, resize, bounded output, preview expiry/binding, roles/login isolation, credential/host-key rejection, archive/revocation/logout cleanup and audit without I/O",
  );
} finally {
  if (app) {
    await app.get(DeviceTerminalService).onModuleDestroy();
    if (users.length && db?.isInitialized) await db.getRepository(AppUser).delete(users);
    await app.close();
  }
  lines.close();
  if (server.exitCode === null && server.signalCode === null) {
    const closed = once(server, "close");
    server.kill("SIGTERM");
    const timer = setTimeout(() => server.kill("SIGKILL"), 5000);
    await closed;
    clearTimeout(timer);
  }
}
