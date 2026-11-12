import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPairSync, randomBytes, createHash } from "node:crypto";
import ssh2 from "ssh2";
const { Server, utils } = ssh2;
const { TerminalRuntime, TERMINAL_LIMITS } = require("../dist/modules/devices/terminal-runtime.js");
const sshHostKeySha256Fingerprint = (key) => createHash("sha256").update(key).digest("hex");

test("interactive terminal authenticates real SSH PTY, preserves shell state and closes isolated sessions", async () => {
  const key = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
    type: "pkcs1",
    format: "pem",
  });
  const password = randomBytes(24).toString("base64"),
    audits = [],
    windows = [];
  let authentications = 0,
    commands = 0;
  const sockets = new Set();
  const server = new Server({ hostKeys: [key] }, (client) => {
    sockets.add(client);
    client.on("error", () => {});
    client.on("close", () => sockets.delete(client));
    client.on("authentication", (ctx) => {
      authentications++;
      if (ctx.method === "password" && ctx.username === "fixture" && ctx.password === password)
        ctx.accept();
      else if (
        ctx.method === "publickey" &&
        ctx.key.data.equals(utils.parseKey(key).getPublicSSH()) &&
        (!ctx.signature || utils.parseKey(key).verify(ctx.blob, ctx.signature, ctx.hashAlgo))
      )
        ctx.accept();
      else ctx.reject();
    });
    client.on("ready", () =>
      client.on("session", (accept) => {
        const session = accept();
        let cwd = "/fixture";
        session.on("pty", (accept) => accept?.());
        session.on("window-change", (accept, _reject, info) => {
          windows.push(info.cols);
          accept?.();
        });
        session.on("shell", (accept) => {
          const channel = accept();
          channel.write("\x1b[32mfixture\x1b[0m $ ");
          channel.on("data", (bytes) => {
            commands++;
            const input = bytes.toString();
            if (input.includes("cd /tmp")) cwd = "/tmp";
            if (input === "burst\r") channel.write(Buffer.alloc(320 * 1024, 65));
            else if (input === "exit\r") {
              channel.write("goodbye\r\n");
              channel.end();
            } else
              channel.write(
                input === "\u0003" ? "^C\r\n" : input === "pwd\r" ? `${cwd}\r\n` : input,
              );
          });
        });
      }),
    );
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port,
    owner = { userId: "u", ownerId: "workspace", sessionHash: "session-a" },
    identity = { ...owner, deviceId: "d", revision: "r", fingerprint: "fixture" };
  const runtime = new TerminalRuntime(async (audit) => {
    audits.push(audit);
  });
  const config = {
    host: "127.0.0.1",
    port,
    username: "fixture",
    password,
    readyTimeout: 3000,
    hostVerifier: (raw) => !!sshHostKeySha256Fingerprint(raw),
  };
  const wait = async (fn) => {
    for (let i = 0; i < 80; i++) {
      if (fn()) return;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.fail("SSH fixture condition timed out");
  };
  try {
    await assert.rejects(
      runtime.open(identity, config, { cols: 80, rows: 24 }, async () => {
        throw new Error("audit down");
      }),
      (error) => error.code === "TERMINAL_AUDIT_UNAVAILABLE",
    );
    assert.equal(authentications, 0, "audit failure must prevent SSH login");
    const result = await runtime.open(identity, config, { cols: 80, rows: 24 }, async () => {});
    assert.equal(result.state, "connected");
    assert.throws(
      () => runtime.read(result.id, { ...owner, sessionHash: "other" }, 0),
      (error) => error.code === "TERMINAL_NOT_FOUND",
    );
    assert.throws(
      () => runtime.input(result.id, owner, 2, "pwd\r"),
      (error) => error.code === "TERMINAL_INPUT_SEQUENCE",
    );
    runtime.input(result.id, owner, 1, "cd /tmp\r");
    await wait(() => commands === 1);
    runtime.input(result.id, owner, 2, "pwd\r");
    await wait(() => commands === 2);
    await wait(() =>
      Buffer.from(runtime.read(result.id, owner, 0).data, "base64")
        .toString()
        .includes("/tmp"),
    );
    assert.throws(
      () => runtime.input(result.id, owner, 2, "pwd\r"),
      (error) => error.code === "TERMINAL_INPUT_SEQUENCE",
      "replay is rejected",
    );
    runtime.input(result.id, owner, 3, "\u0003");
    runtime.resize(result.id, owner, 100, 30);
    await wait(() => windows.includes(100));
    runtime.input(result.id, owner, 4, "burst\r");
    await wait(() => runtime.read(result.id, owner, 0).truncated);
    let cursor = 0,
      readBytes = 0;
    while (true) {
      const chunk = runtime.read(result.id, owner, cursor);
      cursor = chunk.cursor;
      readBytes += Buffer.from(chunk.data, "base64").length;
      if (!chunk.hasMore) break;
    }
    assert.ok(readBytes <= TERMINAL_LIMITS.retentionBytes, "server output storage stays bounded");
    assert.throws(
      () => runtime.input(result.id, owner, 5, "x".repeat(32769)),
      (error) => error.code === "TERMINAL_INPUT_LIMIT",
    );
    runtime.input(result.id, owner, 5, "exit\r");
    await wait(() => runtime.read(result.id, owner, cursor).state === "closed");
    assert.match(
      Buffer.from(runtime.read(result.id, owner, cursor).data, "base64").toString(),
      /goodbye/,
    );
    const second = await runtime.open(identity, config, { cols: 80, rows: 24 }, async () => {});
    runtime.sweep(Date.now() + TERMINAL_LIMITS.leaseMs + 1);
    assert.equal(runtime.read(second.id, owner, 0).reason, "browser_disconnected");
    const revoked = await runtime.open(
      { ...identity, companyId: "company-a" },
      config,
      { cols: 80, rows: 24 },
      async () => {},
    );
    await runtime.revalidate(async () => false);
    assert.equal(
      runtime.read(revoked.id, { ...owner, companyId: "company-a" }, 0).reason,
      "authorization_changed",
    );

    const keySession = await runtime.open(
      identity,
      { ...config, password: undefined, privateKey: key },
      { cols: 80, rows: 24 },
      async () => {},
    );
    assert.equal(keySession.state, "connected");
    runtime.close(keySession.id, owner);
    const firstLimit = await runtime.open(identity, config, { cols: 80, rows: 24 }, async () => {});
    const secondLimit = await runtime.open(
      identity,
      config,
      { cols: 80, rows: 24 },
      async () => {},
    );
    await assert.rejects(
      runtime.open(identity, config, { cols: 80, rows: 24 }, async () => {}),
      (error) => error.code === "TERMINAL_SESSION_LIMIT",
    );
    runtime.close(firstLimit.id, owner);
    runtime.close(secondLimit.id, owner);
    const idle = await runtime.open(identity, config, { cols: 80, rows: 24 }, async () => {});
    runtime.owned(idle.id, owner).inputAt = Date.now() - TERMINAL_LIMITS.idleMs - 1;
    runtime.sweep();
    assert.equal(runtime.read(idle.id, owner, 0).reason, "idle_timeout");
    const lifetime = await runtime.open(identity, config, { cols: 80, rows: 24 }, async () => {});
    runtime.owned(lifetime.id, owner).openedAt = Date.now() - TERMINAL_LIMITS.lifetimeMs - 1;
    runtime.sweep();
    assert.equal(runtime.read(lifetime.id, owner, 0).reason, "session_expired");
    assert.equal(runtime.active(), 0);
    assert.ok(audits.length >= 2);
    assert.equal(JSON.stringify(audits).includes(password), false);
    assert.equal(JSON.stringify(audits).includes("cd /tmp"), false);
  } finally {
    await runtime.shutdown();
    for (const client of sockets) client.end();
    await new Promise((resolve) => server.close(() => resolve()));
  }
});
