import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import "reflect-metadata";
import { config } from "dotenv";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";

config({ quiet: true });
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  transport = require("../dist/modules/devices/ssh-transport.js");
const files = {
  cisco: Buffer.from(
    "version 17.9\nhostname Restored\ninterface GigabitEthernet0/1\n description restored\nend\n",
  ),
  mikrotik: Buffer.from(
    "# by RouterOS 7.16.2\n# model = fixture\n# serial number = a1\n/interface bridge\nadd name=restored\n",
  ),
  fortigate: Buffer.from(
    "#config-version=FGT-7.4.3:opmode=0\nconfig system global\nset hostname restored\nend\n",
  ),
};
const current = new Map(),
  staged = new Map();
let writes = 0,
  imports = 0,
  version = "7.16.2",
  mismatch = false;
transport.runSshCommand = async (device, _credentials, command, options) => {
  if (command.startsWith(":put")) return Buffer.from(version);
  if (
    command.startsWith("/export") ||
    command === "show running-config" ||
    command === "scp -f sys_config"
  )
    return current.get(device.id);
  if (command === "sftp" || command.startsWith("scp -t")) {
    staged.set(device.id, (options.sftpUpload ?? options.scpUpload).content);
    writes++;
    return Buffer.alloc(0);
  }
  if (
    command.startsWith("configure replace") ||
    (command.startsWith("/import") && !command.includes("dry-run"))
  ) {
    imports++;
    if (!mismatch) current.set(device.id, staged.get(device.id));
  }
  return Buffer.alloc(0);
};
const { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js");
const app = await NestFactory.create(AppModule, { logger: false });
app.useBodyParser("raw", { type: "application/octet-stream", limit: 20 * 1024 * 1024 });
app.setGlobalPrefix("api/v1");
app.useGlobalPipes(
  new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
);
const users = [];
try {
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
        username: "native_restore_" + randomBytes(7).toString("hex"),
        password: "Native-Restore-2026!",
        displayName: "تست بازیابی وندور",
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
    employee = await account("co_employee", admin.id);
  const credential = await call("/devices/credentials", {
    token: admin.token,
    body: {
      operation: "verify",
      name: "native-fixture",
      username: "fixture",
      password: "fixture-secret",
      hostKey: "ssh-ed25519 AAAA",
    },
  });
  assert.equal(credential.status, 201);
  async function waitResult(path, id) {
    for (let n = 0; n < 150; n++) {
      const item = (await call(path + "/backup-restores", { token: admin.token })).body.items.find(
        (item) => item.id === id,
      );
      if (item.status !== "running") return item;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw Error("Native restore did not finish");
  }
  let index = 0;
  for (const vendor of ["cisco", "mikrotik", "fortigate"]) {
    const registered = await call("/devices", {
      token: admin.token,
      body: {
        name: vendor + " fixture",
        type: vendor,
        vendor,
        host: "192.0.2." + (110 + index++),
        managementPort: 22,
        protocol: "ssh",
        environment: "lab",
        tags: [],
        credentialId: credential.body.id,
      },
    });
    assert.equal(registered.status, 201);
    const deviceId = registered.body.id,
      path = "/devices/" + deviceId;
    const previous = Buffer.from(
      files[vendor].toString().replace(/Restored|restored/g, "original"),
    );
    current.set(deviceId, previous);
    const response = await fetch(base + path + "/backup-upload", {
      method: "POST",
      headers: {
        authorization: "Bearer " + admin.token,
        "content-type": "application/octet-stream",
        "x-backup-filename": "native.cfg",
      },
      body: files[vendor],
    });
    assert.equal(response.status, 201);
    const artifact = await response.json();
    const initialWrites = writes;
    if (vendor === "mikrotik") {
      version = "7.15.3";
      assert.equal(
        (
          await call(path + "/backup-restore-preview", {
            token: admin.token,
            body: { artifactId: artifact.id },
          })
        ).status,
        409,
      );
      version = "7.16.2";
    }
    const preview = await call(path + "/backup-restore-preview", {
      token: admin.token,
      body: { artifactId: artifact.id },
    });
    assert.equal(preview.status, 201);
    assert.equal(preview.body.vendor, vendor);
    assert.equal(preview.body.connectorInvoked, false);
    assert.equal(writes, initialWrites);
    const confirmation = {
      intent: "execute",
      confirmation: "RESTORE BACKUP",
      sha256: preview.body.sha256,
    };
    assert.equal(
      (
        await call(path + `/backup-restores/${preview.body.id}/execute`, {
          token: admin.token,
          body: confirmation,
        })
      ).status,
      202,
    );
    const result = await waitResult(path, preview.body.id);
    assert.ok(result.safetyBackupId);
    assert.equal(result.vendor, vendor);
    assert.equal(result.connectorInvoked, true);
    assert.equal(
      (
        await call(path + `/backup-restores/${preview.body.id}/execute`, {
          token: admin.token,
          body: confirmation,
        })
      ).status,
      409,
    );
    const verifyPath = path + `/backup-restores/${preview.body.id}/verify`;
    if (vendor !== "fortigate") {
      assert.equal(result.status, "succeeded");
      assert.equal((await call(verifyPath, { token: admin.token, body: {} })).status, 409);
    } else {
      assert.equal(result.state, "awaiting_verification");
      assert.equal(result.status, "failed");
      assert.equal((await call(verifyPath, { token: other.token, body: {} })).status, 404);
      assert.equal((await call(verifyPath, { token: employee.token, body: {} })).status, 403);
      const beforeWrites = writes;
      assert.equal((await call(verifyPath, { token: admin.token, body: {} })).status, 409);
      assert.equal(writes, beforeWrites);
      current.set(deviceId, files[vendor]);
      await db.query(
        `UPDATE "device_restore_plans" SET "expiresAt"=now()-interval '20 minutes' WHERE "id"=$1`,
        [preview.body.id],
      );
      const verified = await call(verifyPath, { token: admin.token, body: {} });
      assert.equal(verified.status, 201);
      assert.equal(verified.body.verified, true);
      assert.equal(writes, beforeWrites);
      const final = (await call(path + "/backup-restores", { token: admin.token })).body.items.find(
        (item) => item.id === preview.body.id,
      );
      assert.equal(final.status, "succeeded");
      assert.equal(final.state, "configuration_verified");
      await db.query(
        `UPDATE "device_restore_plans" SET "status"='running', "state"='applying', "startedAt"=now()-interval '11 minutes', "heartbeatAt"=now() WHERE "id"=$1`,
        [preview.body.id],
      );
      assert.equal(
        (await call(path + "/backup-restores", { token: admin.token })).body.items.find(
          (item) => item.id === preview.body.id,
        ).interrupted,
        false,
      );
      assert.equal((await call(verifyPath, { token: admin.token, body: {} })).status, 409);
      await db.query(
        `UPDATE "device_restore_plans" SET "status"='running', "state"='applying', "startedAt"=now()-interval '11 minutes', "heartbeatAt"=now()-interval '11 minutes' WHERE "id"=$1`,
        [preview.body.id],
      );
      assert.equal(
        (await call(path + "/backup-restores", { token: admin.token })).body.items.find(
          (item) => item.id === preview.body.id,
        ).interrupted,
        true,
      );
      assert.equal((await call(verifyPath, { token: admin.token, body: {} })).status, 201);
      assert.equal(writes, beforeWrites);
      const [audit] = await db.query(
        `SELECT COUNT(*)::integer AS count FROM "device_restore_events" WHERE "planId"=$1 AND "action"='verified'`,
        [preview.body.id],
      );
      assert.equal(audit.count, 2);
    }
    if (vendor === "mikrotik") {
      current.set(deviceId, previous);
      mismatch = true;
      const retry = await call(path + "/backup-restore-preview", {
        token: admin.token,
        body: { artifactId: artifact.id },
      });
      assert.equal(retry.status, 201);
      await call(path + `/backup-restores/${retry.body.id}/execute`, {
        token: admin.token,
        body: confirmation,
      });
      const pending = await waitResult(path, retry.body.id);
      mismatch = false;
      assert.equal(pending.state, "applied_merge_needs_review");
      const beforeImports = imports;
      current.set(deviceId, files[vendor]);
      assert.equal(
        (
          await call(path + `/backup-restores/${retry.body.id}/verify`, {
            token: admin.token,
            body: {},
          })
        ).status,
        201,
      );
      assert.equal(imports, beforeImports);
    }
    const safety = await call(path + "/backups/" + result.safetyBackupId, { token: admin.token });
    assert.equal(safety.status, 200);
    assert.deepEqual(Buffer.from(safety.body.content, "base64"), previous);
  }
  console.log(
    "PASS: Cisco/MikroTik/FortiGate restore API, independent safety copy, replay denial, version gate, pending verification, read-only recovery and audit",
  );
} finally {
  if (users.length) await app.get(DataSource).getRepository(AppUser).delete(users);
  await app.close();
}
