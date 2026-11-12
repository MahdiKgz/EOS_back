// Disposable local UI test API. SSH is replaced in this process only; no network connector is invoked.
import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";

config({ quiet: true });
if (process.env.NODE_ENV === "production")
  throw new Error("UI fixtures require development/test environment");
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url);
const directory = mkdtempSync(join(tmpdir(), "eos-restore-ui-"));
mkdirSync(join(directory, "etc"));
writeFileSync(join(directory, "etc", "hostname"), "fixture-host\n");
const archive = execFileSync("tar", ["-czf", "-", "-C", directory, "etc"]);
const transport = require("../dist/modules/devices/ssh-transport.js");
const files = {
  linux_edge: archive,
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
transport.runSshCommand = async (device, _credentials, command, options) => {
  await new Promise((resolve) => setTimeout(resolve, 350));
  if (command.includes("tar -czf")) return archive;
  if (command.startsWith(":put")) return Buffer.from("7.16.2");
  if (
    command === "show running-config" ||
    command === "scp -f sys_config" ||
    command.startsWith("/export")
  )
    return current.get(device.id);
  if (command === "sftp" || command.startsWith("scp -t")) {
    staged.set(device.id, (options.sftpUpload ?? options.scpUpload).content);
    if (device.type === "fortigate") {
      const ready = setTimeout(() => current.set(device.id, staged.get(device.id)), 1000);
      ready.unref();
    }
    return Buffer.alloc(0);
  }
  if (
    command.startsWith("configure replace") ||
    (command.startsWith("/import") && !command.includes("dry-run"))
  ) {
    current.set(device.id, staged.get(device.id));
    return Buffer.alloc(0);
  }
  if (
    command === "configure confirm" ||
    command.startsWith("/import") ||
    command.startsWith("/file remove") ||
    command.startsWith("delete /force")
  )
    return Buffer.alloc(0);
  if (!command.includes("SOAR_ETC_RESTORE_V1") || !options.stdin)
    throw new Error("Unexpected fixture command");
  const payload = JSON.parse(options.stdin.toString());
  return Buffer.from(
    JSON.stringify({
      receiver: "SOAR_ETC_RESTORE_V1",
      intent: payload.intent,
      verified: true,
      entries: payload.entries.length,
    }),
  );
};
const { AppModule } = require("../dist/app.module.js");
const { AppUser } = require("../dist/modules/users/user.entity.js");
let app,
  userId,
  stopping = false;
async function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  try {
    if (app) {
      if (userId) await app.get(DataSource).getRepository(AppUser).delete(userId);
      await app.close();
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
    process.exit(code);
  }
}
process.on("SIGTERM", () => void stop());
process.on("SIGINT", () => void stop());
try {
  app = await NestFactory.create(AppModule, { logger: false });
  app.useBodyParser("raw", { type: "application/octet-stream", limit: 20 * 1024 * 1024 });
  app.setGlobalPrefix("api/v1");
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
  await app.listen(4001, "127.0.0.1");
  const base = "http://127.0.0.1:4001/api/v1";
  async function post(path, body, token) {
    const response = await fetch(base + path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: "Bearer " + token } : {}),
      },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`Fixture request ${path}: ${response.status}`);
    return response.json();
  }
  const username = "ui_restore_" + randomBytes(4).toString("hex");
  const account = await post("/auth/register", {
    username,
    password: "UI-Restore-Review-2026!",
    displayName: "بررسی بازیابی آزمایشی",
  });
  userId = account.user.id;
  await app.get(DataSource).getRepository(AppUser).update(userId, { role: "co_admin" });
  const credential = await post(
    "/devices/credentials",
    {
      name: "اعتبارنامه آزمایشی",
      operation: "verify",
      username: "fixture",
      password: "fixture-secret",
      hostKey: "ssh-ed25519 AAAA",
    },
    account.accessToken,
  );
  const devices = [];
  const secondaryCompany = await post(
    "/devices/companies",
    { name: "شرکت نمونهٔ دوم" },
    account.accessToken,
  );
  let index = 0;
  for (const type of ["linux_edge", "cisco", "mikrotik", "fortigate"]) {
    const device = await post(
      "/devices",
      {
        name: type + " نمونهٔ بازیابی",
        type,
        vendor: type === "linux_edge" ? "linux" : type,
        host: "192.0.2." + (191 + index++),
        managementPort: 22,
        protocol: "ssh",
        environment: "lab",
        tags: [],
        credentialId: credential.id,
        ...(type === "fortigate" ? { companyId: secondaryCompany.id } : {}),
      },
      account.accessToken,
    );
    current.set(
      device.id,
      type === "linux_edge"
        ? archive
        : Buffer.from(files[type].toString().replace(/Restored|restored/g, "original")),
    );
    const upload = await fetch(`${base}/devices/${device.id}/backup-upload`, {
      method: "POST",
      headers: {
        authorization: "Bearer " + account.accessToken,
        "content-type": "application/octet-stream",
        "x-backup-filename": type + (type === "linux_edge" ? ".tar.gz" : ".cfg"),
      },
      body: files[type],
    });
    if (upload.status !== 201) throw new Error("Fixture upload failed");
    devices.push({ type, deviceId: device.id });
  }
  const cisco = devices.find((device) => device.type === "cisco");
  const evidence = await fetch(`${base}/devices/${cisco.deviceId}/backup-upload`, {
    method: "POST",
    headers: {
      authorization: "Bearer " + account.accessToken,
      "content-type": "application/octet-stream",
      "x-backup-filename": "deleted-evidence.cfg",
    },
    body: files.cisco,
  });
  if (evidence.status !== 201) throw new Error("Fixture evidence upload failed");
  const evidenceFile = await evidence.json();
  const removed = await fetch(`${base}/devices/${cisco.deviceId}/backups/${evidenceFile.id}`, {
    method: "DELETE",
    headers: { authorization: "Bearer " + account.accessToken },
  });
  if (!removed.ok) throw new Error("Fixture evidence cleanup failed");
  await app.get(DataSource).query(
    `INSERT INTO "device_backup_events" ("deviceId", "actorId", "actorName", "actorUsername", "action", "deviceName", "host", "vendor", "companyName", "durationMs", "failureCode")
    SELECT $1, $2, 'کاربر نمونهٔ تاریخچه', $3, 'failed', 'سرور نمونهٔ تاریخچه', '192.0.2.191', 'linux', 'شرکت اصلی', 1234, 'collection_failed' FROM generate_series(1, 22)`,
    [devices[0].deviceId, userId, username],
  );
  console.log(JSON.stringify({ username, devices }));
} catch {
  console.error("Restore UI fixture startup failed.");
  await stop(1);
}
