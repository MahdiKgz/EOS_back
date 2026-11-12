// Loopback-only UI harness; fixture PTY recognizes fixed strings and never runs OS commands.
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
config({ quiet: true });
if (process.env.NODE_ENV === "production") throw new Error("UI fixture requires development/test");
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js"),
  { DeviceTerminalService } = require("../dist/modules/devices/device-terminal.service.js");
const server = spawn("python3", ["test/fixtures/terminal-server.py"], {
  stdio: ["ignore", "pipe", "pipe"],
});
server.stderr.on("data", () => {});
const lines = createInterface({ input: server.stdout });
let app,
  userId,
  stopping = false;
async function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  try {
    if (app) {
      await app.get(DeviceTerminalService).onModuleDestroy();
      if (userId) await app.get(DataSource).getRepository(AppUser).delete(userId);
      await app.close();
    }
  } finally {
    lines.close();
    server.kill("SIGTERM");
    process.exit(code);
  }
}
process.on("SIGTERM", () => void stop());
process.on("SIGINT", () => void stop());
try {
  const [line] = await once(lines, "line", { signal: AbortSignal.timeout(10000) }),
    fixture = JSON.parse(line);
  app = await NestFactory.create(AppModule, { logger: false });
  app.setGlobalPrefix("api/v1");
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
  await app.listen(4001, "127.0.0.1");
  async function post(path, body, token) {
    const response = await fetch("http://127.0.0.1:4001/api/v1" + path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: "Bearer " + token } : {}),
      },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error("Fixture request failed: " + path + " " + response.status);
    return response.json();
  }
  const username = "ui_terminal_" + randomBytes(4).toString("hex"),
    account = await post("/auth/register", {
      username,
      password: "UI-Terminal-Review-2026!",
      displayName: "بررسی ترمینال آزمایشی",
    });
  userId = account.user.id;
  await app.get(DataSource).getRepository(AppUser).update(userId, { role: "co_admin" });
  const credential = await post(
    "/devices/credentials",
    {
      name: "SSH آزمایشی",
      operation: "verify",
      username: "fixture",
      password: "fixture-secret",
      hostKey: fixture.hostKey,
    },
    account.accessToken,
  );
  const device = await post(
    "/devices",
    {
      name: "سرور آزمایشی ترمینال",
      type: "linux_edge",
      vendor: "linux",
      host: "127.0.0.1",
      managementPort: fixture.port,
      protocol: "ssh",
      environment: "lab",
      tags: [],
      credentialId: credential.id,
    },
    account.accessToken,
  );
  console.log(JSON.stringify({ username, deviceId: device.id }));
} catch {
  await stop(1);
}
