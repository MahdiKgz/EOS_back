import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import "reflect-metadata";
import { config } from "dotenv";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DataSource } from "typeorm";
import { onvifFixture } from "./fixtures/onvif-server.mjs";
config({ quiet: true });
if (process.env.NODE_ENV === "production") throw new Error("UI fixtures require development/test");
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.DEVICE_CREDENTIAL_KEY = randomBytes(32).toString("hex");
const require = createRequire(import.meta.url),
  { AppModule } = require("../dist/app.module.js"),
  { AppUser } = require("../dist/modules/users/user.entity.js");
let app,
  fixture,
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
    await fixture?.close();
  } finally {
    process.exit(code);
  }
}
process.on("SIGTERM", () => void stop());
process.on("SIGINT", () => void stop());
try {
  fixture = await onvifFixture();
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
    if (!response.ok) throw new Error("UI fixture request failed " + path + " " + response.status);
    return response.json();
  }
  const username = "ui_camera_" + randomBytes(4).toString("hex"),
    account = await post("/auth/register", {
      username,
      password: "UI-Camera-Review-2026!",
      displayName: "بررسی موجودی دوربین",
    });
  userId = account.user.id;
  await app.get(DataSource).getRepository(AppUser).update(userId, { role: "co_admin" });
  const company = await post("/devices/companies", { name: "شرکت نمونه دوم" }, account.accessToken),
    devices = [];
  for (const [index, type] of ["camera", "nvr", "dvr"].entries()) {
    const input = {
      name: ["دوربین ورودی ساختمان", "ضبط‌کننده شرکت دوم", "ضبط‌کننده انبار"][index],
      companyId: index === 1 ? company.id : userId,
      vendor: "fixture-" + type,
      type,
      host: fixture.host,
      managementPort: fixture.port,
      protocol: "api",
      environment: "lab",
      location: "طبقه اول",
      tags: [],
    };
    const proof = await post(
      "/devices/draft-connection",
      {
        device: input,
        recorder: {
          username: "fixture",
          password: "fixture-secret",
          https: false,
          mode: "onvif",
          onvifPath: "/custom/device_service",
        },
        saveRecorderConnection: true,
      },
      account.accessToken,
    );
    devices.push(
      await post(
        "/devices",
        { ...input, verificationToken: proof.verificationToken },
        account.accessToken,
      ),
    );
  }
  await post(
    "/devices",
    {
      name: "سرور شبکه آزمایشی",
      type: "linux_edge",
      vendor: "linux",
      host: "192.0.2.199",
      managementPort: 22,
      protocol: "ssh",
      environment: "lab",
      tags: [],
      companyId: userId,
    },
    account.accessToken,
  );
  for (let index = 0; index < 21; index++)
    await post(
      "/devices",
      {
        name: "سرور نمونه " + String(index + 1).padStart(2, "0"),
        type: "linux_edge",
        vendor: "linux",
        host: "192.0.2." + (150 + index),
        managementPort: 22,
        protocol: "ssh",
        environment: "lab",
        tags: [],
        companyId: userId,
      },
      account.accessToken,
    );
  const { Device } = require("../dist/modules/devices/device.entity.js");
  await app
    .get(DataSource)
    .getRepository(Device)
    .update(
      { workspaceOwnerId: userId, host: "192.0.2.199" },
      { status: "online", lastSeenAt: new Date() },
    );
  process.stdin.on("data", (chunk) => {
    const command = chunk.toString().trim();
    if (command === "fail") {
      fixture.setFailed(true);
      console.log("Fixture unavailable");
    }
    if (command === "recover") {
      fixture.setFailed(false);
      console.log("Fixture recovered");
    }
  });
  console.log(
    JSON.stringify({ username, devices: devices.map((d) => ({ id: d.id, type: d.type })) }),
  );
} catch {
  await stop(1);
}
