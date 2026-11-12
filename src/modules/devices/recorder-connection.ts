import { verifyRtsp } from "./recorder-rtsp";
import {
  BadGatewayException,
  ConflictException,
  UnprocessableEntityException,
} from "@nestjs/common";
import { dvripPasswordHash, verifyDvrip } from "./recorder-dvrip";
import type { RecorderConnectionDto } from "./device.dto";
import { cameraHttp, privateCameraHost, recorderOnvifPath } from "./recorder-http";
import { verifyRecorder } from "./recorder-onvif";

const appWebActive = new Set<string>();
const appWebCooldown = new Map<string, number>();

async function withAppWeb<T>(
  origin: string,
  credentials: RecorderConnectionDto,
  read: (
    request: (path: "/CGI/Custom/version" | "/CGI/Record/storageinfo") => Promise<unknown>,
  ) => Promise<T>,
) {
  const account = JSON.stringify([origin, credentials.username]);
  const now = Date.now();
  for (const [key, until] of appWebCooldown) {
    if (until <= now) appWebCooldown.delete(key);
  }
  if (appWebActive.has(origin) || appWebCooldown.has(account))
    throw new ConflictException(
      "نشست AppWeb در حال اجراست یا اخیراً ورود رد شده است. کمی بعد تلاش کنید.",
    );
  appWebActive.add(origin);
  let cookie = "";
  let loggedIn = false;
  const rejectLogin = () => {
    if (appWebCooldown.size >= 256) {
      const oldest = appWebCooldown.keys().next().value;
      if (oldest !== undefined) appWebCooldown.delete(oldest);
    }
    appWebCooldown.set(account, Date.now() + 60000);
    throw new Error("AppWeb login refused");
  };
  const request = async (path: string, body?: string) => {
    const response = await cameraHttp(new URL(origin + path), {
      method: body ? "POST" : "GET",
      body,
      timeout: 3000,
      maxBytes: 65536,
      headers: {
        ...(cookie ? { Cookie: cookie } : {}),
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
    });
    if (path.endsWith("/userCheck") && [401, 403].includes(response.status)) rejectLogin();
    if (response.status !== 200) throw new Error("AppWeb request failed");
    const data = JSON.parse(response.body.toString("utf8"));
    if (path.endsWith("/userCheck") && ["203", "206", "207"].includes(String(data.statusValue)))
      rejectLogin();
    if (data.statusValue !== undefined && String(data.statusValue) !== "200")
      throw new Error("AppWeb rejected request");
    return { data, headers: response.headers };
  };
  const validSession = (value: unknown): value is string =>
    typeof value === "string" && /^[\w.-]{1,256}$/.test(value);
  try {
    const challenge = await request(`/CGI/Security/sessionLogin?timestamp:${Date.now()}`);
    const { salt, sessionID } = challenge.data;
    if (
      String(challenge.data.statusValue) !== "200" ||
      typeof salt !== "string" ||
      salt.length > 256 ||
      !validSession(sessionID)
    )
      throw new Error("Invalid AppWeb challenge");
    cookie = (challenge.headers["set-cookie"] ?? [])
      .slice(0, 8)
      .map((value) => value.split(";")[0])
      .filter(
        (value) =>
          /^[\w.-]+=[\x21-\x3a\x3c-\x7e]*$/.test(value) && !value.startsWith("webSessionID="),
      )
      .join("; ")
      .slice(0, 2048);
    const { data: login } = await request(
      "/CGI/Security/SelfExt/userCheck",
      JSON.stringify({
        Username: credentials.username,
        Password: dvripPasswordHash(dvripPasswordHash(credentials.password) + salt),
        Sessionid: sessionID,
      }),
    );
    if (String(login.statusValue) !== "200" || !validSession(login.sessionID))
      throw new Error("Invalid AppWeb login");
    cookie = [cookie, `webSessionID=${login.sessionID}`].filter(Boolean).join("; ");
    loggedIn = true;
    return await read(async (path) => (await request(path)).data);
  } catch {
    throw new BadGatewayException(
      "تأیید AppWeb انجام نشد. تنظیمات اتصال و اطلاعات ورود را بررسی کنید.",
    );
  } finally {
    if (loggedIn)
      await cameraHttp(new URL(origin + "/CGI/Security/Lougout"), {
        method: "POST",
        headers: { Cookie: cookie },
        timeout: 1200,
        maxBytes: 4096,
      }).catch(() => undefined);
    appWebActive.delete(origin);
  }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Invalid AppWeb object");
  return value as Record<string, unknown>;
}

function appWebCapacity(value: unknown) {
  const match =
    typeof value === "string" ? /^\s*(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)\s*$/i.exec(value) : null;
  if (!match) return null;
  const bytes = Math.round(
    Number(match[1]) * 1024 ** ["B", "KB", "MB", "GB", "TB"].indexOf(match[2].toUpperCase()),
  );
  return Number.isSafeInteger(bytes) ? bytes : null;
}

export async function inspectAppWeb(
  host: string,
  port: number,
  credentials: RecorderConnectionDto,
) {
  privateCameraHost(host);
  const origin = `${credentials.https ? "https" : "http"}://${host}:${port}`;
  return withAppWeb(origin, credentials, async (request) => {
    const errors: string[] = [];
    let configuredChannels: number | null = null;
    try {
      const info = object(await request("/CGI/Custom/version"));
      const counts = [info.VideoInChannel, info.DigChannel].filter(
        (value): value is number =>
          typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 128,
      );
      if (counts.length) configuredChannels = Math.max(...counts);
    } catch {
      errors.push("ChannelCount");
    }
    let disks = null;
    try {
      const storage = await request("/CGI/Record/storageinfo");
      if (!Array.isArray(storage)) throw new Error("Invalid AppWeb storage");
      disks = storage.slice(0, 32).map((item, index) => {
        const disk = object(item);
        const capacityBytes = appWebCapacity(disk.StorageSize);
        const free = appWebCapacity(disk.StorageRemain);
        const state = typeof disk.StorageState === "string" ? disk.StorageState.slice(0, 80) : "";
        return {
          id: String(index + 1),
          capacityBytes,
          freeBytes: capacityBytes !== null && free !== null && free <= capacityBytes ? free : null,
          reportedState:
            state === "StateOK"
              ? "سالم طبق گزارش دستگاه"
              : state === "StateErr"
                ? "خطای دیسک"
                : state || "نامشخص",
        };
      });
    } catch {
      errors.push("StorageInfo");
    }
    return {
      checkedAt: new Date().toISOString(),
      configuredChannels,
      channels: null,
      disks,
      errors,
    };
  });
}

export async function verifyRecorderConnection(
  host: string,
  port: number,
  credentials: RecorderConnectionDto,
) {
  const origin = `${credentials.https ? "https" : "http"}://${host}:${port}`;
  let mode = credentials.mode ?? "onvif";
  if (mode === "auto") {
    try {
      privateCameraHost(host);
      const probe = await cameraHttp(new URL(origin + "/doc/script/common.js"), {
        timeout: 1500,
        maxBytes: 65536,
      });
      const script = probe.body.toString("utf8");
      if (
        probe.status === 200 &&
        script.includes("/CGI/Security/") &&
        script.includes("webSessionID")
      )
        mode = "appweb";
    } catch {
      // A missing AppWeb endpoint can coexist with an ONVIF service.
    }
    if (mode === "auto") {
      const probe = await cameraHttp(new URL(origin + recorderOnvifPath(credentials.onvifPath)), {
        timeout: 1500,
        maxBytes: 65536,
      }).catch(() => undefined);
      if (
        !probe ||
        !(
          probe.status === 405 ||
          (probe.status === 401 && probe.headers["www-authenticate"]) ||
          (probe.status === 200 && /onvif\.org|soap-envelope/i.test(probe.body.toString("utf8")))
        )
      )
        throw new UnprocessableEntityException(
          "روش اتصال شناسایی نشد. روش را دستی انتخاب کنید یا تجهیز را بدون تأیید ثبت کنید.",
        );
      mode = "onvif";
    }
  }
  if (mode === "rtsp") return { identity: await verifyRtsp(host, port, credentials), mode };
  if (mode === "dvrip") {
    if (credentials.https)
      throw new UnprocessableEntityException("برای اتصال DVRIP گزینهٔ HTTPS را خاموش کنید.");
    try {
      return { identity: await verifyDvrip(host, port, credentials), mode };
    } catch {
      throw new BadGatewayException(
        "تأیید DVRIP انجام نشد. آدرس، پورت و اطلاعات ورود را بررسی کنید.",
      );
    }
  }
  if (mode === "appweb") {
    try {
      privateCameraHost(host);
    } catch {
      throw new UnprocessableEntityException("برای اتصال AppWeb آدرس IPv4 خصوصی وارد کنید.");
    }
    const identity = await withAppWeb(origin, credentials, async (read) => {
      const data = object(await read("/CGI/Custom/version"));
      return {
        ...(typeof data.HardWareVersion === "string"
          ? { Model: data.HardWareVersion.slice(0, 160) }
          : {}),
        ...(typeof data.Version === "string"
          ? { FirmwareVersion: data.Version.slice(0, 160) }
          : {}),
      };
    });
    return { identity, mode };
  }
  return { identity: await verifyRecorder(host, port, credentials), mode };
}
