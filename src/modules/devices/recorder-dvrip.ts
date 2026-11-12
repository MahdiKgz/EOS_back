import { Socket } from "node:net";
import { createHash } from "node:crypto";
import { CameraError, privateCameraHost, type CameraCredentials } from "./recorder-http";

type ReadName = "SystemInfo" | "StorageInfo" | "WorkState";
const uint = (value: string) => Number(BigInt(value));

export function dvripPasswordHash(password: string) {
  const digest = createHash("md5").update(password, "utf8").digest(),
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  return Array.from(
    { length: 8 },
    (_, i) => alphabet[(digest[i * 2] + digest[i * 2 + 1]) % 62],
  ).join("");
}
/** Only fixed reads and session lifecycle. No config, reboot, PTZ, format or arbitrary command. */
async function sessionRead<T>(
  host: string,
  port: number,
  credentials: CameraCredentials,
  version: 0 | 1,
  work: (
    read: (name: ReadName) => Promise<unknown>,
    login: Record<string, unknown>,
    wireVersion: number,
  ) => Promise<T>,
  responseTimeout: number,
): Promise<T> {
  privateCameraHost(host);
  if (!credentials.username || credentials.password === undefined)
    throw new CameraError("CAMERA_AUTH_REQUIRED", 401);
  const socket = new Socket();
  let session = 0,
    sequence = version ? 2 : 0,
    authenticated = false;
  const lifetime = setTimeout(() => socket.destroy(new CameraError("CAMERA_TIMEOUT", 504)), 30000);
  lifetime.unref();
  socket.on("error", () => undefined);
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new CameraError("NVR_DVRIP_CONNECT_TIMEOUT", 504));
      }, 3000);
      const cleanup = () => {
        clearTimeout(timer);
        socket.off("connect", connected);
        socket.off("error", failed);
      };
      const connected = () => {
          cleanup();
          resolve();
        },
        failed = () => {
          cleanup();
          reject(new CameraError("CAMERA_CONNECTION_FAILED", 502));
        };
      socket.once("connect", connected);
      socket.once("error", failed);
      socket.connect(port, host);
    });
    const packet = (command: number, payload: Record<string, unknown>, seq: number) => {
      const body = Buffer.from(JSON.stringify(payload) + (version ? "" : "\n\0"), "utf8"),
        header = Buffer.alloc(20);
      header[0] = 255;
      header[1] = version;
      header.writeUInt32LE(session, 4);
      header.writeUInt32LE(seq, 8);
      header.writeUInt16LE(command, 14);
      header.writeUInt32LE(body.length, 16);
      return Buffer.concat([header, body]);
    };
    const request = async (command: number, payload: Record<string, unknown>) => {
      const seq = sequence;
      sequence += version ? 2 : 1;
      return new Promise<Record<string, unknown>>((resolve, reject) => {
        let data = Buffer.alloc(0),
          settled = false,
          total = 0,
          count = 0,
          limit = 0;
        const parts = new Map<number, Buffer>();
        const finish = (error?: CameraError, result?: Record<string, unknown>) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          socket.off("data", received);
          socket.off("error", failed);
          socket.off("close", failed);
          if (error) reject(error);
          else resolve(result!);
        };
        const timer = setTimeout(
          () =>
            finish(
              new CameraError(
                command === 1000 ? "NVR_DVRIP_LOGIN_TIMEOUT" : "NVR_DVRIP_READ_TIMEOUT",
                504,
              ),
            ),
          responseTimeout,
        );
        const failed = () => finish(new CameraError("CAMERA_CONNECTION_FAILED", 502));
        const received = (chunk: Buffer) => {
          if (data.length + chunk.length + total > 524608) {
            finish(new CameraError("CAMERA_RESPONSE_TOO_LARGE", 502));
            return;
          }
          data = Buffer.concat([data, chunk]);
          while (!settled && data.length >= 20) {
            const length = data.readUInt32LE(16),
              fragments = Math.max(data[12], 1),
              fragment = data[13],
              responseSeq = data.readUInt32LE(8);
            if (
              data[0] !== 255 ||
              ![0, 1].includes(data[1]) ||
              data.readUInt16LE(14) !== command + 1 ||
              !(responseSeq === seq || (version === 1 && responseSeq === seq + 1)) ||
              length > 524288 ||
              fragments > 16 ||
              fragment >= fragments ||
              (limit && limit !== fragments) ||
              parts.has(fragment) ||
              (command !== 1000 && data.readUInt32LE(4) !== session)
            ) {
              finish(new CameraError("NVR_STORAGE_RESPONSE_INVALID", 502));
              return;
            }
            if (data.length < 20 + length) return;
            limit = fragments;
            const headerSession = data.readUInt32LE(4);
            parts.set(fragment, data.subarray(20, 20 + length));
            total += length;
            count++;
            data = data.subarray(20 + length);
            if (count < limit) continue;
            if (data.length) {
              finish(new CameraError("NVR_STORAGE_RESPONSE_INVALID", 502));
              return;
            }
            try {
              const payload = Buffer.concat(Array.from({ length: limit }, (_, i) => parts.get(i)!));
              let end = payload.length;
              while (end && [0, 10, 13].includes(payload[end - 1])) end--;
              const result = JSON.parse(payload.toString("utf8", 0, end));
              if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error();
              if ([205, 206, 207, 212].includes(result.Ret)) {
                finish(new CameraError("NVR_ACCOUNT_LOCKED", 401));
                return;
              }
              if ([105, 106, 202, 203, 204].includes(result.Ret)) {
                finish(new CameraError("CAMERA_AUTH_FAILED", 401));
                return;
              }
              if ([103, 107, 213].includes(result.Ret)) {
                finish(new CameraError("NVR_ACCESS_DENIED", 403));
                return;
              }
              if (result.Ret === 102 && command === 1000) {
                finish(new CameraError("NVR_DVRIP_VERSION_UNSUPPORTED", 422));
                return;
              }
              if (result.Ret !== 100) {
                finish(new CameraError("NVR_STORAGE_UNSUPPORTED", 422));
                return;
              }
              if (command === 1000) {
                if (result.DataUseAES === true) {
                  finish(new CameraError("NVR_DVRIP_ENCRYPTION_REQUIRED", 422));
                  return;
                }
                const sid =
                  typeof result.SessionID === "string" &&
                  /^0x[0-9a-f]{1,12}$/i.test(result.SessionID)
                    ? uint(result.SessionID)
                    : null;
                if (!sid || sid > 0xffffffff || headerSession !== sid) throw new Error();
                session = sid;
                authenticated = true;
              }
              finish(undefined, result);
            } catch {
              finish(new CameraError("NVR_STORAGE_RESPONSE_INVALID", 502));
            }
          }
        };
        socket.on("data", received);
        socket.once("error", failed);
        socket.once("close", failed);
        socket.write(packet(command, payload, seq));
      });
    };
    const login = await request(1000, {
      EncryptType: "MD5",
      LoginType: "DVRIP-Web",
      PassWord: dvripPasswordHash(credentials.password),
      UserName: credentials.username,
    });
    const read = async (name: ReadName) => {
      const result = await request(1020, {
        Name: name,
        SessionID: `0x${session.toString(16).padStart(8, "0")}`,
      });
      if ((result.Name !== undefined && result.Name !== name) || !Object.hasOwn(result, name))
        throw new CameraError("NVR_STORAGE_RESPONSE_INVALID", 502);
      return result[name];
    };
    return await work(read, login, version);
  } finally {
    clearTimeout(lifetime);
    if (authenticated && !socket.destroyed) {
      const body = Buffer.from(
          JSON.stringify({ Name: "", SessionID: `0x${session.toString(16).padStart(8, "0")}` }) +
            (version ? "" : "\n\0"),
        ),
        header = Buffer.alloc(20);
      header[0] = 255;
      header[1] = version;
      header.writeUInt32LE(session, 4);
      header.writeUInt32LE(sequence, 8);
      header.writeUInt16LE(1002, 14);
      header.writeUInt32LE(body.length, 16);
      socket.end(Buffer.concat([header, body]));
      const cleanup = setTimeout(() => socket.destroy(), 1000);
      cleanup.unref();
      socket.once("close", () => clearTimeout(cleanup));
    } else socket.destroy();
  }
}
async function negotiate<T>(
  host: string,
  port: number,
  credentials: CameraCredentials,
  work: Parameters<typeof sessionRead<T>>[4],
  responseTimeout = 4500,
) {
  try {
    return await sessionRead(host, port, credentials, 0, work, responseTimeout);
  } catch (e) {
    if (
      !(e instanceof CameraError) ||
      !["NVR_DVRIP_LOGIN_TIMEOUT", "NVR_DVRIP_VERSION_UNSUPPORTED"].includes(e.code)
    )
      throw e;
  }
  // Same credentials, one alternative framing only after no login reply/version mismatch.
  // Authentication/permission/lock failures are never retried.
  return sessionRead(host, port, credentials, 1, work, responseTimeout);
}
export async function verifyDvrip(host: string, port: number, credentials: CameraCredentials) {
  return negotiate(host, port, credentials, async (read) => {
    const value = await read("SystemInfo");
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw new CameraError("NVR_DVRIP_IDENTITY_INVALID", 502);
    const info = value as Record<string, unknown>;
    const identity: Record<string, string> = {};
    for (const [label, field] of [
      ["Model", "DeviceModel"],
      ["FirmwareVersion", "SoftWareVersion"],
    ]) {
      const text = info[field];
      if (typeof text === "string" && text.trim()) identity[label] = text.trim().slice(0, 160);
    }
    return identity;
  });
}

function parseDvripDisks(input: unknown) {
  if (!Array.isArray(input) || input.length > 32)
    throw new CameraError("NVR_STORAGE_RESPONSE_INVALID", 502);
  const mb = (raw: unknown) => {
    const value =
      typeof raw === "string" && /^0x[0-9a-f]{1,12}$/i.test(raw)
        ? parseInt(raw.slice(2), 16)
        : typeof raw === "number" && Number.isInteger(raw)
          ? raw
          : NaN;
    const bytes = value * 1048576;
    return Number.isSafeInteger(bytes) && bytes >= 0 ? bytes : null;
  };
  return input.map((raw, index) => {
    if (
      !raw ||
      typeof raw !== "object" ||
      !Array.isArray(raw.Partition) ||
      raw.Partition.length > 32
    )
      throw new CameraError("NVR_STORAGE_RESPONSE_INVALID", 502);
    const partitions = raw.Partition as Record<string, unknown>[];
    const sum = (key: string) => {
      const numbers = partitions.map((p) => mb(p[key]));
      const result = numbers.reduce<number>((s, n) => s + (n ?? 0), 0);
      return numbers.length && numbers.every((n) => n !== null) && Number.isSafeInteger(result)
        ? result
        : null;
    };
    const capacityBytes = sum("TotalSpace"),
      rawFree = sum("RemainSpace"),
      freeBytes =
        rawFree !== null && capacityBytes !== null && rawFree <= capacityBytes ? rawFree : null;
    const id =
      typeof raw.PlysicalNo === "number" && Number.isSafeInteger(raw.PlysicalNo)
        ? String(raw.PlysicalNo)
        : String(index);
    // Partition.Status is firmware-dependent. Never label zero or a successful API call as a SMART pass.
    const statuses = partitions
      .map((p) => (Number.isSafeInteger(p.Status) ? String(p.Status) : "?"))
      .join(",")
      .slice(0, 120);
    return {
      id,
      name: `HDD ${index + 1}`,
      capacityBytes,
      freeBytes,
      usedBytes: capacityBytes !== null && freeBytes !== null ? capacityBytes - freeBytes : null,
      health: "unknown",
      reportedState: `partition_status:${statuses}`,
      temperatureC: null,
      smart: "unknown",
    };
  });
}

export async function inspectDvrip(host: string, port: number, credentials: CameraCredentials) {
  return negotiate(
    host,
    port,
    credentials,
    async (read, login) => {
      const errors: string[] = [];
      const optional = async <T>(name: ReadName, parse: (value: unknown) => T) => {
        try {
          return parse(await read(name));
        } catch {
          errors.push(name);
          return null;
        }
      };
      const channels = await optional("WorkState", (value) => {
        const state = value as {
          ChannelState?: { Record?: unknown; Bitrate?: unknown }[];
          AlarmState?: { VideoLoss?: unknown };
        } | null;
        if (!Array.isArray(state?.ChannelState)) throw new Error("Missing channel status");
        const rawLoss = state.AlarmState?.VideoLoss;
        const loss =
          typeof rawLoss === "number"
            ? rawLoss
            : typeof rawLoss === "string" && /^0x[0-9a-f]{1,8}$/i.test(rawLoss)
              ? Number(rawLoss)
              : NaN;
        const limit =
          typeof login.ChannelNum === "number" &&
          Number.isInteger(login.ChannelNum) &&
          login.ChannelNum > 0
            ? Math.min(login.ChannelNum, 128)
            : 128;
        return state.ChannelState.slice(0, limit).map((channel, index) => ({
          index: index + 1,
          recording: typeof channel?.Record === "boolean" ? channel.Record : null,
          signalPresent:
            Number.isInteger(loss) && loss >= 0 && loss <= 0xffffffff && index < 32
              ? (BigInt(loss) & (1n << BigInt(index))) === 0n
              : null,
          bitrateBps:
            typeof channel?.Bitrate === "number" &&
            Number.isSafeInteger(channel.Bitrate * 1024) &&
            channel.Bitrate >= 0
              ? channel.Bitrate * 1024
              : null,
        }));
      });
      const disks = await optional("StorageInfo", parseDvripDisks);
      return { checkedAt: new Date().toISOString(), channels, disks, errors };
    },
    2500,
  );
}
