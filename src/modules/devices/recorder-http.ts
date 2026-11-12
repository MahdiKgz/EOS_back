import { isIP } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import * as http from "node:http";
import * as https from "node:https";

export class CameraError extends Error {
  constructor(
    readonly code: string,
    readonly statusCode = 400,
  ) {
    super(code);
    this.name = "CameraError";
  }
}

export function privateCameraHost(value: unknown) {
  const host = String(value ?? "").trim();
  if (isIP(host) !== 4) throw new CameraError("CAMERA_PRIVATE_IP_REQUIRED");
  const [a, b] = host.split(".").map(Number);
  if (!(a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)))
    throw new CameraError("CAMERA_PRIVATE_IP_REQUIRED");
  return host;
}

export type CameraCredentials = { username?: string; password?: string };
export function recorderOnvifPath(value?: string) {
  const path = value ?? "/onvif/device_service";
  if (!/^\/(?!\/)[a-zA-Z0-9_./-]{1,255}$/.test(path) || path.includes(".."))
    throw new CameraError("CAMERA_PATH_INVALID");
  return path;
}
type HttpResult = { status: number; headers: http.IncomingHttpHeaders; body: Buffer };

/** Never follows a redirect or resolves a hostname. Device-returned URLs remain pinned to its private IP. */
export function cameraHttp(
  url: URL,
  options: {
    method?: string;
    body?: string;
    headers?: Record<string, string>;
    timeout?: number;
    maxBytes?: number;
  },
): Promise<HttpResult> {
  privateCameraHost(url.hostname);
  return new Promise((resolve, reject) => {
    const body = options.body;
    const request = (url.protocol === "https:" ? https : http).request(
      url,
      {
        method: options.method ?? "GET",
        rejectUnauthorized: true,
        headers: {
          ...(body ? { "Content-Length": String(Buffer.byteLength(body)) } : {}),
          ...options.headers,
        },
      },
      (response) => {
        let length = 0;
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => {
          length += chunk.length;
          if (length > (options.maxBytes ?? 512 * 1024)) {
            response.destroy();
            request.destroy();
            reject(new CameraError("CAMERA_RESPONSE_TOO_LARGE", 502));
          } else chunks.push(chunk);
        });
        response.once("end", () =>
          resolve({
            status: response.statusCode ?? 500,
            headers: response.headers,
            body: Buffer.concat(chunks),
          }),
        );
        response.once("error", () => reject(new CameraError("CAMERA_CONNECTION_FAILED", 502)));
      },
    );
    request.setTimeout(options.timeout ?? 4000, () => {
      request.destroy();
      reject(new CameraError("CAMERA_TIMEOUT", 504));
    });
    // An inactivity timeout alone allows an endless trickle to hold a monitor lease.
    const deadline = setTimeout(() => {
      request.destroy();
      reject(new CameraError("CAMERA_TIMEOUT", 504));
    }, options.timeout ?? 4000);
    deadline.unref();
    request.once("close", () => clearTimeout(deadline));
    request.once("error", () => reject(new CameraError("CAMERA_CONNECTION_FAILED", 502)));
    request.end(body);
  });
}

export function cameraAuthorization(
  challenge: string,
  method: string,
  url: URL,
  credentials: CameraCredentials,
  requestTarget = `${url.pathname}${url.search}`,
) {
  if (!credentials.username || !credentials.password) return undefined;
  if (/^Basic\s/i.test(challenge))
    return `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString("base64")}`;
  if (!/^Digest\s/i.test(challenge)) return undefined;
  const parts: Record<string, string> = {};
  for (const match of challenge.matchAll(/(\w+)=(?:"([^"]*)"|([^,\s]+))/g))
    parts[match[1].toLowerCase()] = match[2] ?? match[3];
  const algorithm = (parts.algorithm ?? "MD5").toUpperCase();
  if (
    !["MD5", "MD5-SESS", "SHA-256", "SHA-256-SESS"].includes(algorithm) ||
    !parts.nonce ||
    !parts.realm
  )
    return undefined;
  const hash = (value: string) =>
    createHash(algorithm.startsWith("SHA-256") ? "sha256" : "md5")
      .update(value)
      .digest("hex");
  const cnonce = randomBytes(12).toString("hex"),
    nc = "00000001",
    uri = requestTarget;
  const qop = parts.qop
    ?.split(",")
    .map((v) => v.trim())
    .includes("auth")
    ? "auth"
    : undefined;
  if (parts.qop && !qop) return undefined;
  let ha1 = hash(`${credentials.username}:${parts.realm}:${credentials.password}`);
  if (algorithm.endsWith("-SESS")) ha1 = hash(`${ha1}:${parts.nonce}:${cnonce}`);
  const response = hash(
    qop
      ? `${ha1}:${parts.nonce}:${nc}:${cnonce}:${qop}:${hash(`${method}:${uri}`)}`
      : `${ha1}:${parts.nonce}:${hash(`${method}:${uri}`)}`,
  );
  const quote = (v: string) => `"${v.replace(/["\\\r\n]/g, "")}"`;
  return `Digest username=${quote(credentials.username)}, realm=${quote(parts.realm)}, nonce=${quote(parts.nonce)}, uri=${quote(uri)}, response=${quote(response)}, algorithm=${algorithm}${parts.opaque ? `, opaque=${quote(parts.opaque)}` : ""}${qop ? `, qop=auth, nc=${nc}, cnonce=${quote(cnonce)}` : algorithm.endsWith("-SESS") ? `, cnonce=${quote(cnonce)}` : ""}`;
}

export async function authenticatedCameraHttp(
  url: URL,
  credentials: CameraCredentials,
  options: Parameters<typeof cameraHttp>[1],
) {
  const first = await cameraHttp(url, options);
  if (first.status !== 401) return first;
  if (!credentials.username || !credentials.password) return first;
  const challenge = String(first.headers["www-authenticate"] ?? "");
  const authorization = cameraAuthorization(challenge, options.method ?? "GET", url, credentials);
  if (!authorization) throw new CameraError("CAMERA_AUTH_REQUIRED", 401);
  const next = await cameraHttp(url, {
    ...options,
    headers: { ...options.headers, Authorization: authorization },
  });
  if (next.status === 401 || next.status === 403) throw new CameraError("CAMERA_AUTH_FAILED", 401);
  return next;
}
