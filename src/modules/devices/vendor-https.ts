import * as https from "node:https";
import * as tls from "node:tls";
import { isIP } from "node:net";
import { createHash } from "node:crypto";
import type { Device } from "./device.entity";
import type { ApiSecret } from "./ssh-credential-vault";

export class VendorApiError extends Error {
  constructor(
    readonly code: string,
    readonly apiStatus?: number,
  ) {
    super(code);
  }
}

async function pinnedCertificate(device: Device, pin: string): Promise<string> {
  return new Promise((resolve, reject) => {
    // The first handshake sends no application data. Only the independently supplied pin authorizes the peer.
    const socket = tls.connect({
      host: device.host,
      port: device.managementPort,
      servername: isIP(device.host) ? undefined : device.host,
      rejectUnauthorized: false,
      minVersion: "TLSv1.2",
    });
    const timer = setTimeout(() => socket.destroy(new VendorApiError("SOPHOS_TLS_TIMEOUT")), 6000);
    socket.once("close", () => clearTimeout(timer));
    socket.once("error", () => reject(new VendorApiError("SOPHOS_TLS_OR_NETWORK")));
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate(true);
      if (
        !certificate.raw ||
        createHash("sha256").update(certificate.raw).digest("hex").toUpperCase() !== pin
      ) {
        socket.destroy();
        reject(new VendorApiError("SOPHOS_TLS_FINGERPRINT_MISMATCH"));
        return;
      }
      let issuer = certificate;
      const seen = new Set<string>();
      while (issuer.issuerCertificate?.raw && !seen.has(issuer.issuerCertificate.fingerprint256)) {
        seen.add(issuer.fingerprint256);
        issuer = issuer.issuerCertificate;
      }
      const pem =
        "-----BEGIN CERTIFICATE-----\n" +
        issuer.raw
          .toString("base64")
          .match(/.{1,64}/g)!
          .join("\n") +
        "\n-----END CERTIFICATE-----";
      socket.end();
      resolve(pem);
    });
  });
}

export class VendorHttpsClient {
  private readonly startedAt = Date.now();
  private constructor(
    private readonly device: Device,
    private readonly agent: https.Agent,
  ) {}
  static async connect(device: Device, secret: ApiSecret, allowFingerprint: boolean) {
    if (secret.tlsFingerprint && !allowFingerprint)
      throw new VendorApiError("API_TLS_PIN_NOT_SUPPORTED");
    const pin = secret.tlsFingerprint;
    const ca = pin ? await pinnedCertificate(device, pin) : secret.caCertificate;
    const agent = new https.Agent({
      keepAlive: true,
      maxSockets: 3,
      maxFreeSockets: 1,
      maxCachedSessions: 0,
      minVersion: "TLSv1.2",
      rejectUnauthorized: true,
      ca,
      ...(pin
        ? {
            checkServerIdentity: (_host: string, certificate: tls.PeerCertificate) =>
              createHash("sha256").update(certificate.raw).digest("hex").toUpperCase() === pin
                ? undefined
                : new VendorApiError("SOPHOS_TLS_FINGERPRINT_MISMATCH"),
          }
        : {}),
    });
    return new VendorHttpsClient(device, agent);
  }
  close() {
    this.agent.destroy();
  }
  request(
    path: string,
    options: {
      method: "GET" | "POST";
      headers?: Record<string, string>;
      body?: string;
      maxBytes?: number;
    },
  ): Promise<string> {
    const remaining = 180000 - (Date.now() - this.startedAt);
    if (remaining <= 0) throw new VendorApiError("API_TIMEOUT");
    return new Promise((resolve, reject) => {
      const request = https.request(
        {
          hostname: this.device.host,
          port: this.device.managementPort,
          path,
          method: options.method,
          agent: this.agent,
          rejectUnauthorized: true,
          headers: {
            ...options.headers,
            ...(options.body ? { "Content-Length": String(Buffer.byteLength(options.body)) } : {}),
          },
        },
        (response) => {
          let size = 0;
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => {
            size += chunk.length;
            if (size > (options.maxBytes ?? 6 * 1024 * 1024))
              request.destroy(new VendorApiError("API_RESPONSE_TOO_LARGE"));
            else chunks.push(chunk);
          });
          response.once("aborted", () => reject(new VendorApiError("API_RESPONSE_INCOMPLETE")));
          response.once("error", () => reject(new VendorApiError("API_RESPONSE_INCOMPLETE")));
          response.once("end", () => {
            if (response.statusCode === 401 || response.statusCode === 403) {
              reject(new VendorApiError("API_AUTH_FAILED"));
              return;
            }
            if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
              reject(new VendorApiError("API_HTTP_ERROR", response.statusCode));
              return;
            }
            resolve(Buffer.concat(chunks).toString("utf8"));
          });
        },
      );
      const timer = setTimeout(
        () => request.destroy(new VendorApiError("API_TIMEOUT")),
        Math.min(15000, remaining),
      );
      timer.unref();
      request.once("close", () => clearTimeout(timer));
      request.once("error", (error) =>
        reject(error instanceof VendorApiError ? error : new VendorApiError("API_TLS_OR_NETWORK")),
      );
      request.end(options.body);
    });
  }
}

export function redactApiResult<T>(value: T, secret: ApiSecret): T {
  return JSON.parse(
    JSON.stringify(value, (key, item: unknown) =>
      typeof item === "string" && !["kind", "collectedAt"].includes(key)
        ? item.split(secret.password).join("[redacted]")
        : item,
    ),
  ) as T;
}
