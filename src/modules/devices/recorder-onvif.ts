import { verifyRtsp } from "./recorder-rtsp";
import { BadGatewayException, BadRequestException } from "@nestjs/common";
import { createHash, randomBytes } from "node:crypto";
import type { RecorderConnectionDto } from "./device.dto";
import {
  authenticatedCameraHttp,
  CameraError,
  privateCameraHost,
  recorderOnvifPath,
} from "./recorder-http";

const namespace = "http://www.onvif.org/ver10/device/wsdl";
const xmlEntities: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;" };

async function soap(
  host: string,
  port: number,
  credentials: RecorderConnectionDto,
  operation: string,
  path = recorderOnvifPath(credentials.onvifPath),
  ns = namespace,
  content = "",
) {
  privateCameraHost(host);
  const nonce = randomBytes(16);
  const created = new Date().toISOString();
  const digest = createHash("sha1")
    .update(nonce)
    .update(created)
    .update(credentials.password)
    .digest("base64");
  const username = credentials.username.replace(/[&<>]/g, (character) => xmlEntities[character]);
  const security = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss";
  const body = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Header><wsse:Security s:mustUnderstand="1" xmlns:wsse="${security}-wssecurity-secext-1.0.xsd" xmlns:wsu="${security}-wssecurity-utility-1.0.xsd">
    <wsse:UsernameToken><wsse:Username>${username}</wsse:Username>
    <wsse:Password Type="${security}-username-token-profile-1.0#PasswordDigest">${digest}</wsse:Password>
    <wsse:Nonce EncodingType="${security}-soap-message-security-1.0#Base64Binary">${nonce.toString("base64")}</wsse:Nonce>
    <wsu:Created>${created}</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>
    <s:Body><m:${operation} xmlns:m="${ns}">${content}</m:${operation}></s:Body></s:Envelope>`;

  const url = new URL(`${credentials.https ? "https" : "http"}://${host}:${port}${path}`);
  const action = `"${ns}/${operation}"`;
  const response = await authenticatedCameraHttp(url, credentials, {
    method: "POST",
    body,
    timeout: 2200,
    headers: {
      "Content-Type": `application/soap+xml; charset=utf-8; action=${action}`,
      SOAPAction: action,
    },
  });
  const xml = response.body.toString("utf8");
  if (
    response.status < 200 ||
    response.status >= 300 ||
    /<(?:[\w.-]+:)?(?:Fault|html)(?:[\s>])/i.test(xml) ||
    !new RegExp(`<(?:[\\w.-]+:)?${operation}Response(?:[\\s/>])`).test(xml)
  )
    throw new Error("Invalid ONVIF response");
  return xml;
}

export async function verifyRecorder(
  host: string,
  port: number,
  credentials: RecorderConnectionDto,
) {
  try {
    privateCameraHost(host);
  } catch {
    throw new BadRequestException("برای تست ضبط‌کننده، آدرس IPv4 خصوصی وارد کنید.");
  }
  try {
    const xml = await soap(host, port, credentials, "GetDeviceInformation");
    const identity =
      xml.match(
        /<(?:[\w.-]+:)?GetDeviceInformationResponse(?:\s[^>]*)?>([\s\S]*?)<\/(?:[\w.-]+:)?GetDeviceInformationResponse>/,
      )?.[1] ?? "";
    const fields = ["Manufacturer", "Model", "FirmwareVersion"] as const;
    return Object.fromEntries(
      fields.flatMap((field) => {
        const value = identity
          .match(
            new RegExp(`<(?:[\\w.-]+:)?${field}>([^<]{1,256})<\\/(?:[\\w.-]+:)?${field}>`),
          )?.[1]
          .trim();
        return value ? [[field, value]] : [];
      }),
    );
  } catch {
    throw new BadGatewayException(
      "تست ONVIF انجام نشد. آدرس، پورت و اطلاعات ورود ضبط‌کننده را بررسی کنید.",
    );
  }
}

const mediaNamespace = "http://www.onvif.org/ver10/media/wsdl";
const media2Namespace = "http://www.onvif.org/ver20/media/wsdl";

async function mediaPath(host: string, port: number, credentials: RecorderConnectionDto) {
  let endpoint: string | undefined;
  let serviceNamespace = mediaNamespace;
  try {
    const services = await soap(
      host,
      port,
      credentials,
      "GetServices",
      undefined,
      namespace,
      "<m:IncludeCapability>false</m:IncludeCapability>",
    );
    const entries = Array.from(
      services.matchAll(/<(?:[\w.-]+:)?Service(?:\s[^>]*)?>([\s\S]*?)<\/(?:[\w.-]+:)?Service>/g),
    );
    for (const candidate of [mediaNamespace, media2Namespace]) {
      const service = entries.find(
        ([, content]) => profileText(content, "Namespace") === candidate,
      );
      endpoint = service && profileText(service[1], "XAddr");
      if (endpoint) {
        serviceNamespace = candidate;
        break;
      }
    }
  } catch (error) {
    if (error instanceof CameraError && error.code === "CAMERA_AUTH_FAILED") throw error;
  }
  if (!endpoint) {
    const capabilities = await soap(
      host,
      port,
      credentials,
      "GetCapabilities",
      undefined,
      namespace,
      "<m:Category>Media</m:Category>",
    );
    endpoint = profileText(profileSection(capabilities, "Media"), "XAddr");
  }
  if (!endpoint) throw new Error("Missing ONVIF media endpoint");
  const media = new URL(endpoint);
  if (
    !["http:", "https:"].includes(media.protocol) ||
    media.username ||
    media.password ||
    media.pathname.startsWith("//")
  )
    throw new Error("Invalid ONVIF media endpoint");
  return { path: media.pathname + media.search, serviceNamespace };
}

function profileText(xml: string, field: string) {
  return xml
    .match(new RegExp(`<(?:[\\w.-]+:)?${field}(?:\\s[^>]*)?>([^<]{1,1024})<\\/`))?.[1]
    .trim();
}

function profileSection(xml: string, field: string) {
  return (
    xml.match(
      new RegExp(`<(?:[\\w.-]+:)?${field}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${field}>`),
    )?.[1] ?? ""
  );
}

function positiveInteger(value: string | undefined) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

export async function inspectOnvif(host: string, port: number, credentials: RecorderConnectionDto) {
  const { path, serviceNamespace } = await mediaPath(host, port, credentials);
  const xml = await soap(
    host,
    port,
    credentials,
    "GetProfiles",
    path,
    serviceNamespace,
    serviceNamespace === media2Namespace ? "<m:Type>All</m:Type>" : "",
  );
  const profiles = Array.from(
    xml.matchAll(/<(?:[\w.-]+:)?Profiles\b([^>]*)>([\s\S]*?)<\/(?:[\w.-]+:)?Profiles>/g),
  )
    .slice(0, 128)
    .flatMap(([, attributes, content]) => {
      const token = /\btoken=(?:"([^"]{1,256})"|'([^']{1,256})')/.exec(attributes);
      const name = /<(?:[\w.-]+:)?Name>([^<]{1,160})<\//.exec(content)?.[1].trim();
      if (!token) return [];
      const id = (token[1] ?? token[2]).replace(
        /&(amp|lt|gt|quot|apos);/g,
        (entity) =>
          ({ "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" })[entity] ??
          entity,
      );
      const video =
        profileSection(content, "VideoEncoderConfiguration") ||
        profileSection(content, "VideoEncoder");
      const audio =
        profileSection(content, "AudioEncoderConfiguration") ||
        profileSection(content, "AudioEncoder");
      return [
        {
          token: id,
          name: name || id,
          width: positiveInteger(profileText(video, "Width")),
          height: positiveInteger(profileText(video, "Height")),
          fps: positiveInteger(profileText(video, "FrameRateLimit")),
          encoding: profileText(video, "Encoding")?.slice(0, 32) ?? null,
          audioEncoding: profileText(audio, "Encoding")?.slice(0, 32) ?? null,
        },
      ];
    });
  return { checkedAt: new Date().toISOString(), profiles, channels: null, disks: null };
}

export async function snapshotOnvif(
  host: string,
  port: number,
  credentials: RecorderConnectionDto,
  token: string,
) {
  const { path, serviceNamespace } = await mediaPath(host, port, credentials);
  const escaped = token.replace(/[&<>]/g, (character) => xmlEntities[character]);
  const xml = await soap(
    host,
    port,
    credentials,
    "GetSnapshotUri",
    path,
    serviceNamespace,
    `<m:ProfileToken>${escaped}</m:ProfileToken>`,
  );
  const uri = xml
    .match(/<(?:[\w.-]+:)?Uri>([^<]{1,2048})<\//)?.[1]
    .trim()
    .replaceAll("&amp;", "&");
  if (!uri) throw new Error("Missing snapshot URI");
  const snapshot = new URL(uri);
  if (!["http:", "https:"].includes(snapshot.protocol) || snapshot.username || snapshot.password)
    throw new Error("Invalid snapshot URI");
  const url = new URL(`${credentials.https ? "https" : "http"}://${host}:${port}`);
  url.pathname = snapshot.pathname;
  url.search = snapshot.search;
  const result = await authenticatedCameraHttp(url, credentials, {
    timeout: 2200,
    maxBytes: 1024 * 1024,
    headers: { Accept: "image/jpeg" },
  });
  if (
    result.status !== 200 ||
    result.body.length < 4 ||
    result.body[0] !== 255 ||
    result.body[1] !== 216 ||
    result.body[2] !== 255
  )
    throw new Error("Invalid JPEG snapshot");
  return { jpeg: result.body.toString("base64") };
}

export async function verifyOnvifStream(
  host: string,
  port: number,
  credentials: RecorderConnectionDto,
  token: string,
) {
  const { path, serviceNamespace } = await mediaPath(host, port, credentials);
  const escaped = token.replace(/[&<>]/g, (character) => xmlEntities[character]);
  const xml = await soap(
    host,
    port,
    credentials,
    "GetStreamUri",
    path,
    serviceNamespace,
    serviceNamespace === media2Namespace
      ? `<m:Protocol>RTSP</m:Protocol><m:ProfileToken>${escaped}</m:ProfileToken>`
      : `<m:StreamSetup xmlns:tt="http://www.onvif.org/ver10/schema"><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></m:StreamSetup><m:ProfileToken>${escaped}</m:ProfileToken>`,
  );
  const uri = xml
    .match(/<(?:[\w.-]+:)?Uri>([^<]{1,2048})<\//)?.[1]
    .trim()
    .replaceAll("&amp;", "&");
  if (!uri) throw new Error("Missing ONVIF stream URI");
  const stream = new URL(uri);
  if (stream.protocol !== "rtsp:" || stream.hash) throw new Error("Invalid ONVIF stream URI");
  await verifyRtsp(host, Number(stream.port || 554), {
    ...credentials,
    https: false,
    rtspPath: stream.pathname + stream.search,
  });
  return { checkedAt: new Date().toISOString() };
}
