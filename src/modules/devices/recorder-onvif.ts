import { BadGatewayException, BadRequestException } from "@nestjs/common";
import { createHash, randomBytes } from "node:crypto";
import type { RecorderConnectionDto } from "./device.dto";
import { authenticatedCameraHttp, privateCameraHost } from "./recorder-http";

const namespace = "http://www.onvif.org/ver10/device/wsdl";
const xmlEntities: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;" };

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
    <s:Body><GetDeviceInformation xmlns="${namespace}"/></s:Body></s:Envelope>`;

  try {
    const url = new URL(
      `${credentials.https ? "https" : "http"}://${host}:${port}/onvif/device_service`,
    );
    const action = `"${namespace}/GetDeviceInformation"`;
    const response = await authenticatedCameraHttp(url, credentials, {
      method: "POST",
      body,
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
      !/<(?:[\w.-]+:)?GetDeviceInformationResponse(?:[\s>])/.test(xml)
    ) {
      throw new Error("Invalid ONVIF response");
    }
  } catch {
    throw new BadGatewayException(
      "تست ONVIF انجام نشد. آدرس، پورت و اطلاعات ورود ضبط‌کننده را بررسی کنید.",
    );
  }
}
