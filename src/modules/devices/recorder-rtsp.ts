import { BadGatewayException, BadRequestException } from "@nestjs/common";
import { createConnection } from "node:net";
import type { RecorderConnectionDto } from "./device.dto";
import { cameraAuthorization, privateCameraHost } from "./recorder-http";

function describe(url: URL, port: number, sequence: number, authorization?: string) {
  return new Promise<{ status: number; challenge?: string; body: string }>((resolve, reject) => {
    const socket = createConnection({ host: url.hostname, port });
    const timer = setTimeout(() => fail(), 3500);
    let pending = Buffer.alloc(0);
    function fail() {
      clearTimeout(timer);
      socket.destroy();
      reject(new Error("RTSP response unavailable"));
    }
    socket.once("error", fail);
    socket.once("close", fail);
    socket.once("connect", () =>
      socket.write(
        [
          `DESCRIBE ${url.href} RTSP/1.0`,
          `CSeq: ${sequence}`,
          "Accept: application/sdp",
          ...(authorization ? [`Authorization: ${authorization}`] : []),
          "",
          "",
        ].join("\r\n"),
      ),
    );
    socket.on("data", (chunk: Buffer) => {
      if (pending.length + chunk.length > 65536) return fail();
      pending = Buffer.concat([pending, chunk]);
      const boundary = pending.indexOf("\r\n\r\n");
      if (boundary < 0) return;
      const [line, ...headers] = pending.toString("utf8", 0, boundary).split("\r\n");
      const status = Number(/^RTSP\/1\.0 (\d{3})(?: |$)/.exec(line)?.[1]);
      const header = (name: string) =>
        headers
          .find((item) => item.toLowerCase().startsWith(name + ":"))
          ?.slice(name.length + 1)
          .trim();
      const length = Number(header("content-length") ?? 0);
      if (
        !status ||
        Number(header("cseq")) !== sequence ||
        !Number.isSafeInteger(length) ||
        length < 0 ||
        length > 60000
      )
        return fail();
      const start = boundary + 4;
      if (pending.length < start + length) return;
      clearTimeout(timer);
      socket.off("close", fail);
      socket.destroy();
      resolve({
        status,
        challenge: header("www-authenticate"),
        body: pending.toString("utf8", start, start + length),
      });
    });
  });
}

export async function verifyRtsp(host: string, port: number, credentials: RecorderConnectionDto) {
  const path = credentials.rtspPath;
  try {
    privateCameraHost(host);
  } catch {
    throw new BadRequestException("برای RTSP یک IPv4 خصوصی وارد کنید.");
  }
  if (!path || !/^\/[!-~]{0,511}$/.test(path) || /[\\#]/.test(path) || credentials.https)
    throw new BadRequestException("مسیر RTSP معتبر وارد کنید و HTTPS را خاموش کنید.");
  const url = new URL(`rtsp://${host}:${port}${path}`);
  try {
    let result = await describe(url, port, 1);
    if (result.status === 401 && result.challenge) {
      const authorization = cameraAuthorization(
        result.challenge,
        "DESCRIBE",
        url,
        credentials,
        url.href,
      );
      if (authorization) result = await describe(url, port, 2, authorization);
    }
    if (result.status !== 200 || !/^v=0\r?$/m.test(result.body) || !/^m=video\s/m.test(result.body))
      throw new Error("RTSP video description missing");
    return {};
  } catch {
    throw new BadGatewayException(
      "تأیید جریان RTSP انجام نشد. مسیر، پورت و اطلاعات ورود را بررسی کنید.",
    );
  }
}
