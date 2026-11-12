// Independent SOAP/HTTP/RTSP fixture, bound only to a private address owned by this host.
import { createServer } from "node:http";
import { createServer as tcpServer } from "node:net";
import { networkInterfaces } from "node:os";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
export async function onvifFixture() {
  const host = Object.values(networkInterfaces())
    .flat()
    .find(
      (i) =>
        i?.family === "IPv4" &&
        !i.internal &&
        /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(i.address),
    )?.address;
  if (!host)
    throw new Error(
      "ONVIF integration requires a private IPv4 address owned by the local test host",
    );
  const requests = [],
    sockets = new Set();
  let failed = false,
    media2 = false;
  const jpeg = execFileSync("python3", [
    "-c",
    "from PIL import Image; import sys; Image.new('RGB',(64,36),(30,160,180)).save(sys.stdout.buffer,format='JPEG')",
  ]);
  const rtsp = tcpServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    let pending = "";
    socket.on("data", (bytes) => {
      pending += bytes.toString();
      if (pending.length > 8192) {
        socket.destroy();
        return;
      }
      if (!pending.includes("\r\n\r\n")) return;
      const cseq = /CSeq: (\d+)/i.exec(pending)?.[1] ?? "1",
        authorized = pending.includes(
          "Authorization: Basic " + Buffer.from("fixture:fixture-secret").toString("base64"),
        );
      requests.push({ path: "/stream", operation: "DESCRIBE", authorized });
      const body = authorized ? "v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n" : "";
      socket.end(
        `RTSP/1.0 ${authorized ? "200 OK" : "401 Unauthorized"}\r\nCSeq: ${cseq}\r\n${authorized ? "Content-Type: application/sdp" : 'WWW-Authenticate: Basic realm="fixture"'}\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
      );
    });
  });
  await new Promise((resolve) => rtsp.listen(0, host, resolve));
  const rtspPort = rtsp.address().port;
  const http = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    const operation = /<m:(\w+) xmlns:m=/.exec(body)?.[1];
    requests.push({ path: req.url, operation: operation ?? req.method });
    if (failed) {
      res.writeHead(503);
      res.end();
      return;
    }
    if (req.url === "/snapshot") {
      if (
        req.headers.authorization !==
        "Basic " + Buffer.from("fixture:fixture-secret").toString("base64")
      ) {
        res.writeHead(401, { "www-authenticate": 'Basic realm="fixture"' });
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "image/jpeg" });
      res.end(jpeg);
      return;
    }
    if (
      req.method !== "POST" ||
      !["/custom/device_service", "/custom/media_service"].includes(req.url)
    ) {
      res.writeHead(404);
      res.end();
      return;
    }
    const nonce = /<wsse:Nonce[^>]*>([^<]+)/.exec(body)?.[1],
      created = /<wsu:Created>([^<]+)/.exec(body)?.[1],
      password = /<wsse:Password[^>]*>([^<]+)/.exec(body)?.[1];
    const valid =
      nonce &&
      created &&
      body.includes("<wsse:Username>fixture</wsse:Username>") &&
      createHash("sha1")
        .update(Buffer.from(nonce, "base64"))
        .update(created)
        .update("fixture-secret")
        .digest("base64") === password;
    if (!valid) {
      res.writeHead(500, { "content-type": "application/soap+xml" });
      res.end("<s:Fault/>");
      return;
    }
    const namespace = media2
      ? "http://www.onvif.org/ver20/media/wsdl"
      : "http://www.onvif.org/ver10/media/wsdl";
    const result = {
      GetDeviceInformation:
        "<Manufacturer>Fixture</Manufacturer><Model>Private Camera</Model><FirmwareVersion>1.2.3</FirmwareVersion>",
      GetServices: `<Service><Namespace>${namespace}</Namespace><XAddr>http://198.51.100.200:9/custom/media_service</XAddr></Service>`,
      GetProfiles:
        '<Profiles token="main"><Name>Main camera</Name><VideoEncoderConfiguration><Encoding>H264</Encoding><Resolution><Width>1920</Width><Height>1080</Height></Resolution><RateControl><FrameRateLimit>25</FrameRateLimit></RateControl></VideoEncoderConfiguration><AudioEncoderConfiguration><Encoding>AAC</Encoding></AudioEncoderConfiguration></Profiles>',
      GetSnapshotUri: "<MediaUri><Uri>http://198.51.100.200:9/snapshot</Uri></MediaUri>",
      GetStreamUri: `<MediaUri><Uri>rtsp://198.51.100.200:${rtspPort}/stream</Uri></MediaUri>`,
    }[operation];
    if (result === undefined) {
      res.writeHead(500);
      res.end("<s:Fault/>");
      return;
    }
    res.writeHead(200, { "content-type": "application/soap+xml" });
    res.end(
      `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><${operation}Response>${result}</${operation}Response></s:Body></s:Envelope>`,
    );
  });
  await new Promise((resolve) => http.listen(0, host, resolve));
  return {
    host,
    port: http.address().port,
    rtspPort,
    jpeg,
    requests,
    setFailed: (value) => {
      failed = value;
    },
    setMedia2: (value) => {
      media2 = value;
    },
    async close() {
      http.closeAllConnections();
      for (const socket of sockets) socket.destroy();
      await Promise.all([
        new Promise((resolve) => http.close(resolve)),
        new Promise((resolve) => rtsp.close(resolve)),
      ]);
    },
  };
}
