import { createServer } from "node:https";
import { networkInterfaces, tmpdir } from "node:os";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { X509Certificate } from "node:crypto";
import { join } from "node:path";
import { once } from "node:events";
const execute = promisify(execFile);
export async function networkApiFixture() {
  const host = Object.values(networkInterfaces())
    .flat()
    .find(
      (nic) =>
        nic?.family === "IPv4" &&
        !nic.internal &&
        /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(nic.address),
    )?.address;
  if (!host) throw new Error("Network API fixture requires an owned private IPv4 address");
  const directory = await mkdtemp(join(tmpdir(), "eos-network-api-"));
  const username = "fixture",
    password = "fixture<&api-2026",
    calls = [],
    sockets = new Set();
  let server,
    mode = "normal",
    paused,
    observed,
    queued = [];
  function release() {
    paused = undefined;
    for (const respond of queued.splice(0)) respond();
  }
  try {
    await execute("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "2",
      "-subj",
      "/CN=Network API fixture",
      "-addext",
      `subjectAltName=IP:${host}`,
      "-keyout",
      join(directory, "key.pem"),
      "-out",
      join(directory, "cert.pem"),
    ]);
    const ca = await readFile(join(directory, "cert.pem"), "utf8"),
      key = await readFile(join(directory, "key.pem"));
    const data = {
      "/rest/system/identity": [{ name: "fixture-router" }],
      "/rest/system/resource": [
        {
          version: "7.20.1 (stable)",
          "architecture-name": "arm64",
          uptime: "3d2h",
          "cpu-load": "15",
          "cpu-count": "4",
          "free-memory": "67108864",
          "total-memory": "134217728",
          "free-hdd-space": "1000000",
          "total-hdd-space": "2000000",
          password: "NEVER_RETURN",
        },
      ],
      "/rest/system/package": [{ name: "routeros", version: "7.20.1" }],
      "/rest/interface": [
        {
          name: "ether1",
          running: "true",
          disabled: "false",
          "mac-address": "02:00:00:00:00:01",
          password: "NEVER_RETURN",
        },
      ],
      "/rest/ip/address": [{ address: "192.0.2.1/24", interface: "ether1" }],
      "/rest/ip/route": [{ "dst-address": "0.0.0.0/0", gateway: "192.0.2.254", active: "true" }],
      "/rest/ip/firewall/filter": [
        { chain: "forward", action: "accept", protocol: "tcp", "dst-port": "443" },
      ],
      "/rest/ip/firewall/nat": [{ chain: "srcnat", action: "masquerade" }],
      "/rest/ip/firewall/mangle": [],
      "/rest/ip/firewall/address-list": [],
      "/rest/ip/service": [
        { name: "www-ssl", port: "443", disabled: "false", secret: "NEVER_RETURN" },
      ],
      "/rest/log": [
        { time: "12:00:00", topics: "fixture", message: "Sensitive fixture " + password },
      ],
      "/rest/interface?.proplist=name,rx-byte,tx-byte": [
        { name: "ether1", "rx-byte": "123456", "tx-byte": "654321" },
        { name: "invalid", "rx-byte": "bad", "tx-byte": "10" },
      ],
      "/rest/ip/arp": [
        { address: "192.0.2.5", "mac-address": "02:00:00:00:00:05", interface: "ether1" },
      ],
      "/rest/ip/dhcp-server/lease": [
        { address: "192.0.2.6", "host-name": "workstation", status: "bound" },
      ],
      "/rest/interface/bridge/host": [
        {
          "mac-address": "02:00:00:00:00:07",
          "on-interface": "ether1",
          bridge: "bridge1",
          vid: "20",
        },
      ],
      "/rest/ip/dns/cache": [{ name: "fixture.test", address: "192.0.2.7" }],
    };
    const sophos = {
      Interface:
        "<Interface><Name><![CDATA[Port <2> & local]]></Name><Hardware>Port2</Hardware><NetworkZone>LAN</NetworkZone><IPAddress>192.0.2.1</IPAddress><Netmask>255.255.255.0</Netmask><MACAddress>02:00:00:00:00:02</MACAddress><InterfaceSpeed>1000</InterfaceSpeed><Status>up</Status><InterfaceStatus>off</InterfaceStatus></Interface>",
      Zone: "<Zone><Name>L&#x41;N</Name></Zone>",
      Gateway: "<Gateway/>",
      FirewallRule:
        "<FirewallRule><Name>Web</Name><Status>Enable</Status><Action>Accept</Action><SourceZones><Zone>LAN</Zone></SourceZones><DestinationZones><Zone>WAN</Zone></DestinationZones><Services><Service>HTTPS</Service></Services></FirewallRule>",
      IPHost:
        "<IPHost><Name>Workstation</Name><IPAddress>192.0.2.5</IPAddress><HostType>IP</HostType><IPFamily>IPv4</IPFamily><Password>NEVER_RETURN</Password></IPHost>",
      Services:
        "<Services><Name>Web</Name><Protocol>TCP</Protocol><DestinationPort>443</DestinationPort></Services>",
      VPNIPSecConnection:
        "<VPNIPSecConnection><Configuration><Name>Tunnel</Name><Status>Active</Status><ConnectionType>SiteToSite</ConnectionType><Policy>Fixture</Policy><RemoteHost>192.0.2.99</RemoteHost><RemoteNetwork><Network>192.0.2.0/24</Network></RemoteNetwork><PresharedKey>NEVER_RETURN_PSK</PresharedKey><AuthenticationType>PresharedKey</AuthenticationType></Configuration></VPNIPSecConnection>",
      VPNProfile:
        "<VPNProfile><Name>Fixture</Name><IKEVersion>IKEv2</IKEVersion><Phase1><EncryptionAlgorithm1>AES256</EncryptionAlgorithm1><AuthenticationAlgorithm1>SHA256</AuthenticationAlgorithm1><DHGroup>14</DHGroup></Phase1><Phase2><EncryptionAlgorithm1>AES256</EncryptionAlgorithm1></Phase2></VPNProfile>",
    };
    server = createServer({ key, cert: ca }, async (request, response) => {
      const path = request.url;
      calls.push({ path, method: request.method });
      const json = (status, value) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(value));
      };
      if (path.startsWith("/rest/")) {
        if (request.method !== "GET") {
          json(405, {});
          return;
        }
        if (
          request.headers.authorization !==
          "Basic " + Buffer.from(username + ":" + password).toString("base64")
        ) {
          json(401, { password });
          return;
        }
        if (mode === "redirect") {
          response.writeHead(302, { location: "https://127.0.0.1/credentials" }).end();
          return;
        }
        if (mode === "malformed") {
          response.writeHead(200).end("not JSON");
          return;
        }
        if (mode === "shape") {
          json(200, "invalid shape");
          return;
        }
        if (mode === "unknownFields" && path === "/rest/log") {
          json(200, [{ password: "NEVER_RETURN" }]);
          return;
        }
        if (mode === "fakeIdentity" && path === "/rest/system/resource") {
          json(200, [{ version: "6.49" }]);
          return;
        }
        if (mode === "partial" && path === "/rest/log") {
          json(404, { password });
          return;
        }
        const send = () => json(data[path] ? 200 : 404, data[path] ?? {});
        if (paused === "mikrotik" && path === "/rest/system/resource") {
          queued.push(send);
          observed?.();
        } else send();
        return;
      }
      if (path !== "/webconsole/APIController" || request.method !== "POST") {
        json(404, {});
        return;
      }
      let body = "";
      for await (const chunk of request) {
        body += chunk.toString();
        if (body.length > 32768) {
          response.writeHead(413).end();
          return;
        }
      }
      const xml = new URLSearchParams(body).get("reqxml") ?? "",
        module = /<Get><([A-Za-z]+)/.exec(xml)?.[1];
      const send = () => {
        response.writeHead(200, { "content-type": "application/xml" });
        if (
          !xml.includes(`<Username>${username}</Username>`) ||
          !xml.includes("<Password>fixture&lt;&amp;api-2026</Password>")
        ) {
          response.end(
            "<Response><Login><status>Authentication Failed</status></Login></Response>",
          );
          return;
        }
        if (mode === "malformed") {
          response.end("<Response><broken>");
          return;
        }
        if (mode === "dtd") {
          response.end('<!DOCTYPE Response [<!ENTITY forbidden "secret">]><Response/>');
          return;
        }
        const login = "<Login><status>Authentication Successful</status></Login>";
        const rejected = mode === "missing" || (mode === "partial" && module === "VPNProfile");
        response.end(
          `<Response APIVersion="2000.1">${login}${rejected ? `<Status code="529">Rejected ${password.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</Status>` : (sophos[module] ?? "")}</Response>`,
        );
      };
      if (paused === "sophos" && module === "Interface") {
        queued.push(send);
        observed?.();
      } else send();
    });
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    server.listen(0, host);
    await once(server, "listening");
    return {
      host,
      port: server.address().port,
      ca,
      fingerprint: new X509Certificate(ca).fingerprint256.replace(/:/g, ""),
      username,
      password,
      calls,
      counters(rx, tx) {
        data["/rest/interface?.proplist=name,rx-byte,tx-byte"][0]["rx-byte"] = String(rx);
        data["/rest/interface?.proplist=name,rx-byte,tx-byte"][0]["tx-byte"] = String(tx);
      },
      mode(value) {
        mode = value;
      },
      pause(kind) {
        paused = kind;
        return new Promise((resolve) => {
          observed = resolve;
        });
      },
      release,
      async close() {
        release();
        for (const socket of sockets) socket.destroy();
        await new Promise((resolve) => server.close(resolve));
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    server?.close();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
