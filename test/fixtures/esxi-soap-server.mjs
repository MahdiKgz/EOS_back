import { createServer } from "node:https";
import { networkInterfaces, tmpdir } from "node:os";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { once } from "node:events";
const execute = promisify(execFile);
const ref = (type, id) => `<ManagedObjectReference type="${type}">${id}</ManagedObjectReference>`;
const envelope = (method, body) =>
  `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><${method}Response xmlns="urn:vim25">${body}</${method}Response></s:Body></s:Envelope>`;
const fault = () =>
  '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>ServerFaultCode</faultcode><faultstring>Denied</faultstring></s:Fault></s:Body></s:Envelope>';
export async function esxiSoapFixture() {
  const host = Object.values(networkInterfaces())
    .flat()
    .find(
      (nic) =>
        nic?.family === "IPv4" &&
        !nic.internal &&
        /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(nic.address),
    )?.address;
  if (!host) throw new Error("ESXi TLS fixture requires an owned private IPv4 address");
  const directory = await mkdtemp(join(tmpdir(), "eos-esxi-test-"));
  let server;
  const sessions = new Set(),
    sockets = new Set(),
    calls = [];
  const data = new Map([
    ["Folder:group-d1", { childEntity: ref("Datacenter", "dc1") }],
    ["Datacenter:dc1", { hostFolder: ref("Folder", "group-h1") }],
    ["Folder:group-h1", { childEntity: ref("ComputeResource", "domain-c1") }],
    ["ComputeResource:domain-c1", { host: ref("HostSystem", "ha-host") }],
    [
      "HostSystem:ha-host",
      {
        summary:
          "<config><name>esxi-fixture</name></config><hardware><cpuMhz>2000</cpuMhz><numCpuCores>4</numCpuCores><memorySize>8589934592</memorySize><model>Fixture Server</model><vendor>Fixture Labs</vendor></hardware><quickStats><overallCpuUsage>1000</overallCpuUsage><overallMemoryUsage>2048</overallMemoryUsage></quickStats><overallStatus>green</overallStatus>",
        runtime:
          "<connectionState>connected</connectionState><inMaintenanceMode>false</inMaintenanceMode><bootTime>2026-11-01T00:00:00Z</bootTime><healthSystemRuntime><systemHealthInfo><numericSensorInfo><name>Temperature</name><healthState><key>green</key></healthState><currentReading>-55</currentReading><unitModifier>-1</unitModifier><baseUnits>celsius</baseUnits></numericSensorInfo></systemHealthInfo></healthSystemRuntime>",
        hardware:
          "<systemInfo><serialNumber>FIXTURE-123</serialNumber></systemInfo><biosInfo><biosVersion>Fixture BIOS</biosVersion></biosInfo>",
        vm: ref("VirtualMachine", "vm-1") + ref("VirtualMachine", "vm-2"),
        datastore: ref("Datastore", "ds-1"),
        network: ref("Network", "network-1"),
        configManager:
          '<serviceSystem type="HostServiceSystem">service-1</serviceSystem><dateTimeSystem type="HostDateTimeSystem">date-1</dateTimeSystem>',
        "config.service":
          "<service><key>TSM-SSH</key><label>SSH</label><running>true</running><policy>off</policy><required>false</required></service>",
        "config.network":
          "<pnic><device>vmnic0</device><linkSpeed><speedMb>1000</speedMb></linkSpeed></pnic><vnic><device>vmk0</device><spec><ip><ipAddress>192.0.2.10</ipAddress></ip></spec></vnic><vswitch><name>vSwitch0</name><numPorts>128</numPorts></vswitch><portgroup><spec><name>Management</name><vlanId>20</vlanId><vswitchName>vSwitch0</vswitchName></spec></portgroup><dnsConfig><hostName>esxi</hostName><domainName>fixture.test</domainName><address>192.0.2.53</address></dnsConfig>",
        "config.dateTimeInfo":
          "<ntpConfig><server>192.0.2.123</server></ntpConfig><systemClockProtocol>ntp</systemClockProtocol>",
        "config.storageDevice":
          "<hostBusAdapter><device>vmhba0</device><model>Fixture HBA</model><driver>ahci</driver><status>online</status></hostBusAdapter><scsiLun><canonicalName>naa.fixture</canonicalName><displayName>Fixture disk</displayName><deviceType>disk</deviceType><operationalState>ok</operationalState></scsiLun>",
        "config.firewall":
          "<ruleset><key>sshServer</key><label>SSH Server</label><enabled>true</enabled><required>false</required></ruleset>",
        "config.lockdownMode": "lockdownDisabled",
      },
    ],
    [
      "VirtualMachine:vm-1",
      {
        summary:
          "<config><name>Fixture VM 1</name><guestFullName>Linux</guestFullName><numCpu>2</numCpu><memorySizeMB>1024</memorySizeMB></config><runtime><powerState>poweredOn</powerState></runtime>",
      },
    ],
    [
      "VirtualMachine:vm-2",
      {
        summary:
          "<config><name>Fixture VM 2</name><numCpu>1</numCpu><memorySizeMB>512</memorySizeMB></config><runtime><powerState>poweredOff</powerState></runtime>",
      },
    ],
    [
      "Datastore:ds-1",
      {
        summary:
          "<name>datastore1</name><capacity>107374182400</capacity><freeSpace>53687091200</freeSpace><accessible>true</accessible>",
      },
    ],
    ["Network:network-1", { name: "Management" }],
  ]);
  let mode = "normal",
    hold = false,
    seen,
    queued = [];
  const username = "fixture@local",
    password = "fixture<&password-2026";
  function release() {
    hold = false;
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
      "/CN=ESXi fixture",
      "-addext",
      `subjectAltName=IP:${host}`,
      "-keyout",
      join(directory, "key.pem"),
      "-out",
      join(directory, "cert.pem"),
    ]);
    const key = await readFile(join(directory, "key.pem")),
      ca = await readFile(join(directory, "cert.pem"), "utf8");
    server = createServer({ key, cert: ca }, async (request, response) => {
      let xml = "";
      for await (const chunk of request) {
        xml += chunk.toString();
        if (xml.length > 32768) {
          response.writeHead(413).end();
          return;
        }
      }
      if (
        request.method !== "POST" ||
        request.url !== "/sdk" ||
        request.headers.soapaction !== '"urn:vim25/6.5"'
      ) {
        response.writeHead(400).end();
        return;
      }
      const method =
        /<(?:\w+:)?(RetrieveServiceContent|Login|Logout|RetrievePropertiesEx|ContinueRetrievePropertiesEx)(?:\s|>)/.exec(
          xml,
        )?.[1];
      calls.push(method);
      const send = (body) => {
        response.writeHead(200, { "content-type": "text/xml" });
        response.end(body);
      };
      if (method === "RetrieveServiceContent") {
        if (mode === "dtd") {
          send('<!DOCTYPE data [<!ENTITY attack "fixture">]>' + envelope(method, "<returnval/>"));
          return;
        }
        send(
          envelope(
            method,
            `<returnval><rootFolder type="Folder">group-d1</rootFolder><propertyCollector type="PropertyCollector">prop-1</propertyCollector><sessionManager type="SessionManager">session-1</sessionManager><about><apiType>${mode === "vcenter" ? "VirtualCenter" : "HostAgent"}</apiType><version>8.0.3</version><build>24022510</build></about></returnval>`,
          ),
        );
        return;
      }
      if (method === "Login") {
        if (
          !xml.includes(`<userName>${username}</userName>`) ||
          !xml.includes("<password>fixture&lt;&amp;password-2026</password>")
        ) {
          send(fault());
          return;
        }
        const cookie = "vmware_soap_session=fixture-" + sessions.size + "-" + Date.now();
        sessions.add(cookie);
        response.setHeader("set-cookie", cookie + "; HttpOnly; Secure; Path=/");
        send(envelope(method, "<returnval><key>fixture</key></returnval>"));
        return;
      }
      const cookie = request.headers.cookie;
      if (!sessions.has(cookie)) {
        response.writeHead(401).end();
        return;
      }
      if (method === "Logout") {
        sessions.delete(cookie);
        send(envelope(method, ""));
        return;
      }
      if (method === "RetrievePropertiesEx") {
        const respond = () => {
          const objects = [...xml.matchAll(/<obj type="([A-Za-z]+)">([A-Za-z0-9_-]+)<\/obj>/g)]
            .map(([, type, id]) => {
              const props = data.get(type + ":" + id) ?? {};
              return `<objects><obj type="${type}">${id}</obj>${Object.entries(props)
                .map(
                  ([name, value]) => `<propSet><name>${name}</name><val>${value}</val></propSet>`,
                )
                .join("")}</objects>`;
            })
            .join("");
          send(envelope(method, "<returnval>" + objects + "</returnval>"));
        };
        if (hold && xml.includes('type="HostSystem"')) {
          queued.push(respond);
          seen?.();
        } else respond();
        return;
      }
      send(fault());
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
      username,
      password,
      calls,
      sessions,
      mode(value) {
        mode = value;
      },
      pause() {
        hold = true;
        return new Promise((resolve) => {
          seen = resolve;
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
