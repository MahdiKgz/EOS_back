import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import ssh2 from "ssh2";
export async function esxiSshFixture() {
  const generate = () =>
    generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
    }).privateKey;
  const hostPrivate = generate(),
    privateKey = generate(),
    publicKey = ssh2.utils.parseKey(privateKey),
    host = ssh2.utils.parseKey(hostPrivate),
    hostKey = host.type + " " + host.getPublicSSH().toString("base64");
  const username = "fixture",
    password = "fixture-esxi-2026",
    calls = [],
    clients = new Set(),
    waiting = [];
  let mode = "normal",
    paused,
    observed;
  const outputs = {
    "vmware -v": "VMware ESXi 8.0.3 build-24022510",
    "vim-cmd hostsvc/hostsummary": `(vim.host.Summary) {
  hardware = (vim.host.Summary.HardwareSummary) {
    memorySize = 8589934592,
    numCpuCores = 4,
    cpuMhz = 2000,
  },
  quickStats = (vim.host.Summary.QuickStats) {
    overallCpuUsage = 2000,
    overallMemoryUsage = 1024,
  },
}`,
    "esxcli system hostname get":
      "Fully Qualified Domain Name: esxi.fixture\nHost Name: esxi\nDomain Name: fixture",
    "esxcli hardware platform get":
      "Vendor Name: Fixture\nProduct Name: " +
      password +
      " hardware\nSerial Number: fixture-serial",
    "esxcli hardware memory get": "Physical Memory: 8589934592 Bytes",
    "esxcli hardware cpu global get": "CPU Cores: 4",
    "esxcli system maintenanceMode get": "Disabled",
    "esxcli --formatter=csv storage filesystem list":
      'Mount Point,Volume Name,UUID,Mounted,Type,Size,Free,\n/vmfs/volumes/fixture,"data, store",fixture,true,VMFS-6,107374182400,53687091200,',
    "esxcli --formatter=csv network nic list": "Name,Link Status,Speed,\nvmnic0,Up,1000,",
    "esxcli --formatter=csv network ip interface ipv4 get": "Name,IPv4 Address,\nvmk0,192.0.2.20,",
    "esxcli --formatter=csv network vswitch standard portgroup list":
      "Name,VLAN ID,Virtual Switch,\nManagement,10,vSwitch0,",
    "esxcli --formatter=csv network vswitch standard list": "Name,Num Ports,\nvSwitch0,128,",
    "esxcli network ip dns server list": "DNSServers: 192.0.2.53",
    "esxcli system ntp get": "NTP Servers: 192.0.2.123",
    "vim-cmd hostsvc/service_info":
      '(vim.host.Service) {\n key = "TSM-SSH",\n label = "SSH \\"daemon\\" {safe}",\n running = true,\n required = false,\n policy = "on",\n}',
    "esxcli --formatter=csv storage core adapter list":
      "HBA Name,Driver,Description,Link State,\nvmhba0,ahci,Fixture,link-up,",
    "esxcli --formatter=csv network firewall ruleset list": "Name,Enabled,\nsshServer,true,",
    "esxcli network nic stats get -n vmnic0": "Bytes received: 123456789\nBytes sent: 234567890",
  };
  const server = new ssh2.Server({ hostKeys: [hostPrivate] }, (client) => {
    clients.add(client);
    client.on("error", () => {});
    client.on("close", () => clients.delete(client));
    client.on("authentication", (ctx) => {
      if (ctx.username !== username) return ctx.reject();
      if (ctx.method === "password" && ctx.password === password) return ctx.accept();
      if (
        ctx.method === "publickey" &&
        ctx.key.data.equals(publicKey.getPublicSSH()) &&
        (!ctx.signature || publicKey.verify(ctx.blob, ctx.signature, ctx.hashAlgo))
      )
        return ctx.accept();
      ctx.reject();
    });
    client.on("ready", () =>
      client.on("session", (accept) =>
        accept().on("exec", (accept, reject, info) => {
          calls.push(info.command);
          if (!(info.command in outputs)) return reject();
          const stream = accept(),
            respond = () => {
              const output =
                mode === "mismatch" && info.command === "vmware -v"
                  ? "Linux"
                  : mode === "partial" && info.command === "vim-cmd hostsvc/hostsummary"
                    ? "Error: unavailable"
                    : mode === "malformed" && info.command.includes("storage filesystem")
                      ? '"incomplete'
                      : outputs[info.command];
              stream.write(output + "\n");
              stream.exit(0);
              stream.end();
            };
          if (paused === info.command) {
            waiting.push(respond);
            observed?.();
          } else respond();
        }),
      ),
    );
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const release = () => {
    paused = undefined;
    for (const resume of waiting.splice(0)) resume();
  };
  return {
    host: "127.0.0.1",
    port: server.address().port,
    username,
    password,
    hostKey,
    privateKey,
    calls,
    mode(value) {
      mode = value;
    },
    pause(command) {
      paused = command;
      return new Promise((resolve) => (observed = resolve));
    },
    release,
    async close() {
      release();
      for (const client of clients) client.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
