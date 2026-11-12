import { generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";
import { once } from "node:events";
import ssh2 from "ssh2";
export async function ciscoSshFixture({
  userExec = false,
  legacy = false,
  enablePassword = "enable-fixture-2026",
  echoEnable = false,
} = {}) {
  const privateKey = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
    }).privateKey,
    parsed = ssh2.utils.parseKey(privateKey),
    hostKey = parsed.type + " " + parsed.getPublicSSH().toString("base64");
  const clientPrivateKey = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
    }).privateKey,
    clientKey = ssh2.utils.parseKey(clientPrivateKey);
  const text = async (name) => readFile(new URL("./cisco/" + name, import.meta.url), "utf8");
  const xe = await text("show-version-iosxe.txt"),
    classic = await text("show-version-classic-ios.txt"),
    nxos = await text("show-version-nxos.txt");
  const outputs = {
    "show version": xe,
    "show inventory": await text("show-inventory-iosxe.txt"),
    "show interfaces status": await text("show-interfaces-status-iosxe.txt"),
    "show ip interface brief": await text("show-ip-interface-brief-iosxe.txt"),
    "show vlan brief": await text("show-vlan-brief-iosxe.txt"),
    "show interfaces trunk": await text("show-interfaces-trunk-iosxe.txt"),
    "show etherchannel summary": await text("show-etherchannel-summary-iosxe.txt"),
    "show spanning-tree summary": await text("show-spanning-tree-summary-iosxe.txt"),
    "show ip route": await text("show-ip-route-iosxe.txt"),
    "show access-lists": await text("show-access-lists-iosxe.txt"),
    "show processes cpu":
      "CPU utilization for five seconds: 7%/0%; one minute: 5%; five minutes: 4%",
    "show processes memory": "Processor Pool Total: 100000000 Used: 45000000 Free: 55000000",
    "show running-config | include ^hostname": "hostname Switch",
    "show interfaces":
      "GigabitEthernet1/0/1 is up, line protocol is up\n  Hardware is Gigabit Ethernet\n  100 packets input, 123456789 bytes\n  200 packets output, 234567890 bytes\nVlan120 is administratively down, line protocol is down\n  0 packets input, 0 bytes\n  0 packets output, 0 bytes",
    "show interfaces counters errors": "Port FCS-Err\nGi1/0/1 0",
    "show ip arp": "Internet 192.0.2.5 1 0200.0000.0001 ARPA Vlan120",
    "show mac address-table": "120 0200.0000.0001 DYNAMIC Gi1/0/1",
    "show running-config | include ^username":
      "username admin privilege 15 secret 9 NEVER_CISCO_HASH",
    "show running-config | include ^version|^hostname|^boot|^service timestamps|^ntp server|^logging host|^snmp-server":
      "hostname Switch\nsnmp-server community NEVER_CISCO_COMMUNITY RO\nsnmp-server user operator group v3 auth sha NEVER_CISCO_AUTH priv aes 128 NEVER_CISCO_PRIV\nntp server 192.0.2.123",
    "show startup-config | include ^version|^hostname|^boot|^service timestamps|^ntp server|^logging host|^snmp-server":
      "hostname Switch",
    "show aaa servers": "Server: fixture\nkey = NEVER_CISCO_AAA",
    "show snmp": "Community name: NEVER_CISCO_SNMP",
    "show logging": "logging host 192.0.2.80",
    "show ntp status": "Clock is synchronized",
    "show ip ssh": "SSH Enabled - version 2.0",
    "show clock detail": "12:00:00 UTC Fri Nov 6 2026",
    "dir flash:": "100000000 bytes total (50000000 bytes free)",
    "show license summary": "Network Essentials active",
    "show hosts": "Default domain: fixture",
  };
  const calls = [],
    clients = new Set(),
    waiting = [];
  let password = "cisco-fixture-2026";
  let mode = "normal",
    paused,
    observed;
  const server = new ssh2.Server(
    {
      hostKeys: [privateKey],
      ...(legacy
        ? {
            algorithms: {
              kex: ["diffie-hellman-group14-sha1"],
              serverHostKey: ["ssh-rsa"],
              cipher: ["aes128-cbc"],
              hmac: ["hmac-sha1"],
            },
          }
        : {}),
    },
    (client) => {
      clients.add(client);
      client.on("error", () => {});
      client.on("close", () => clients.delete(client));
      client.on("authentication", (ctx) => {
        if (ctx.username !== "fixture") return ctx.reject();
        if (ctx.method === "password" && ctx.password === password) return ctx.accept();
        if (
          ctx.method === "publickey" &&
          ctx.key.data.equals(clientKey.getPublicSSH()) &&
          (!ctx.signature || clientKey.verify(ctx.blob, ctx.signature, ctx.hashAlgo))
        )
          return ctx.accept();
        ctx.reject();
      });
      client.on("ready", () =>
        client.on("session", (accept) => {
          const session = accept();
          session.on("pty", (accept) => accept());
          session.on("shell", (accept) => {
            const stream = accept();
            let pending = "",
              more;
            let elevated = !userExec,
              awaitingEnable = false;
            stream.write(
              "Welcome to owned fixture\r\n\x1b[32mSwitch" + (elevated ? "#" : ">") + "\x1b[0m ",
            );
            stream.on("data", (chunk) => {
              const input = chunk.toString();
              if (more && input === " ") {
                const resume = more;
                more = undefined;
                resume();
                return;
              }
              pending += input;
              while (pending.includes("\n")) {
                const end = pending.indexOf("\n"),
                  command = pending.slice(0, end).trim();
                pending = pending.slice(end + 1);
                if (command === "exit") {
                  stream.exit(0);
                  stream.end();
                  return;
                }
                if (awaitingEnable) {
                  awaitingEnable = false;
                  elevated = command === enablePassword;
                  if (echoEnable) stream.write(command + "\r\n");
                  stream.write(elevated ? "\r\nSwitch# " : "\r\n% Bad secrets\r\nSwitch> ");
                  continue;
                }
                calls.push(command);
                if (command === "enable" && !elevated) {
                  awaitingEnable = true;
                  stream.write("enable\r\nPassword: ");
                  continue;
                }
                if (!elevated) {
                  stream.write("% Authorization failed.\r\nSwitch> ");
                  continue;
                }
                const respond = () => {
                  let output =
                    mode === "classic" && command === "show version"
                      ? classic
                      : mode === "nxos" && command === "show version"
                        ? nxos
                        : mode === "linux" && command === "show version"
                          ? "Linux fixture"
                          : mode === "partial" && command === "show processes memory"
                            ? "% Authorization failed."
                            : mode === "partial" && command === "show inventory"
                              ? "% Invalid input detected at '^' marker."
                              : (outputs[command] ?? "No entries");
                  if (mode === "large" && command === "show inventory")
                    output = Array.from(
                      { length: 600 },
                      (_, i) =>
                        `NAME: "Module${i}", DESCR: "Fixture"\nPID: FIXTURE, VID: V01, SN: MODULE${i}`,
                    ).join("\n");
                  stream.write(command + "\r\n");
                  if (command === "show interfaces") {
                    const split = output.indexOf("Vlan120");
                    stream.write(output.slice(0, split) + "\r\n--More--\b\b");
                    more = () => stream.write(output.slice(split) + "\r\nSwitch# ");
                  } else stream.write(output + "\r\nSwitch# ");
                };
                if (paused === command) {
                  waiting.push(respond);
                  observed?.();
                } else respond();
              }
            });
          });
        }),
      );
    },
  );
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const release = () => {
    paused = undefined;
    for (const resume of waiting.splice(0)) resume();
  };
  return {
    host: "127.0.0.1",
    port: server.address().port,
    username: "fixture",
    get password() {
      return password;
    },
    setPassword(value) {
      password = value;
    },
    hostKey,
    privateKey: clientPrivateKey,
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
      for (const client of clients) client.end();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
