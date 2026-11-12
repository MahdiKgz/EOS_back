import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url),
  { runFortiSession } = require("../dist/modules/devices/fortigate-session.js"),
  { compileFortiInterface } = require("../dist/modules/devices/fortigate-action-compiler.js"),
  { compileFortiChange } = require("../dist/modules/devices/fortigate-change.js"),
  { parseFortiBlocks } = require("../dist/modules/devices/fortigate-inventory.js"),
  server = spawn("python3", ["test/fixtures/terminal-server.py", "--fortigate"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
server.stderr.on("data", () => {});
const lines = createInterface({ input: server.stdout });
try {
  const [line] = await once(lines, "line", { signal: AbortSignal.timeout(10000) }),
    fixture = JSON.parse(line),
    device = {
      type: "fortigate",
      protocol: "ssh",
      host: "127.0.0.1",
      managementPort: fixture.port,
    },
    credentials = { username: "fixture", password: "fixture-secret", hostKey: fixture.hostKey };
  const plan = compileFortiInterface({
    action: "interface.alias",
    name: "lan",
    value: "Independent#Alias",
  });
  const outputs = await runFortiSession(device, credentials, [
    "get system status",
    ...plan.commands,
    "show full-configuration system interface",
  ]);
  assert.equal(parseFortiBlocks(outputs.at(-1))[0].settings.alias[0], "Independent#Alias");
  const access = await runFortiSession(device, credentials, [
    ...compileFortiInterface({
      action: "interface.allowaccess",
      name: "lan",
      value: "ping,https,ssh",
    }).commands,
    "show full-configuration system interface",
  ]);
  assert.deepEqual(parseFortiBlocks(access.at(-1))[0].settings.allowaccess, [
    "ping",
    "https",
    "ssh",
  ]);
  const cleared = await runFortiSession(device, credentials, [
    ...compileFortiInterface({ action: "interface.allowaccess", name: "lan", value: "" }).commands,
    "show full-configuration system interface",
  ]);
  assert.equal(parseFortiBlocks(cleared.at(-1))[0].settings.allowaccess, undefined);
  async function object(input) {
    const descriptor = compileFortiChange(input);
    const before = parseFortiBlocks(
      (
        await runFortiSession(device, credentials, [
          "show full-configuration " + descriptor.context,
        ])
      )[0],
    );
    const compiled = compileFortiChange(
      input,
      before.find((row) => row.name === input.name),
    );
    const outputs = await runFortiSession(device, credentials, [
      ...compiled.commands,
      "show full-configuration " + compiled.context,
    ]);
    return parseFortiBlocks(outputs.at(-1)).find((row) => row.name === input.name)?.settings;
  }
  assert.equal(
    (
      await object({
        action: "address.create",
        name: "subnet",
        addressType: "subnet",
        value: "198.51.100.0/24",
      })
    ).type[0],
    "ipmask",
  );
  let address = await object({
    action: "address.create",
    name: "wildcard",
    addressType: "wildcard-fqdn",
    value: "*.example.com",
  });
  assert.equal(address.type[0], "fqdn");
  assert.equal(address.fqdn[0], "*.example.com");
  address = await object({
    action: "address.update",
    name: "subnet",
    addressType: "iprange",
    value: "192.0.2.2",
    endIp: "192.0.2.4",
  });
  assert.equal(address["end-ip"][0], "192.0.2.4");
  let service = await object({
    action: "service.create",
    name: "web",
    serviceProtocol: "TCP-UDP",
    value: "80,443",
    udpPorts: "443",
  });
  assert.equal(service.protocol[0], "TCP/UDP/SCTP");
  assert.deepEqual(service["tcp-portrange"], ["80", "443"]);
  service = await object({
    action: "service.update",
    name: "web",
    serviceProtocol: "UDP",
    value: "53",
  });
  assert.equal(service["tcp-portrange"], undefined);
  assert.deepEqual(service["udp-portrange"], ["53"]);
  assert.deepEqual(
    (await object({ action: "addressGroup.create", name: "addresses", value: "subnet,wildcard" }))
      .member,
    ["subnet", "wildcard"],
  );
  assert.deepEqual(
    (await object({ action: "addressGroup.remove", name: "addresses", value: "subnet" })).member,
    ["wildcard"],
  );
  assert.deepEqual(
    (await object({ action: "serviceGroup.create", name: "services", value: "web,HTTPS" })).member,
    ["web", "HTTPS"],
  );
  assert.deepEqual(
    (
      await object({
        action: "schedule.create",
        name: "office",
        value: "monday,tuesday",
        start: "08:30",
        end: "17:45",
      })
    ).day,
    ["monday", "tuesday"],
  );
  assert.equal(
    (await object({ action: "zone.create", name: "zone", value: "", intrazone: "deny" })).interface,
    undefined,
  );
  assert.deepEqual((await object({ action: "zone.add", name: "zone", value: "lan" })).interface, [
    "lan",
  ]);
  assert.equal(
    (await object({ action: "zone.remove", name: "zone", value: "lan" })).interface,
    undefined,
  );
  assert.equal(await object({ action: "zone.delete", name: "zone", value: "" }), undefined);
  const vip = await object({
    action: "vip.create",
    name: "web-vip",
    value: "",
    externalIp: "198.51.100.1",
    mappedIp: "192.0.2.1",
    externalPort: "8443",
    mappedPort: "443",
  });
  assert.deepEqual(vip.mappedip, ["192.0.2.1"]);
  assert.deepEqual(vip.extintf, ["any"]);
  assert.deepEqual(
    (await object({ action: "vip.update", name: "web-vip", value: "", mappedPort: "9443" }))
      .mappedport,
    ["9443"],
  );
  assert.deepEqual(
    (await object({ action: "vipGroup.create", name: "vip-group", value: "web-vip" })).member,
    ["web-vip"],
  );
  assert.deepEqual(
    (
      await object({
        action: "ipPool.create",
        name: "pool",
        value: "198.51.100.10",
        endIp: "198.51.100.20",
      })
    ).startip,
    ["198.51.100.10"],
  );
  assert.deepEqual(
    (await object({ action: "ipPool.update", name: "pool", value: "", endIp: "198.51.100.15" }))
      .endip,
    ["198.51.100.15"],
  );
  assert.equal(await object({ action: "ipPool.delete", name: "pool", value: "" }), undefined);
  await assert.rejects(
    runFortiSession(device, credentials, [
      "config firewall address",
      'edit "invalid"',
      "set type subnet",
      "next",
      "end",
    ]),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  await assert.rejects(
    runFortiSession(device, credentials, [
      "config firewall service custom",
      'edit "invalid"',
      "set protocol TCP",
      "next",
      "end",
    ]),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  await assert.rejects(
    runFortiSession(device, { ...credentials, hostKey: fixture.wrongHostKey }, [
      "get system status",
    ]),
  );
  await assert.rejects(
    runFortiSession(device, { ...credentials, password: "wrong" }, ["get system status"]),
  );
  await assert.rejects(
    runFortiSession(
      device,
      credentials,
      compileFortiInterface({ action: "interface.alias", name: "lan", value: "fail" }).commands,
    ),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  await assert.rejects(
    runFortiSession(
      device,
      credentials,
      compileFortiInterface({ action: "interface.alias", name: "lan", value: "stderr" }).commands,
    ),
    (e) => e.code === "FORTI_STDERR_RECEIVED",
  );
  assert.throws(() =>
    compileFortiInterface({
      action: "interface.alias",
      name: 'lan"\nset status down',
      value: "Alias",
    }),
  );
  assert.throws(() =>
    compileFortiInterface({ action: "interface.ip", name: "lan", value: "192.0.2.1/24/extra" }),
  );
  console.log(
    "Forti session: actual SSH2 client vs independent Paramiko, sequential context prompts, readback, alias #, object/address/service wire enums, membership/unset/schedule/zone/delete, host pin/password rejection, CLI/stderr errors and injection/CIDR rejection passed.",
  );
} finally {
  lines.close();
  server.kill("SIGTERM");
  await once(server, "exit");
}
