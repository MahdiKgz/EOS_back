import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { EventEmitter } from "node:events";
import { gzipSync } from "node:zlib";

const require = createRequire(import.meta.url);
const transport = require("../dist/modules/devices/ssh-transport.js");
const {
  collectBackup,
  sealBackup,
  unsealBackup,
} = require("../dist/modules/devices/device-backup.js");
const { receiveScpFile } = require("../dist/modules/devices/ssh-scp.js");
const { validateBackup } = require("../dist/modules/devices/backup-validation.js");
const commands = [];
let version = "7.16.2";
transport.runSshCommand = async (_device, _credentials, command, options) => {
  commands.push(command);
  if (command.startsWith(":put")) return Buffer.from(version);
  if (command.startsWith("/export"))
    return Buffer.from("# RouterOS\n/interface bridge\nadd name=bridge1\n");
  if (command === "show running-config") {
    assert.equal(options.interactive, true);
    return Buffer.from(
      "Switch#show running-config\r\nBuilding configuration...\r\n\r\nCurrent configuration : 42 bytes\r\n!\r\nversion 17.9\r\nhostname Fixture\r\nend\r\nSwitch#exit\r\n",
    );
  }
  if (command === "scp -f sys_config") {
    assert.equal(options.scp, true);
    return Buffer.from("#config-version=FGT\nconfig system global\nset hostname Fixture\nend\n");
  }
  if (command.includes("/conf/config.xml"))
    return Buffer.from('<?xml version="1.0"?><pfsense><version>23.7</version></pfsense>');
  throw new Error("Unexpected command");
};
const baseDevice = {
  id: "d",
  workspaceOwnerId: "w",
  name: "Fixture",
  host: "192.0.2.4",
  managementPort: 22,
  protocol: "ssh",
};
const credentials = { username: "fixture", hostKey: "fixture", password: "secret" };
for (const type of ["mikrotik", "cisco", "fortigate", "pfsense"]) {
  const result = await collectBackup({ ...baseDevice, type }, credentials);
  assert.ok(result.bytes.length > 0);
  assert.match(result.sha256, /^[a-f0-9]{64}$/);
  if (type === "cisco") {
    assert.match(result.bytes.toString(), /^!\nversion 17.9/);
    assert.equal(result.bytes.toString().includes("Switch#"), false);
  }
}
assert.ok(commands.includes("/export terse show-sensitive"));
version = "6.49.17";
await collectBackup({ ...baseDevice, type: "mikrotik" }, credentials);
assert.ok(commands.includes("/export terse hide-sensitive=no"));
await assert.rejects(collectBackup({ ...baseDevice, type: "esxi" }, credentials), { status: 400 });
assert.throws(() => validateBackup({ key: "linux" }, gzipSync(Buffer.from("incomplete tar"))));
assert.throws(() =>
  validateBackup({ key: "cisco" }, Buffer.from("version 17.9\nhostname no-end\n")),
);

function fakeChild() {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stdin = new EventEmitter();
  const acks = [];
  child.stdin.write = (bytes) => acks.push(bytes);
  child.stdin.end = (bytes) => acks.push(bytes);
  child.kill = () => {
    child.killed = true;
    return true;
  };
  return { child, acks };
}
const { child, acks } = fakeChild();
const result = receiveScpFile(child, 100);
for (const bytes of [Buffer.from("C0644 5 sys_"), Buffer.from("config\nhe"), Buffer.from("llo\0")])
  child.stdout.emit("data", bytes);
assert.equal(result().toString(), "hello");
assert.equal(acks.length, 3);
const oversized = fakeChild();
const tooBig = receiveScpFile(oversized.child, 100);
oversized.child.stdout.emit("data", Buffer.from("C0644 101 sys_config\n"));
assert.throws(tooBig);
assert.equal(oversized.child.killed, true);
const truncated = fakeChild();
const incomplete = receiveScpFile(truncated.child, 100);
truncated.child.stdout.emit("data", Buffer.from("C0644 5 sys_config\nhi"));
assert.throws(incomplete);

process.env.DEVICE_CREDENTIAL_KEY = "b".repeat(64);
const sealed = sealBackup(Buffer.from("confidential config"), "id", "device", "workspace");
assert.deepEqual(
  unsealBackup(sealed, "id", "device", "workspace"),
  Buffer.from("confidential config"),
);
assert.throws(() => unsealBackup(sealed, "id", "other-device", "workspace"));
const changed = Buffer.from(sealed);
changed[changed.length - 1] ^= 1;
assert.throws(() => unsealBackup(changed, "id", "device", "workspace"));
console.log(
  "PASS: vendor backup commands, configuration validation, SCP framing and encrypted file binding",
);
