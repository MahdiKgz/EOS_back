import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { EventEmitter } from "node:events";
const require = createRequire(import.meta.url);
const transport = require("../dist/modules/devices/ssh-transport.js");
const { sendScpFile } = require("../dist/modules/devices/ssh-scp.js");
const { sendSftpFile } = require("../dist/modules/devices/ssh-sftp.js");
const {
  preflightRestore,
  applyRestore,
  verifyRestoredConfiguration,
} = require("../dist/modules/devices/native-restore.js");
const configs = {
  cisco: Buffer.from(
    "version 17.9\nhostname Fixture\ninterface GigabitEthernet0/1\n description restored\nend\n",
  ),
  mikrotik: Buffer.from(
    "# by RouterOS 7.16.2\n# model = fixture\n# serial number = a1\n/interface bridge\nadd name=fixture\n",
  ),
  fortigate: Buffer.from(
    "#config-version=FGT-7.4.3:opmode=0\nconfig system global\nset hostname fixture\nend\n",
  ),
};
const credentials = { username: "fixture", password: "fixture-secret", hostKey: "fixture" };
const base = {
  id: "fixture",
  name: "fixture",
  workspaceOwnerId: "workspace",
  protocol: "ssh",
  host: "192.0.2.5",
  managementPort: 22,
};
let commands = [],
  version = "7.16.2",
  dryRunFailure = false,
  mismatch = false;
transport.runSshCommand = async (device, _credentials, text, options) => {
  commands.push({ text, options });
  if (text.startsWith(":put")) return Buffer.from(version);
  if (text.startsWith("/export"))
    return mismatch
      ? Buffer.from(configs.mikrotik.toString().replace("name=fixture", "name=different"))
      : configs.mikrotik;
  if (text === "show running-config")
    return mismatch
      ? Buffer.from(configs.cisco.toString().replace("hostname Fixture", "hostname Different"))
      : configs.cisco;
  if (text === "scp -f sys_config") return configs.fortigate;
  if (text === "sftp") {
    assert.match(options.sftpUpload.filename, /^soar-[a-f0-9]{32}\.rsc$/);
    assert.deepEqual(options.sftpUpload.content, configs.mikrotik);
  }
  if (text.includes("dry-run") && dryRunFailure)
    return Buffer.from("failure: invalid configuration");
  if (text.startsWith("configure replace")) {
    assert.equal(options.interactive, true);
    assert.equal(options.allowPromptChange, true);
  }
  if (text.startsWith("scp -t")) {
    assert.match(options.scpUpload.filename, /^soar-[a-f0-9]{32}\.(cfg|conf)$/);
    assert.deepEqual(options.scpUpload.content, configs[device.type]);
  }
  return Buffer.from("");
};
const mikrotik = { ...base, type: "mikrotik" };
version = "6.49.17";
await assert.rejects(preflightRestore(mikrotik, credentials, "mikrotik", configs.mikrotik), {
  status: 409,
});
version = "7.15.3";
await assert.rejects(preflightRestore(mikrotik, credentials, "mikrotik", configs.mikrotik), {
  status: 409,
});
version = "7.16.2";
await preflightRestore(mikrotik, credentials, "mikrotik", configs.mikrotik);
commands = [];
dryRunFailure = true;
await assert.rejects(applyRestore(mikrotik, credentials, "mikrotik", configs.mikrotik), {
  status: 502,
});
assert.equal(
  commands.some(({ text }) => text.startsWith("/import") && !text.includes("dry-run")),
  false,
);
assert.ok(commands.some(({ text }) => text.startsWith("/file remove")));
dryRunFailure = false;
commands = [];
assert.equal(
  (await applyRestore(mikrotik, credentials, "mikrotik", configs.mikrotik)).verified,
  true,
);
const dry = commands.findIndex(({ text }) => text.includes("dry-run")),
  imported = commands.findIndex(
    ({ text }) => text.startsWith("/import") && !text.includes("dry-run"),
  );
assert.ok(dry >= 0 && imported > dry);
mismatch = true;
assert.equal(
  (await applyRestore(mikrotik, credentials, "mikrotik", configs.mikrotik)).state,
  "applied_merge_needs_review",
);
mismatch = false;
commands = [];
assert.equal(
  (await applyRestore({ ...base, type: "cisco" }, credentials, "cisco", configs.cisco)).state,
  "running_configuration_verified",
);
assert.ok(
  commands.findIndex(({ text }) => text === "configure confirm") >
    commands.findIndex(({ text }) => text === "show running-config"),
);
assert.ok(commands.at(-1).text.startsWith("delete /force flash:/soar-"));
commands = [];
mismatch = true;
await assert.rejects(
  applyRestore({ ...base, type: "cisco" }, credentials, "cisco", configs.cisco),
  { status: 502 },
);
assert.equal(
  commands.some(({ text }) => text === "configure confirm"),
  false,
);
mismatch = false;
commands = [];
const receipt = await applyRestore(
  { ...base, type: "fortigate" },
  credentials,
  "fortigate",
  configs.fortigate,
);
assert.equal(receipt.verified, false);
assert.equal(receipt.state, "awaiting_verification");
assert.equal(
  await verifyRestoredConfiguration(
    { ...base, type: "fortigate" },
    credentials,
    "fortigate",
    configs.fortigate,
  ),
  true,
);

function child() {
  const process = new EventEmitter();
  process.stdout = new EventEmitter();
  process.stdin = new EventEmitter();
  const writes = [];
  process.stdin.write = (bytes) => {
    writes.push(Buffer.from(bytes));
    return true;
  };
  process.stdin.end = () => {
    process.ended = true;
  };
  process.kill = () => {
    process.killed = true;
  };
  return { process, writes };
}
const filename = "soar-" + "a".repeat(32);
const scp = child(),
  scpResult = sendScpFile(scp.process, Buffer.from("binary\0config"), filename + ".cfg");
scp.process.stdout.emit("data", Buffer.from([0]));
assert.equal(scp.writes[0].toString(), `C0600 13 ${filename}.cfg\n`);
scp.process.stdout.emit("data", Buffer.from([0]));
assert.deepEqual(scp.writes[1], Buffer.from("binary\0config"));
assert.throws(scpResult);
scp.process.stdout.emit("data", Buffer.from([0]));
scpResult();
assert.equal(scp.process.ended, true);
const denied = child(),
  deniedResult = sendScpFile(denied.process, Buffer.from("data"), filename + ".conf");
denied.process.stdout.emit("data", Buffer.from([1]));
assert.throws(deniedResult);
assert.equal(denied.process.killed, true);
const u32 = (value) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value);
  return b;
};
const str = (bytes) => Buffer.concat([u32(bytes.length), bytes]);
const frame = (type, ...values) => {
  const payload = Buffer.concat([Buffer.from([type]), ...values]);
  return Buffer.concat([u32(payload.length), payload]);
};
const versionFrame = frame(2, u32(3)),
  handleFrame = frame(102, u32(1), str(Buffer.from("handle")));
const payload = Buffer.alloc(70001, 0x9b),
  sftp = child(),
  finish = sendSftpFile(sftp.process, payload, filename + ".rsc");
assert.deepEqual(sftp.writes[0], frame(1, u32(3)));
sftp.process.stdout.emit("data", versionFrame.subarray(0, 2));
sftp.process.stdout.emit("data", versionFrame.subarray(2));
const opened = sftp.writes.at(-1);
assert.equal(opened[4], 3);
const pathLength = opened.readUInt32BE(9);
assert.equal(opened.readUInt32BE(13 + pathLength), 0x2a);
assert.equal(opened.readUInt32BE(21 + pathLength), 0o600);
sftp.process.stdout.emit("data", handleFrame);
let total = 0;
const received = [];
while (sftp.writes.at(-1)[4] === 6) {
  const packet = sftp.writes.at(-1),
    id = packet.readUInt32BE(5),
    handleSize = packet.readUInt32BE(9),
    start = 13 + handleSize;
  assert.equal(Number(packet.readBigUInt64BE(start)), total);
  const size = packet.readUInt32BE(start + 8),
    bytes = packet.subarray(start + 12);
  assert.equal(size, bytes.length);
  assert.ok(size <= 32768);
  total += size;
  received.push(bytes);
  const status = frame(101, u32(id), u32(0), str(Buffer.alloc(0)), str(Buffer.alloc(0)));
  sftp.process.stdout.emit("data", status.subarray(0, 7));
  sftp.process.stdout.emit("data", status.subarray(7));
}
assert.equal(total, payload.length);
assert.deepEqual(Buffer.concat(received), payload);
const closed = sftp.writes.at(-1);
assert.equal(closed[4], 4);
assert.throws(finish);
sftp.process.stdout.emit(
  "data",
  frame(101, u32(closed.readUInt32BE(5)), u32(0), str(Buffer.alloc(0)), str(Buffer.alloc(0))),
);
finish();
assert.equal(sftp.process.ended, true);
for (const response of [
  frame(101, u32(99), u32(0)),
  frame(101, u32(2), u32(4)),
  Buffer.from([0xff, 0xff, 0xff, 0xff]),
]) {
  const bad = child(),
    failed = sendSftpFile(bad.process, Buffer.from("data"), filename + ".rsc");
  bad.process.stdout.emit("data", versionFrame);
  bad.process.stdout.emit("data", handleFrame);
  bad.process.stdout.emit("data", response);
  assert.throws(failed);
  assert.equal(bad.process.killed, true);
}
const incomplete = child(),
  incompleteResult = sendSftpFile(incomplete.process, Buffer.from("data"), filename + ".rsc");
incomplete.process.stdout.emit("data", versionFrame.subarray(0, 3));
assert.throws(incompleteResult);
assert.throws(() => sendSftpFile(child().process, Buffer.from("data"), "../outside"));
console.log(
  "PASS: native vendor restore ordering/dry-run/confirm/read-back, SCP acknowledgements and fragmented exclusive-create SFTP v3 writes",
);
