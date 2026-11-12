import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { gzipSync } from "node:zlib";
const require = createRequire(import.meta.url);
const {
  validateRestoreArtifact,
  assertCompatible,
  linuxServiceFiles,
  restoreVendor,
} = require("../dist/modules/devices/restore-artifact.js");

function tar(entries) {
  const blocks = [];
  for (const { path, type = "0", link = "", content = "" } of entries) {
    const header = Buffer.alloc(512);
    const bytes = Buffer.from(content);
    header.write(path, 0, 100);
    header.write("0000755\0", 100);
    header.write("0000000\0", 108);
    header.write("0000000\0", 116);
    header.write(bytes.length.toString(8).padStart(11, "0") + "\0", 124);
    header.write("00000000000\0", 136);
    header.fill(32, 148, 156);
    header.write(type, 156);
    header.write(link, 157, 100);
    const sum = header.reduce((result, value) => result + value, 0);
    header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    blocks.push(header, bytes, Buffer.alloc((512 - (bytes.length % 512)) % 512));
  }
  return gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)]));
}
const etc = { path: "etc/", type: "5" };
const archive = tar([
  etc,
  { path: "etc/hostname", content: "fixture-host" },
  { path: "etc/localtime", type: "2", link: "/usr/share/zoneinfo/UTC" },
]);
validateRestoreArtifact("linux", archive);
assert.equal(linuxServiceFiles(archive, true).length, 3);
for (const invalid of [
  [etc, { path: "etc/../escape", content: "x" }],
  [etc, { path: "/etc/shadow", content: "x" }],
  [etc, { path: "etc/hostname", content: "x" }, { path: "etc/hostname", content: "y" }],
  [
    etc,
    { path: "etc/service", type: "2", link: "/tmp/outside" },
    { path: "etc/service/config", content: "x" },
  ],
  [etc, { path: "etc/override", type: "x", content: "pax record" }],
  [etc, { path: "etc/hardlink", type: "1", link: "etc/shadow" }],
  [etc, { path: "outside", content: "x" }],
  [etc, { path: "etc//empty", content: "x" }],
])
  assert.throws(() => validateRestoreArtifact("linux", tar(invalid)));
assert.throws(() => restoreVendor("pfsense"));
assert.equal(restoreVendor("linux_edge"), "linux");
const cisco = Buffer.from("version 17.9\nhostname Fixture\nend\n");
validateRestoreArtifact("cisco", cisco);
assertCompatible("cisco", cisco, cisco);
assert.throws(() =>
  assertCompatible("cisco", cisco, Buffer.from("version 17.8\nhostname Fixture\nend\n")),
);
assert.throws(() => validateRestoreArtifact("cisco", Buffer.concat([cisco, Buffer.from([0xff])])));
assert.throws(() => validateRestoreArtifact("cisco", Buffer.concat([cisco, Buffer.from([0])])));
assert.throws(() =>
  validateRestoreArtifact(
    "fortigate",
    Buffer.from(
      "#config-version=FGT\nconfig system global\nset password FortinetPasswordMask\nend\n",
    ),
  ),
);
const mikrotik = Buffer.from(
  "# by RouterOS 7.16.2\n# model = fixture\n# serial number = a1\n/interface bridge\nadd name=bridge\n",
);
assertCompatible("mikrotik", mikrotik, mikrotik);
assert.throws(() =>
  assertCompatible("mikrotik", mikrotik, Buffer.from(mikrotik.toString().replace("a1", "a2"))),
);
console.log(
  "PASS: restore file validation, vendor identity compatibility, tar traversal/link/duplicate/format rejection",
);
