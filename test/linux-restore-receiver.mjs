import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { LINUX_ETC_RECEIVER } = require("../dist/modules/devices/linux-restore-script.js");
const directory = mkdtempSync(join(tmpdir(), "eos-restore-receiver-"));
const root = join(directory, "etc"),
  outside = join(directory, "outside");
mkdirSync(root);
mkdirSync(outside);
// Exercise the real receiver only inside a disposable directory, using this unprivileged test user's ownership.
const script = LINUX_ETC_RECEIVER.replace('os.open("/etc",', "os.open(sys.argv[1],").replace(
  "p = json.load(sys.stdin)",
  "os.geteuid = lambda: 0\np = json.load(sys.stdin)",
);
const entry = (path, content) => ({
  path,
  kind: "file",
  bytes: Buffer.byteLength(content),
  mode: 0o640,
  uid: process.getuid(),
  gid: process.getgid(),
  sha256: createHash("sha256").update(content).digest("hex"),
  data: Buffer.from(content).toString("base64"),
  link: "",
});
function run(intent, entries) {
  return JSON.parse(
    execFileSync("python3", ["-c", script, root], {
      input: JSON.stringify({ intent, entries }),
      stdio: ["pipe", "pipe", "pipe"],
    }).toString(),
  );
}
try {
  const entries = [entry("etc/config", "restored configuration\n")];
  writeFileSync(join(root, "config"), "original configuration\n");
  assert.equal(run("preflight", entries).verified, true);
  assert.equal(readFileSync(join(root, "config"), "utf8"), "original configuration\n");
  assert.equal(run("apply", entries).verified, true);
  assert.equal(readFileSync(join(root, "config"), "utf8"), "restored configuration\n");
  assert.equal(run("verify", entries).verified, true);
  writeFileSync(join(root, "config"), "tampered");
  assert.throws(() => run("verify", entries));
  symlinkSync(outside, join(root, "danger"));
  writeFileSync(join(outside, "untouched"), "outside data");
  assert.throws(() => run("preflight", [entry("etc/danger/untouched", "changed")]));
  assert.throws(() => run("apply", [entry("etc/danger/untouched", "changed")]));
  assert.equal(readFileSync(join(outside, "untouched"), "utf8"), "outside data");
  assert.throws(() => run("apply", [entry("etc/../outside/untouched", "changed")]));
  console.log(
    "PASS: isolated Python receiver preflight, atomic file apply/read-back, content mismatch, symlink-parent and traversal rejection",
  );
} finally {
  rmSync(directory, { recursive: true, force: true });
}
