import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url),
  { runFortiSession } = require("../dist/modules/devices/fortigate-session.js"),
  {
    compileFortiChange,
    fortiActionMatches,
    fortiActionBefore,
    fortiActionContexts,
  } = require("../dist/modules/devices/fortigate-change.js"),
  {
    parseFortiBlocks,
    isFortiConfigComplete,
  } = require("../dist/modules/devices/fortigate-inventory.js"),
  { parseFortiSystemConfig } = require("../dist/modules/devices/fortigate-network.js");
async function peer(flags, fn) {
  const server = spawn(
    "python3",
    ["test/fixtures/terminal-server.py", "--fortigate", "--fortigate-vdom", ...flags],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  server.stderr.on("data", () => {});
  const lines = createInterface({ input: server.stdout });
  try {
    const [line] = await once(lines, "line", { signal: AbortSignal.timeout(10000) }),
      fixture = JSON.parse(line),
      events = [];
    lines.on("line", (line) => events.push(JSON.parse(line)));
    const device = {
        type: "fortigate",
        protocol: "ssh",
        host: "127.0.0.1",
        managementPort: fixture.port,
      },
      credentials = { username: "fixture", password: "fixture-secret", hostKey: fixture.hostKey };
    await fn({ device, credentials, events });
  } finally {
    lines.close();
    server.kill("SIGTERM");
    await once(server, "exit");
  }
}
await peer([], async ({ device, credentials, events }) => {
  async function read(input) {
    const contexts = fortiActionContexts(input.action);
    const result = await runFortiSession(device, credentials, [
      "config global",
      ...contexts.map((c) => "show full-configuration " + c),
    ]);
    return {
      ...Object.fromEntries(
        contexts.map((c, i) => {
          assert.equal(isFortiConfigComplete(result[i + 1], "config " + c), true);
          return [c, parseFortiSystemConfig(c, result[i + 1]) ?? parseFortiBlocks(result[i + 1])];
        }),
      ),
      __fortios: [{ name: "version", settings: { vdomMode: ["enabled"] } }],
    };
  }
  async function apply(input) {
    input = { value: "", ...input };
    const p = compileFortiChange(input);
    await runFortiSession(
      device,
      credentials,
      ["config global", ...p.commands],
      input.action === "vdom.create" ? { confirmVdomCreate: { name: input.name } } : {},
    );
    const tables = await read(input);
    assert.equal(
      fortiActionMatches(tables[p.context], input, p.assignments, tables),
      true,
      input.action,
    );
    return { p, tables };
  }
  await apply({ action: "vdom.create", name: "Branch" });
  assert.equal(events.filter((e) => e.name === "Branch").length, 1);
  await apply({
    action: "vdom.update",
    name: "Branch",
    vdomShortName: "BR",
    vdomDescription: 'نام "فارسی"',
  });
  const moved = await apply({ action: "vdom.moveInterface", name: "port3", targetVdom: "Branch" });
  assert.ok(!moved.tables["system vdom"].some((r) => r.name === "port3"));
  assert.equal(
    moved.tables["system interface"].find((r) => r.name === "port3").settings.alias[0],
    "Preserved",
  );
  const before = await read({ action: "vdom.update" }),
    changes = fortiActionBefore(
      before["system vdom"],
      { action: "vdom.update", name: "Branch" },
      { "short-name": "", description: "" },
      before,
    );
  assert.equal(changes.description, 'نام "فارسی"');
  await apply({ action: "vdom.update", name: "Branch", vdomShortName: "", vdomDescription: "" });
  await assert.rejects(
    runFortiSession(device, credentials, [
      "config global",
      "config vdom",
      'delete "Branch"',
      "end",
    ]),
    (e) => e.code === "FORTI_CLI_FAILED",
  );
  await apply({ action: "vdom.moveInterface", name: "port3", targetVdom: "root" });
  await apply({ action: "vdom.delete", name: "Branch" });
  await assert.rejects(
    runFortiSession(device, credentials, [
      "config global",
      "config vdom",
      'edit "NoConsent"',
      "next",
      "end",
    ]),
    (e) => e.code === "FORTI_CONFIRMATION_REQUIRED",
  );
  assert.equal(events.filter((e) => e.name === "NoConsent").length, 0);
  await assert.rejects(
    runFortiSession(
      device,
      credentials,
      ["config global", "config vdom", 'edit "Target"', "next", "end"],
      { confirmVdomCreate: { name: "WrongTarget" } },
    ),
    /FORTI_INVALID_PLAN/,
  );
  const settings = (await read({ action: "vdom.create" }))["system global"][0].settings;
  assert.equal(settings["edit-vdom-prompt"][0], "enable");
});
await peer(["--vdom-wrong-prompt"], async ({ device, credentials, events }) => {
  await assert.rejects(
    runFortiSession(
      device,
      credentials,
      ["config global", "config vdom", 'edit "Unexpected"', "next", "end"],
      { confirmVdomCreate: { name: "Unexpected" } },
    ),
    (e) => e.code === "FORTI_CONFIRMATION_REQUIRED",
  );
  assert.equal(events.length, 0);
});
await peer(["--vdom-repeat-prompt"], async ({ device, credentials, events }) => {
  await assert.rejects(
    runFortiSession(
      device,
      credentials,
      ["config global", "config vdom", 'edit "Repeated"', "next", "end"],
      { confirmVdomCreate: { name: "Repeated" } },
    ),
    (e) => e.code === "FORTI_CONFIRMATION_REQUIRED",
  );
  assert.equal(events.length, 1);
});
console.log(
  "Forti VDOM independent wire: split native prompt answered only once for exact approved edit, unknown/repeated/missing-consent/wrong-target rejection, global create/update/unset/move/delete, separate fresh-session readback, native reference refusal, preserved interface fields and unchanged global prompt setting passed.",
);
