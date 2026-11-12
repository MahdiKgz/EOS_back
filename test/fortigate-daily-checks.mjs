import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fortigateSshFixture } from "./fixtures/fortigate-ssh-server.mjs";
const require = createRequire(import.meta.url),
  {
    FORTIGATE_READ_COMMANDS,
    buildFortiInventory,
    isFortiConfigComplete,
  } = require("../dist/modules/devices/fortigate-inventory.js"),
  { buildFortiDailyCheck } = require("../dist/modules/devices/fortigate-daily-check.js"),
  { redactFortiOutput } = require("../dist/modules/devices/fortigate-output.js");
const fixture = await fortigateSshFixture();
try {
  const collection = buildFortiInventory(
    Object.fromEntries(
      Object.entries(FORTIGATE_READ_COMMANDS).map(([key, command]) => [
        key,
        redactFortiOutput(fixture.outputs[command] ?? ""),
      ]),
    ),
    Object.keys(FORTIGATE_READ_COMMANDS).map((commandId) => ({
      commandId,
      state: "collected",
      lineCount: 1,
      evidence: [],
    })),
    [],
  );
  collection.system.license = "Valid";
  collection.tables
    .find((t) => t.key === "interfaces")
    .rows.forEach((row) => (row.allowaccess = "ping"));
  assert.equal(buildFortiDailyCheck(collection).status, "safe");
  const unknownLicense = structuredClone(collection);
  unknownLicense.system.license = "Validation pending";
  assert.equal(
    buildFortiDailyCheck(unknownLicense).sections.find((s) => s.key === "license").status,
    "not_checked",
  );
  const notValid = structuredClone(collection);
  notValid.system.license = "Not valid";
  assert.equal(
    buildFortiDailyCheck(notValid).sections.find((s) => s.key === "license").status,
    "needs_review",
  );
  const missingPolicy = structuredClone(collection);
  missingPolicy.tables.find((t) => t.key === "policies").rows[0].logtraffic = null;
  assert.equal(
    buildFortiDailyCheck(missingPolicy).sections.find((s) => s.key === "policy_nat_vip").status,
    "not_checked",
  );
  const unsafeSSL = structuredClone(collection);
  unsafeSSL.rawSections.find((s) => s.key === "sslSettings").lines = [
    "config vpn ssl settings",
    "set status enable",
    "end",
  ];
  assert.equal(
    buildFortiDailyCheck(unsafeSSL).sections.find((s) => s.key === "vpn").status,
    "needs_review",
  );
  assert.equal(
    isFortiConfigComplete(
      'config system admin\n edit "operator"\nconfig gui-dashboard\nedit 1\nnext\nend\nnext\nend',
      "config system admin",
    ),
    true,
  );
  assert.equal(
    isFortiConfigComplete('config system admin\nedit "operator"\nend', "config system admin"),
    false,
  );
  assert.equal(
    isFortiConfigComplete('config system admin\nedit "operator"\nnext', "config system admin"),
    false,
  );
  console.log(
    "Forti daily checks: unknown/negative license, missing policy evidence, SSL restrictions and incomplete/nested config do not produce false healthy results.",
  );
} finally {
  await fixture.close();
}
