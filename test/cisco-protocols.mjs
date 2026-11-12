import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { ciscoSshFixture } from "./fixtures/cisco-ssh-server.mjs";
const require = createRequire(import.meta.url),
  {
    collectCiscoInventory,
    redactCiscoOutput,
  } = require("../dist/modules/devices/cisco-collector.js"),
  {
    detectCiscoPlatform,
    parseCiscoVlans,
    parseCiscoIpInterfaceBrief,
  } = require("../dist/modules/devices/cisco-parsers.js");
const fixture = await ciscoSshFixture();
try {
  const target = {
      id: "fixture",
      host: fixture.host,
      managementPort: fixture.port,
      type: "cisco",
      protocol: "ssh",
    },
    credentials = {
      username: fixture.username,
      password: fixture.password,
      hostKey: fixture.hostKey,
    };
  let report = await collectCiscoInventory(target, credentials);
  assert.equal(report.detection.platform, "cisco-ios-xe");
  assert.equal(report.detection.supported, true);
  assert.equal(report.collection.system.model, "C9300-24T");
  assert.equal(report.collection.health.cpu.fiveSeconds, 7);
  assert.equal(report.collection.health.memory[0].usedBytes, 45000000);
  assert.equal(report.collection.interfaces.switchports[0].operationalStatus, "up");
  assert.equal(report.collection.interfaces.summary[1].ipAddress, "192.0.2.1");
  assert.equal(report.collection.interfaceCounters[0].rxBytes, 123456789);
  assert.equal(report.collection.interfaceCounters[1].rxBytes, 0);
  assert.equal(report.collection.network.etherchannel.entries[0].protocol, "LACP");
  assert.ok(!JSON.stringify(report).includes("NEVER_CISCO_"));
  assert.ok(!JSON.stringify(report).includes(fixture.password));
  assert.ok(!fixture.calls.includes("show running-config"));
  assert.ok(!fixture.calls.some((c) => /^(?:configure|copy|write|delete|reload)/.test(c)));
  const keyReport = await collectCiscoInventory(target, {
    username: fixture.username,
    privateKey: fixture.privateKey,
    hostKey: fixture.hostKey,
  });
  assert.equal(keyReport.detection.platform, "cisco-ios-xe");
  assert.deepEqual(parseCiscoVlans("5 invalid\n0 invalid active\n4095 invalid active"), []);
  assert.deepEqual(parseCiscoIpInterfaceBrief("This is a long login banner with seven words"), []);
  fixture.mode("large");
  const large = await collectCiscoInventory(target, credentials);
  assert.ok(large.warnings.includes("CISCO_OUTPUT_TRUNCATED"));
  assert.ok(large.collection.system.inventory.length <= 256);
  assert.equal(large.collection.inventoryStatus, "partial");
  fixture.mode("classic");
  report = await collectCiscoInventory(target, credentials);
  assert.equal(report.detection.platform, "cisco-ios-classic");
  assert.equal(report.detection.supported, true);
  fixture.mode("partial");
  report = await collectCiscoInventory(target, credentials);
  assert.equal(report.collection.health.memory.length, 0);
  assert.equal(
    report.collection.commandEvidence.find((c) => c.commandId === "memory").errorCode,
    "CISCO_COMMAND_REQUIRES_PRIVILEGE",
  );
  assert.equal(
    report.collection.commandEvidence.find((c) => c.commandId === "inventory").state,
    "not_supported",
  );
  assert.ok(report.warnings.includes("CISCO_PARTIAL_COLLECTION"));
  fixture.mode("nxos");
  const before = fixture.calls.length;
  report = await collectCiscoInventory(target, credentials);
  assert.equal(report.detection.platform, "cisco-nx-os");
  assert.equal(report.detection.supported, false);
  assert.equal(report.collection, null);
  assert.deepEqual(fixture.calls.slice(before), ["show version"]);
  assert.equal(
    detectCiscoPlatform("This note mentions ios-xe but is not a system header").supported,
    false,
  );
  for (const [text, key] of [
    ["Cisco IOS XR Software, Version 7.9", "cisco-ios-xr"],
    ["Cisco Adaptive Security Appliance Software Version 9.1", "cisco-asa"],
    ["Cisco Firepower Threat Defense Version 7.1", "cisco-ftd"],
  ])
    assert.equal(detectCiscoPlatform(text).platform, key);
  assert.ok(
    !redactCiscoOutput(
      "username a privilege 15 secret 9 never-secret\nsnmp-server user admin v3 auth sha never-auth priv aes 128 never-priv\nkey = never-aaa",
    ).includes("never-"),
  );
  fixture.mode("normal");
  fixture.setPassword("read");
  report = await collectCiscoInventory(target, { ...credentials, password: "read" });
  assert.equal(report.collection.capabilityProfile.groups.System, "read_only");
  await assert.rejects(collectCiscoInventory(target, { ...credentials, password: "incorrect" }));
  console.log(
    "PASS Cisco readonly SSH: actual OpenSSH/interactive PTY, colored prompts and paging, IOS-XE/Classic detection, NX-OS/ASA/XR/FTD guards, inventory/resources/interfaces/counters, privilege/unsupported failures and secret redaction",
  );
} finally {
  await fixture.close();
}
