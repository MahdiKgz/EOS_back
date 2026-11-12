import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { monitoringSnmpAgent } from "./fixtures/monitoring-snmp-agent.mjs";
const require = createRequire(import.meta.url),
  { collectSnmpMonitoring, snmpNumber } = require("../dist/modules/devices/monitoring-snmp.js");
const agent = await monitoringSnmpAgent();
try {
  const result = await collectSnmpMonitoring(agent.host, agent.port, agent.secret);
  const metric = (key) => result.measurements.find((m) => m.key === key)?.value;
  assert.equal(metric("cpu.usage_percent"), 30);
  assert.equal(metric("memory.usage_percent"), 25);
  assert.equal(metric("disk.usage_percent"), 50);
  assert.equal(metric("system.uptime_seconds"), 1200);
  assert.equal(metric("network.rx_bytes"), 123456789);
  assert.equal(metric("network.tx_bytes"), 234567890);
  assert.equal(result.measurements.find((m) => m.key === "network.rx_bytes").label, "ether1 #1");
  assert.deepEqual(result.warnings, []);
  assert.equal(snmpNumber(Buffer.from("ffffffffffffffff", "hex")), null);
  assert.equal(snmpNumber(-1), null);
  assert.equal(snmpNumber("123"), null);
  assert.equal(snmpNumber(9007199254740993n), null);
  await assert.rejects(
    collectSnmpMonitoring(agent.host, agent.port, {
      ...agent.secret,
      privacyPassword: "wrong-password",
    }),
  );
  console.log(
    "PASS monitoring SNMPv3 authPriv UDP: CPU/storage/interface counters, Counter64 bounds, invalid credentials",
  );
} finally {
  agent.close();
}
