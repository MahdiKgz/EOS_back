import snmp from "net-snmp";
import { createSocket } from "node:dgram";
import { once } from "node:events";
export async function monitoringSnmpAgent() {
  const socket = createSocket("udp4");
  socket.bind(0, "127.0.0.1");
  await once(socket, "listening");
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  const agent = snmp.createAgent(
      { address: "127.0.0.1", port, accessControlModelType: snmp.AccessControlModelType.Simple },
      () => {},
    ),
    mib = agent.getMib();
  const secret = {
    username: "monitor_fixture",
    authProtocol: "SHA256",
    authPassword: "fixture-auth-2026",
    privacyPassword: "fixture-privacy-2026",
  };
  agent.getAuthorizer().addUser({
    name: secret.username,
    level: snmp.SecurityLevel.authPriv,
    authProtocol: snmp.AuthProtocols.sha256,
    authKey: secret.authPassword,
    privProtocol: snmp.PrivProtocols.aes,
    privKey: secret.privacyPassword,
  });
  for (const [name, oid, type, value] of [
    ["sysName", "1.3.6.1.2.1.1.5", snmp.ObjectType.OctetString, "monitor-switch"],
    ["sysUpTime", "1.3.6.1.2.1.1.3", snmp.ObjectType.TimeTicks, 120000],
    ["ifNumber", "1.3.6.1.2.1.2.1", snmp.ObjectType.Integer, 2],
  ]) {
    mib.registerProvider({
      name,
      oid,
      type: snmp.MibProviderType.Scalar,
      scalarType: type,
      maxAccess: snmp.MaxAccess["read-only"],
      handler: (req) => req.done(),
    });
    mib.setScalarValue(name, value);
  }
  const table = (name, oid, columns, rows, foreign) => {
    mib.registerProvider({
      name,
      oid,
      type: snmp.MibProviderType.Table,
      maxAccess: snmp.MaxAccess["not-accessible"],
      tableColumns: columns.map(([number, name, type]) => ({
        number,
        name,
        type,
        maxAccess: snmp.MaxAccess["read-only"],
      })),
      tableIndex: foreign ? [{ foreign, columnName: "ifIndex" }] : [{ columnName: columns[0][1] }],
      handler: (req) => req.done(),
    });
    for (const row of rows) mib.addTableRow(name, row);
  };
  table(
    "cpu",
    "1.3.6.1.2.1.25.3.3.1",
    [
      [1, "cpuIndex", snmp.ObjectType.Integer],
      [2, "cpuLoad", snmp.ObjectType.Integer],
    ],
    [
      [1, 20],
      [2, 40],
    ],
  );
  table(
    "storage",
    "1.3.6.1.2.1.25.2.3.1",
    [
      [1, "storageIndex", snmp.ObjectType.Integer],
      [2, "storageType", snmp.ObjectType.OID],
      [3, "storageDescription", snmp.ObjectType.OctetString],
      [4, "storageAllocation", snmp.ObjectType.Integer],
      [5, "storageSize", snmp.ObjectType.Integer],
      [6, "storageUsed", snmp.ObjectType.Integer],
    ],
    [
      [1, "1.3.6.1.2.1.25.2.1.2", "RAM", 1024, 100000, 25000],
      [2, "1.3.6.1.2.1.25.2.1.4", "disk", 4096, 100000, 50000],
    ],
  );
  const counter = (value) => {
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64BE(BigInt(value));
    return buffer;
  };
  table("ifEntry", "1.3.6.1.2.1.2.2.1", [[1, "ifIndex", snmp.ObjectType.Integer]], [[1]]);
  table(
    "ifX",
    "1.3.6.1.2.1.31.1.1.1",
    [
      [1, "ifName", snmp.ObjectType.OctetString],
      [6, "ifHCInOctets", snmp.ObjectType.Counter64],
      [10, "ifHCOutOctets", snmp.ObjectType.Counter64],
    ],
    [[1, "ether1", counter(123456789), counter(234567890)]],
    "ifEntry",
  );
  return { host: "127.0.0.1", port, secret, close: () => agent.close() };
}
