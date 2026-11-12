import * as snmp from "net-snmp";
import { isIP } from "node:net";
export type SnmpSecret = {
  username: string;
  authProtocol: "SHA" | "SHA256";
  authPassword: string;
  privacyPassword: string;
};
const oids = ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.2.1.0"];
export async function pollSnmpv3(host: string, port: number, secret: SnmpSecret) {
  const session = snmp.createV3Session(
    host,
    {
      name: secret.username,
      level: snmp.SecurityLevel.authPriv,
      authProtocol:
        secret.authProtocol === "SHA256" ? snmp.AuthProtocols.sha256 : snmp.AuthProtocols.sha,
      authKey: secret.authPassword,
      privProtocol: snmp.PrivProtocols.aes,
      privKey: secret.privacyPassword,
    },
    { port, retries: 0, timeout: 3500, transport: isIP(host) === 6 ? "udp6" : "udp4" },
  );
  try {
    return await new Promise<{
      sysName: string;
      uptimeSeconds: number;
      interfaceCount: number | null;
    }>((resolve, reject) => {
      const deadline = setTimeout(() => reject(new Error("SNMP_TIMEOUT")), 5000);
      session.get(oids, (error, bindings) => {
        clearTimeout(deadline);
        if (error) {
          reject(
            new Error(
              String(error.name) === "RequestTimedOutError"
                ? "SNMP_TIMEOUT"
                : "SNMP_AUTH_OR_QUERY_FAILED",
            ),
          );
          return;
        }
        if (
          !bindings ||
          bindings.length !== 3 ||
          bindings.some((v, i) => v.oid !== oids[i]) ||
          bindings.slice(0, 2).some(snmp.isVarbindError)
        ) {
          reject(new Error("SNMP_INVALID_RESPONSE"));
          return;
        }
        const ticks = bindings[1].value;
        const count = bindings[2].value;
        if (
          bindings[0].type !== snmp.ObjectType.OctetString ||
          bindings[1].type !== snmp.ObjectType.TimeTicks ||
          typeof ticks !== "number" ||
          !Number.isFinite(ticks) ||
          ticks < 0
        ) {
          reject(new Error("SNMP_INVALID_RESPONSE"));
          return;
        }
        resolve({
          sysName: Array.from(String(bindings[0].value))
            .filter((char) => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127)
            .join("")
            .slice(0, 256),
          uptimeSeconds: ticks / 100,
          interfaceCount:
            !snmp.isVarbindError(bindings[2]) &&
            typeof count === "number" &&
            Number.isSafeInteger(count) &&
            count >= 0
              ? count
              : null,
        });
      });
    });
  } finally {
    session.close();
  }
}
