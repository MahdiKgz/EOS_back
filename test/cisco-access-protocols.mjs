import ssh2 from "ssh2";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { ciscoSshFixture } from "./fixtures/cisco-ssh-server.mjs";
const require = createRequire(import.meta.url),
  { collectCiscoInventory } = require("../dist/modules/devices/cisco-collector.js"),
  { runSshCommand } = require("../dist/modules/devices/ssh-transport.js"),
  { legacyCiscoAlgorithms } = require("../dist/modules/devices/cisco-access-error.js"),
  { runLinuxSsh } = require("../dist/modules/devices/linux-ssh.js"),
  {
    sealSshCredentials,
    unsealSshCredentials,
    sealCiscoEnable,
    unsealCiscoEnable,
  } = require("../dist/modules/devices/ssh-credential-vault.js");
process.env.DEVICE_CREDENTIAL_KEY = "c".repeat(64);
for (const legacy of [false, true]) {
  const enablePassword = "separate-enable-secret";
  const fixture = await ciscoSshFixture({
    userExec: true,
    legacy,
    enablePassword,
    echoEnable: true,
  });
  try {
    const target = {
      id: "owned-fixture",
      type: "cisco",
      protocol: "ssh",
      host: fixture.host,
      managementPort: fixture.port,
    };
    const base = {
      username: fixture.username,
      password: fixture.password,
      hostKey: fixture.hostKey,
    };
    if (legacy)
      await assert.rejects(
        collectCiscoInventory(target, base),
        (error) => error.code === "CISCO_NEGOTIATION_FAILED" && !error.stderr && !error.stdout,
      );
    const credentials = { ...base, cisco: { profile: legacy ? "legacy_cisco" : "modern" } };
    await assert.rejects(
      collectCiscoInventory(target, credentials),
      (error) => error.code === "CISCO_ENABLE_REQUIRED",
    );
    await assert.rejects(
      collectCiscoInventory(target, {
        ...credentials,
        cisco: { ...credentials.cisco, enableSecret: "wrong" },
      }),
      (error) => error.code === "CISCO_ENABLE_FAILED",
    );
    credentials.cisco.enableSecret = enablePassword;
    const report = await collectCiscoInventory(target, credentials);
    assert.equal(report.detection.platform, "cisco-ios-xe");
    assert.ok(!JSON.stringify(report).includes(enablePassword));
    assert.ok(!JSON.stringify(report).includes(fixture.password));
    assert.ok(fixture.calls.includes("enable"));
    assert.ok(!fixture.calls.includes(enablePassword));
    const identity = await runLinuxSsh(target, { ...credentials, operation: "verify" });
    assert.equal(identity.identity.Manufacturer, "Cisco");
    assert.ok(!JSON.stringify(identity).includes(enablePassword));
    const keyReport = await collectCiscoInventory(target, {
      username: fixture.username,
      privateKey: fixture.privateKey,
      hostKey: fixture.hostKey,
      cisco: credentials.cisco,
    });
    assert.equal(keyReport.detection.supported, true);
    const context = {
        id: "device",
        workspaceOwnerId: "owner",
        host: "fixture",
        managementPort: 22,
      },
      key = Buffer.from(process.env.DEVICE_CREDENTIAL_KEY, "hex");
    await assert.rejects(
      runSshCommand(target, credentials, "show version", { interactive: true, maxBuffer: 32 }),
      (error) => error.code === "CISCO_OUTPUT_LIMIT" && !error.stdout && !error.stderr,
    );
    if (legacy) {
      await assert.rejects(
        runSshCommand({ ...target, type: "linux_edge" }, credentials, "uname -s"),
      );
      const client = new ssh2.Client();
      await new Promise((resolve, reject) => {
        client
          .once("error", reject)
          .once("ready", () =>
            client.shell((error, stream) => {
              if (error) return reject(error);
              let output = "",
                exiting = false;
              stream.on("data", (chunk) => {
                output += chunk.toString();
                if (output.includes("Switch>") && !exiting) {
                  exiting = true;
                  stream.end("exit\n");
                }
              });
              stream.once("close", () => {
                client.end();
                try {
                  assert.ok(output.includes("Switch>"));
                  assert.ok(!output.includes(enablePassword));
                  resolve();
                } catch (error) {
                  reject(error);
                }
              });
            }),
          )
          .connect({
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            password: fixture.password,
            algorithms: legacyCiscoAlgorithms,
            hostVerifier: (raw) => raw.equals(Buffer.from(fixture.hostKey.split(" ")[1], "base64")),
            readyTimeout: 5000,
          });
      });
    }
    const sealed = sealSshCredentials(context, credentials, key);
    assert.ok(!JSON.stringify(unsealSshCredentials(context, sealed, key)).includes(enablePassword));
    const separate = sealCiscoEnable("owner", "secret", enablePassword);
    assert.equal(unsealCiscoEnable("owner", "secret", separate), enablePassword);
    assert.throws(() => unsealCiscoEnable("other", "secret", separate));
    assert.throws(() => unsealSshCredentials(context, separate, key));
  } finally {
    await fixture.close();
  }
}
console.log(
  "Cisco access: real OpenSSH standard/explicit legacy, separate enable password/key auth, missing/wrong secret, private vault separation passed.",
);
