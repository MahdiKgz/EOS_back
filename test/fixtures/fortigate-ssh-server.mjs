import { createHash, generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import ssh2 from "ssh2";
const config = (scope, entries) =>
  `config ${scope}\n${entries.map(([name, settings]) => `    edit "${name}"\n${settings.map(([key, value]) => `        set ${key} ${value}`).join("\n")}\n    next`).join("\n")}\nend`;
export async function fortigateSshFixture({
  password = "forti-fixture-2026",
  control = false,
} = {}) {
  const makeKey = () =>
    generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
    }).privateKey;
  const serverKey = makeKey(),
    parsed = ssh2.utils.parseKey(serverKey),
    privateKey = makeKey(),
    clientKey = ssh2.utils.parseKey(privateKey);
  const secret = "NEVER_FORTI_SECRET";
  const outputs = {
    "get system status":
      "Version: FortiGate-101F v7.4.4,build2662,240514 (GA.M)\nHostname: fgt-fixture\nSerial-Number: FGT101FFIXTURE\nOperation Mode: NAT\nCurrent HA mode: standalone\nVirtual domain configuration: enable\nCurrent virtual domain: root\nLicense Status: Invalid\nSystem time: Sat Nov 7 12:00:00 2026",
    "get system performance status":
      "CPU states: 3% user 5% system 92% idle 0% iowait\nMemory: 1000000k total, 400000k used (40.0%), 600000k free (60.0%)\nAverage sessions: 42 sessions in 1 minute\nUptime: 2 days, 3 hours, 4 minutes",
    "diagnose sys top-summary": "CPU 8%\nfixture processes",
    "show system interface": config("system interface", [
      [
        "wan1",
        [
          ["ip", "203.0.113.2 255.255.255.0"],
          ["vdom", '"root"'],
          ["role", "wan"],
          ["allowaccess", "ping https ssh"],
          ["status", "up"],
        ],
      ],
      [
        "lan",
        [
          ["ip", "192.0.2.1 255.255.255.0"],
          ["status", "down"],
          ["alias", '"office network"'],
        ],
      ],
    ]),
    "get system interface physical":
      "== [wan1]\nstatus: up\nspeed: 1000Mbps\nduplex: full\n== [lan]\nstatus: down",
    "diagnose netlink interface list":
      "if=wan1 family=00 type=1 index=2\nstat: rxb=1000000 txb=2000000 rxp=3 txp=4\nif=lan family=00 type=1 index=3\nstat: rxb=4000000 txb=8000000\nif=incomplete family=00\nstat: txb=12",
    "get router info routing-table all":
      "S* 0.0.0.0/0 [10/0] via 203.0.113.1, wan1\nC 192.0.2.0/24 is directly connected, lan",
    "get system dns": "primary: 192.0.2.53\nsecondary: 192.0.2.54",
    "show system dns": "config system dns\nset primary 192.0.2.53\nend",
    "show system fortiguard": `config system fortiguard\n set password ENC ${secret}\n set update-server-location usa\nend`,
    "show system admin": `config system admin\n edit "operator"\n set accprofile "super_admin"\n set password ENC ${secret}\n set trusthost1 192.0.2.0 255.255.255.0\n config gui-dashboard\n edit 1\n set name "nested dashboard"\n next\n end\n next\nend`,
    "show system zone": config("system zone", [["internal", [["interface", '"lan"']]]]),
    "show firewall policy": config("firewall policy", [
      [
        "1",
        [
          ["name", '"office internet"'],
          ["srcintf", '"lan"'],
          ["dstintf", '"wan1"'],
          ["srcaddr", '"all"'],
          ["dstaddr", '"all"'],
          ["service", '"HTTPS"'],
          ["action", "accept"],
          ["nat", "enable"],
          ["logtraffic", "all"],
        ],
      ],
    ]),
    "show firewall address": config("firewall address", [
      ["office", [["subnet", "192.0.2.0 255.255.255.0"]]],
    ]),
    "show firewall addrgrp": config("firewall addrgrp", [["employees", [["member", '"office"']]]]),
    "show firewall service custom": config("firewall service custom", [
      ["HTTPS", [["tcp-portrange", "443"]]],
    ]),
    "show firewall service group": config("firewall service group", [
      ["web", [["member", '"HTTPS"']]],
    ]),
    "show firewall schedule recurring": config("firewall schedule recurring", [
      [
        "working",
        [
          ["day", "monday tuesday"],
          ["start", "08:00"],
          ["end", "17:00"],
        ],
      ],
    ]),
    "show router static": config("router static", [
      [
        "7",
        [
          ["dst", "198.51.100.0 255.255.255.0"],
          ["gateway", "192.0.2.254"],
          ["device", '"lan"'],
        ],
      ],
    ]),
    "show firewall central-snat-map": config("firewall central-snat-map", [
      [
        "8",
        [
          ["srcintf", '"lan"'],
          ["dstintf", '"wan1"'],
          ["orig-addr", '"all"'],
          ["dst-addr", '"all"'],
          ["nat", "enable"],
        ],
      ],
    ]),
    "show firewall vipgrp": config("firewall vipgrp", [
      [
        "public-services",
        [
          ["interface", "any"],
          ["member", '"web-vip"'],
        ],
      ],
    ]),
    "show firewall vip": config("firewall vip", [
      [
        "web-vip",
        [
          ["extip", "203.0.113.10"],
          ["mappedip", '"192.0.2.10"'],
        ],
      ],
    ]),
    "show firewall ippool": config("firewall ippool", [
      [
        "office-nat",
        [
          ["startip", "203.0.113.20"],
          ["endip", "203.0.113.25"],
        ],
      ],
    ]),
    "get vpn ipsec tunnel summary":
      "'vpn-a[1]' 203.0.113.5:0 selectors(total,up): 2/1 rx(pkt,err): 10/0",
    "diagnose vpn tunnel list": "name=vpn-a[1] ver=2 status=up\npsksecret ENC " + secret,
    "get vpn ssl monitor": "Users: 2",
    "show vpn ipsec phase1-interface": config("vpn ipsec phase1-interface", [
      [
        "vpn-a[1]",
        [
          ["interface", '"wan1"'],
          ["psksecret", `ENC ${secret}`],
        ],
      ],
    ]),
    "show vpn ipsec phase2-interface": config("vpn ipsec phase2-interface", [
      ["office-remote", [["phase1name", '"vpn-a[1]"']]],
    ]),
    "show vpn ssl settings": `config vpn ssl settings\nset status enable\nset servercert "Fortinet_Factory"\nset private-key "-----BEGIN PRIVATE KEY-----\n${secret}\n-----END PRIVATE KEY-----"\nend`,
    "show system sdwan":
      "config system sdwan\nset status disable\nconfig zone\nedit virtual-wan-link\nset service-sla-tie-break cfg-order\nnext\nend\nend",
    "get system ha status": "HA Health Status: OK\nMode: HA A-P\nConfiguration Status: in-sync",
    "show system ha": "config system ha\nset mode a-p\nset group-name " + '"fixture-cluster"\nend',
    "show system vdom-property": "config system vdom-property\nend",
    "show system vdom": config("system vdom", [["root", []]]),
    "get system arp": "Address Age Hardware Addr Interface\n192.0.2.2 0 02:00:00:00:00:01 lan",
    "diagnose ip arp list":
      "index=2 ifname=lan 192.0.2.2 02:00:00:00:00:01 state=00000002 use=1 confirm=1 update=1 ref=1",
    "diagnose user device list": "host fixture ip=192.0.2.2 interface=lan",
  };
  const interfaceRows = {
    wan1: { ip: "203.0.113.2 255.255.255.0", alias: "WAN", role: "wan", status: "up" },
    lan: { ip: "192.0.2.1 255.255.255.0", alias: "Office", role: "lan", status: "up" },
  };
  const controlSystem = {
    "system ha": {
      mode: "standalone",
      "group-name": "fixture-cluster",
      priority: "128",
      hbdev: "ha1 50 ha2 100",
      password: "ENC fixture-ha-secret",
    },
    "system global": {
      "edit-vdom-prompt": "enable",
      "management-vdom": "root",
      "admin-sport": "443",
      "admin-telnet": "enable",
      "admin-ssh-v1": "enable",
      "admin-ssh-password": "enable",
      "admin-scp": "enable",
    },
    "system settings": { "central-nat": "disable", "ngfw-mode": "profile-based" },
    "system dns": { primary: "192.0.2.53", secondary: "192.0.2.54", protocol: "dot" },
    "system ntp": { ntpsync: "disable", type: "fortiguard", syncinterval: "60" },
  };
  const sdwan = {
    status: "disable",
    sections: {
      zone: { "virtual-wan-link": { "service-sla-tie-break": "cfg-order" } },
      members: { 1: { interface: "wan1", zone: "virtual-wan-link", status: "enable" } },
      "health-check": {},
      service: {},
    },
  };
  let sdwanId = 300;
  const sdwanConfig = () =>
    "config system sdwan\nset status " +
    sdwan.status +
    "\n" +
    Object.entries(sdwan.sections)
      .map(
        ([section, rows]) =>
          "config " +
          section +
          "\n" +
          Object.entries(rows)
            .map(
              ([id, fields]) =>
                "edit " +
                JSON.stringify(id) +
                "\n" +
                Object.entries(fields)
                  .map(
                    ([key, value]) =>
                      "set " +
                      key +
                      " " +
                      (["members", "priority-members", "src", "dst"].includes(key)
                        ? value.split(" ").map(JSON.stringify).join(" ")
                        : JSON.stringify(value)),
                  )
                  .join("\n") +
                "\nnext",
            )
            .join("\n") +
          "\nend",
      )
      .join("\n") +
    "\nend";
  const ntpServers = { 1: { server: "old.ntp.local" }, 2: { server: "keep.ntp.local" } };
  const controlScopes = [];
  let committedSinceMode = false,
    nextRouteId = 500,
    nextSnatId = 800;
  const policyOrder = ["10", "20"];
  let nextPolicyId = 1000;
  const controlTables = {
    "system admin": {
      operator: {
        accprofile: "super_admin",
        vdom: "root",
        password: "ENC fixture-hash",
        trusthost1: "192.0.2.0 255.255.255.0",
      },
    },
    "system api-user": {},
    "system accprofile": { limited: { secfabgrp: "read" } },
    "system vdom": { root: {}, tenant: {} },
    "system vdom-property": {},
    "router static": {},
    "firewall central-snat-map": {},
    "firewall policy": {
      10: { name: "baseline", status: "enable", comments: "existing operator policy" },
      20: { name: "last-rule", status: "disable", comments: "firewall-log-analyzer existing" },
    },
    "firewall vip": {},
    "firewall vipgrp": {},
    "firewall ippool": {},
    "system interface": interfaceRows,
    "firewall address": { office: { type: "ipmask", subnet: "192.0.2.0 255.255.255.0" } },
    "firewall addrgrp": { employees: { member: "office" } },
    "firewall service custom": {
      "custom-http": { protocol: "TCP/UDP/SCTP", "tcp-portrange": "80", comment: "legacy" },
    },
    "firewall service group": { web: { member: "HTTPS" } },
    "firewall schedule recurring": {},
    "system zone": { legacy: { interface: "lan", intrazone: "deny" } },
  };
  const controlWrites = [];
  const logSessions = [];
  const vdomConfirmations = [];
  const vdomQuestion =
    "The input VDOM name doesn't exist.\r\nDo you want to create a new VDOM?\r\nPlease press 'y' to continue, or press 'n' to cancel. (y/n)";
  const calls = [],
    clients = new Set(),
    waiting = [];
  let mode = "normal",
    paused,
    observed;
  const server = new ssh2.Server({ hostKeys: [serverKey] }, (client) => {
    clients.add(client);
    client.on("error", () => {}).once("close", () => clients.delete(client));
    client.on("authentication", (ctx) => {
      if (ctx.username !== "fixture") return ctx.reject();
      if (ctx.method === "password" && ctx.password === password) return ctx.accept();
      if (
        ctx.method === "publickey" &&
        ctx.key.data.equals(clientKey.getPublicSSH()) &&
        (!ctx.signature || clientKey.verify(ctx.blob, ctx.signature, ctx.hashAlgo))
      )
        return ctx.accept();
      ctx.reject();
    });
    client.on("ready", () =>
      client.on("session", (accept) => {
        const session = accept();
        session.on("pty", (accept) => accept());
        session.on("shell", (accept) => {
          const stream = accept();
          let pending = "",
            more,
            editingSystem,
            pendingSystem,
            editingNtp = false,
            ntpEditId,
            pendingNtpRow,
            reset = false,
            logLimit = 0;
          let editingContext,
            editName,
            pendingRow,
            sdwanEditing = false,
            sdwanPart,
            sdwanTarget,
            sdwanPending,
            vdomEditing = false,
            awaitingVdom;
          const sessionCalls = [];
          logSessions.push(sessionCalls);
          const prompt = "FGT (root) # ";
          stream.write("Welcome\r\n\x1b[32m" + prompt + "\x1b[0m");
          stream.on("data", (chunk) => {
            const input = chunk.toString();
            if (more && input === " ") {
              const resume = more;
              more = undefined;
              resume();
              return;
            }
            pending += input;
            while (pending.includes("\n")) {
              const end = pending.indexOf("\n"),
                command = pending.slice(0, end).trim();
              pending = pending.slice(end + 1);
              if (command === "exit") {
                stream.exit(0);
                stream.end();
                return;
              }
              calls.push(command);
              sessionCalls.push(command);
              const respond = () => {
                let output = outputs[command] ?? "Command fail. Return code -61";
                if (control) {
                  if (
                    command.startsWith("config ") &&
                    !["config global", "config vdom"].includes(command)
                  )
                    vdomEditing = false;
                  if (command === "config system sdwan") {
                    editingContext = undefined;
                    pendingRow = undefined;
                  }
                  if (command === "config global" || command === "config vdom") {
                    output = "";
                    controlScopes.push(command);
                    if (command === "config vdom") vdomEditing = true;
                  }
                  if (command.startsWith("config ") && controlSystem[command.slice(7)]) {
                    editingSystem = command.slice(7);
                    pendingSystem = { ...controlSystem[editingSystem] };
                    output = "";
                    controlWrites.push(command);
                  }
                  if (command === "config ntpserver" && editingSystem === "system ntp") {
                    editingNtp = true;
                    output = "";
                    controlWrites.push(command);
                  }
                  if (command.startsWith("edit ") && editingNtp) {
                    ntpEditId = String(JSON.parse(command.slice(5)));
                    pendingNtpRow = { ...(ntpServers[ntpEditId] ?? {}) };
                    output = "";
                    controlWrites.push(command);
                  }
                  if (command.startsWith("set ") && editingSystem) {
                    const [, key, rest] = command.match(/^set (\S+) (.*)$/) ?? [];
                    if (key) {
                      const values = (rest.match(/"(?:\\.|[^"\\])*"|\S+/g) ?? []).map((v) =>
                        v.startsWith('"') ? JSON.parse(v) : v,
                      );
                      if (editingNtp && pendingNtpRow) pendingNtpRow[key] = values.join(" ");
                      else pendingSystem[key] = values.join(" ");
                      output = mode === "control-failure" ? "Command fail. Return code -61" : "";
                      controlWrites.push(command);
                    }
                  }
                  if (command === "next" && editingNtp && pendingNtpRow) {
                    if (mode !== "control-mismatch") {
                      ntpServers[ntpEditId] = pendingNtpRow;
                      committedSinceMode = true;
                    }
                    pendingNtpRow = undefined;
                    output = "";
                    controlWrites.push(command);
                  }
                  if (command === "end" && editingSystem) {
                    if (editingNtp) editingNtp = false;
                    else {
                      if (mode !== "control-mismatch") {
                        controlSystem[editingSystem] = pendingSystem;
                        committedSinceMode = true;
                      }
                      editingSystem = undefined;
                      pendingSystem = undefined;
                    }
                  }
                  if (command === 'edit "root"' && !editingContext) output = "";
                  if (command === "config vdom") {
                    editingContext = "system vdom";
                    output = "";
                  }
                  if (command.startsWith("config ") && controlTables[command.slice(7)]) {
                    editingContext = command.slice(7);
                    output = "";
                    controlWrites.push(command);
                  }
                  if (command.startsWith("edit ") && editingContext) {
                    editName = String(JSON.parse(command.slice(5)));
                    if (editingContext === "firewall policy" && editName === "0")
                      editName = String(nextPolicyId++);
                    if (editingContext === "router static" && editName === "0")
                      editName = String(nextRouteId++);
                    if (editingContext === "firewall central-snat-map" && editName === "0")
                      editName = String(nextSnatId++);
                    pendingRow = { ...(controlTables[editingContext][editName] ?? {}) };
                    output = "";
                    if (!(
                      vdomEditing &&
                      editingContext === "system vdom" &&
                      controlTables["system vdom"][editName]
                    ))
                      controlWrites.push(command);
                  }
                  if (command.startsWith("set ") && editingContext && pendingRow) {
                    const match = command.match(/^set (\S+) (.*)$/);
                    if (match) {
                      const values = (match[2].match(/"(?:\\.|[^"\\])*"|\S+/g) ?? []).map(
                        (token) => (token.startsWith('"') ? JSON.parse(token) : token),
                      );
                      pendingRow[match[1]] =
                        match[1] === "password"
                          ? "ENC " + createHash("sha256").update(values.join(" ")).digest("hex")
                          : values.join(" ");
                      output =
                        mode === "control-failure" ||
                        (mode === "control-policy-failure" && editingContext === "firewall policy")
                          ? "Command fail. Return code -61"
                          : "";
                      if (
                        editingContext === "system interface" &&
                        match[1] === "vdom" &&
                        (Object.values(controlTables["system zone"]).some((r) =>
                          (r.interface ?? "").split(" ").includes(editName),
                        ) ||
                          mode === "vdom-move-used")
                      )
                        output = "Command fail. Return code -23";
                      if (
                        editingContext === "system vdom-property" &&
                        mode === "vdom-property-failure"
                      )
                        output = "Command fail. Return code -61";
                      controlWrites.push(command);
                    }
                  }
                  if (command.startsWith("unset ") && editingContext && pendingRow) {
                    delete pendingRow[command.slice(6)];
                    output = "";
                    controlWrites.push(command);
                  }
                  if (command.startsWith("delete ") && editingContext) {
                    const name = String(JSON.parse(command.slice(7)));
                    if (
                      mode === "control-dependency" ||
                      (editingContext === "system vdom" &&
                        (Object.entries(interfaceRows).some(
                          ([key, r]) =>
                            r.vdom === name &&
                            !["ssl.", "l2t.", "naf."].some((prefix) => key === prefix + name),
                        ) ||
                          Object.values(controlTables["system admin"]).some((r) =>
                            (r.vdom ?? "").split(" ").includes(name),
                          )))
                    )
                      output = "Command fail. Return code -23";
                    else {
                      if (mode !== "control-mismatch") {
                        delete controlTables[editingContext][name];
                        if (editingContext === "system vdom") {
                          delete controlTables["system vdom-property"][name];
                          for (const [key, r] of Object.entries(interfaceRows))
                            if (
                              r.vdom === name &&
                              ["ssl.", "l2t.", "naf."].some((prefix) => key === prefix + name)
                            )
                              delete interfaceRows[key];
                        }
                        if (editingContext === "firewall policy") {
                          const offset = policyOrder.indexOf(name);
                          if (offset >= 0) policyOrder.splice(offset, 1);
                        }
                      }
                      output = "";
                    }
                    controlWrites.push(command);
                  }
                  if (command === "next" && editingContext && pendingRow) {
                    if (mode !== "control-mismatch") {
                      controlTables[editingContext][editName] = pendingRow;
                      committedSinceMode = true;
                      if (editingContext === "firewall policy" && !policyOrder.includes(editName))
                        policyOrder.push(editName);
                    }
                    pendingRow = undefined;
                    output = "";
                    controlWrites.push(command);
                    if (mode === "control-disconnect") {
                      stream.end();
                      return;
                    }
                  }
                  if (command.startsWith("move ") && editingContext === "firewall policy") {
                    const [, source, direction, destination] = command.split(" ");
                    const sourceOffset = policyOrder.indexOf(source);
                    if (sourceOffset < 0 || !policyOrder.includes(destination))
                      output = "Command fail. Return code -61";
                    else if (mode !== "control-mismatch") {
                      policyOrder.splice(sourceOffset, 1);
                      policyOrder.splice(
                        policyOrder.indexOf(destination) + (direction === "after" ? 1 : 0),
                        0,
                        source,
                      );
                      output = "";
                    } else output = "";
                    controlWrites.push(command);
                  }
                  if (command === "end") {
                    editingContext = undefined;
                    output = "";
                  }
                  if (
                    command.startsWith("show full-configuration ") &&
                    controlTables[command.slice(24)]
                  ) {
                    const context = command.slice(24);
                    output = config(
                      context,
                      (context === "firewall policy"
                        ? policyOrder.map((name) => [name, controlTables[context][name]])
                        : Object.entries(controlTables[context])
                      ).map(([name, fields]) => [
                        name,
                        Object.entries(fields).map(([key, value]) => [
                          key,
                          [
                            "member",
                            "interface",
                            "srcintf",
                            "dstintf",
                            "srcaddr",
                            "dstaddr",
                            "service",
                          ].includes(key)
                            ? value.split(" ").filter(Boolean).map(JSON.stringify).join(" ")
                            : [
                                  "alias",
                                  "comment",
                                  "comments",
                                  "name",
                                  "schedule",
                                  "description",
                                  "fqdn",
                                  "country",
                                ].includes(key)
                              ? JSON.stringify(value)
                              : value,
                        ]),
                      ]),
                    );
                  }
                }

                if (control) {
                  if (command === "config system sdwan") {
                    sdwanEditing = true;
                    output = "";
                    controlWrites.push(command);
                  } else if (
                    sdwanEditing &&
                    command.startsWith("config ") &&
                    sdwan.sections[command.slice(7)]
                  ) {
                    sdwanPart = command.slice(7);
                    output = "";
                    controlWrites.push(command);
                  } else if (sdwanEditing && sdwanPart && command.startsWith("edit ")) {
                    sdwanTarget = String(JSON.parse(command.slice(5)));
                    if (sdwanTarget === "0") sdwanTarget = String(sdwanId++);
                    sdwanPending = { ...sdwan.sections[sdwanPart][sdwanTarget] };
                    output = "";
                    controlWrites.push(command);
                  } else if (
                    sdwanEditing &&
                    sdwanPart &&
                    sdwanPending &&
                    command.startsWith("set ")
                  ) {
                    const [, key, rest] = command.match(/^set (\S+) (.*)$/) ?? [];
                    const values = (rest.match(/"(?:\\.|[^"\\])*"|\S+/g) ?? []).map((v) =>
                      v.startsWith('"') ? JSON.parse(v) : v,
                    );
                    sdwanPending[key] = values.join(" ");
                    output = mode === "control-failure" ? "Command fail. Return code -61" : "";
                    controlWrites.push(command);
                  } else if (sdwanEditing && command === "next" && sdwanPending) {
                    if (mode !== "control-mismatch") {
                      sdwan.sections[sdwanPart][sdwanTarget] = sdwanPending;
                      committedSinceMode = true;
                    }
                    sdwanPending = undefined;
                    output = "";
                    controlWrites.push(command);
                    if (mode === "control-disconnect") {
                      stream.destroy();
                      return;
                    }
                  } else if (sdwanEditing && command === "end") {
                    if (sdwanPart) sdwanPart = undefined;
                    else sdwanEditing = false;
                    output = "";
                    controlWrites.push(command);
                  }
                  if (
                    command === "show full-configuration system sdwan" ||
                    command === "show system sdwan"
                  )
                    output = sdwanConfig();
                  if (command === "get system ha status")
                    output =
                      "HA Health Status: OK\nMode: " +
                      (controlSystem["system ha"].mode === "standalone"
                        ? "Standalone"
                        : "HA " + controlSystem["system ha"].mode.toUpperCase()) +
                      "\nConfiguration Status: in-sync";
                }
                if (
                  control &&
                  command === "get system ha status" &&
                  (mode === "ha-status-partial" ||
                    (mode === "ha-status-after-write" && committedSinceMode))
                )
                  output = "HA Health Status: unknown";
                if (
                  control &&
                  command === "show full-configuration system sdwan" &&
                  mode === "nested-missing-next"
                )
                  output = output.replace(/next\s*\n/, "");

                if (
                  control &&
                  command.startsWith("show full-configuration ") &&
                  controlSystem[command.slice(24)]
                ) {
                  const context = command.slice(24),
                    fields = controlSystem[context];
                  const nested =
                    context === "system ntp"
                      ? "\nconfig ntpserver\n" +
                        Object.entries(ntpServers)
                          .map(
                            ([id, fields]) =>
                              `edit ${id}\n${Object.entries(fields)
                                .map(([key, value]) => `set ${key} ${JSON.stringify(value)}`)
                                .join("\n")}\nnext`,
                          )
                          .join("\n") +
                        "\nend"
                      : "";
                  output = `config ${context}\n${Object.entries(fields)
                    .map(([key, value]) => `set ${key} ${JSON.stringify(value)}`)
                    .join("\n")}${nested}\nend`;
                }
                if (control && command.startsWith("show full-configuration ")) {
                  if (mode === "control-read-failure")
                    output = "Permission denied. Command fail. Return code -37";
                  if (mode === "control-incomplete-readback" && committedSinceMode)
                    output = output.replace(/end\s*$/, "");
                }

                if (command === "execute log filter reset") {
                  reset = true;
                  logLimit = 0;
                  output =
                    mode === "log-failure"
                      ? "Permission denied. Command fail. Return code -37"
                      : "";
                }
                if (command === "execute log filter view-lines 500") {
                  logLimit = 500;
                  output = reset ? "" : "Command fail. Return code -1";
                }
                if (command === "execute log display")
                  output =
                    !reset || logLimit !== 500
                      ? "Command fail. Return code -1"
                      : mode === "empty-logs"
                        ? "0 logs found."
                        : mode === "large-logs"
                          ? Array.from(
                              { length: 520 },
                              (_, i) =>
                                `date=2026-11-07 time=12:00:00 logid="${i}" type=event subtype=system level=notice vd=root msg="fixture event ${i}"`,
                            ).join("\n") + "\n520 logs found."
                          : `1: date=2026-11-07 time=12:00:00 eventtime=1794052800000000000 tz="+0330" logid="0100032002" type="event" subtype="system" level="information" vd="root" logdesc="Admin login" user="operator" srcip=192.0.2.2 msg="Admin logged in"\n2: date=2026-11-07 time=12:00:01 logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" action="accept" srcip=192.0.2.3 msg="session allowed" password=${secret}\n2 logs found.`;

                if (mode === "unsupported" && command === "get system status")
                  output = "Version: Linux 6.8";
                if (mode === "partial" && command === "show system admin")
                  output = "Permission denied. Command fail. Return code -37";
                if (mode === "partial" && command === "diagnose sys top-summary")
                  output =
                    "command parse error before 'top-summary'. Command fail. Return code -61";
                if (mode === "large" && command === "show firewall address")
                  output = config(
                    "firewall address",
                    Array.from({ length: 300 }, (_, i) => [
                      "address-" + i,
                      [["subnet", "192.0.2.0 255.255.255.0"]],
                    ]),
                  );
                if (control && command === "show system vdom")
                  output = config(
                    "system vdom",
                    Object.entries(controlTables["system vdom"]).map(([key, fields]) => [
                      key,
                      Object.entries(fields).map(([k, v]) => [k, JSON.stringify(v)]),
                    ]),
                  );
                if (control && command === "show system vdom-property")
                  output = config(
                    "system vdom-property",
                    Object.entries(controlTables["system vdom-property"]).map(([key, fields]) => [
                      key,
                      Object.entries(fields).map(([k, v]) => [k, JSON.stringify(v)]),
                    ]),
                  );
                if (
                  control &&
                  vdomEditing &&
                  editingContext === "system vdom" &&
                  command.startsWith("edit ") &&
                  !controlTables["system vdom"][editName] &&
                  controlSystem["system global"]["edit-vdom-prompt"] === "enable"
                ) {
                  awaitingVdom = editName;
                  const question =
                    mode === "vdom-wrong-question"
                      ? "Do you want to delete every VDOM? (y/n)"
                      : vdomQuestion;
                  const payload = command + "\r\n" + question;
                  stream.write(payload.slice(0, Math.floor(payload.length / 2)));
                  setTimeout(() => {
                    if (!stream.destroyed)
                      stream.write(payload.slice(Math.floor(payload.length / 2)));
                  }, 5);
                  return;
                }
                if (control && command === "y" && awaitingVdom) {
                  vdomConfirmations.push(awaitingVdom);
                  awaitingVdom = undefined;
                  output = "current vf=" + editName;
                  if (mode === "vdom-repeat-question") {
                    stream.write(vdomQuestion);
                    return;
                  }
                }
                if (command === "end") vdomEditing = false;
                stream.write(command + "\r\n");
                if (command === "show system interface") {
                  const split = output.indexOf('    edit "lan"');
                  stream.write(output.slice(0, split) + "\r\n--More--\b\b");
                  more = () => stream.write(output.slice(split) + "\r\n" + prompt);
                } else stream.write(output + "\r\n" + prompt);
              };
              if (paused === command) {
                waiting.push(respond);
                observed?.();
              } else respond();
            }
          });
        });
      }),
    );
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const release = () => {
    paused = undefined;
    for (const resume of waiting.splice(0)) resume();
  };
  return {
    host: "127.0.0.1",
    port: server.address().port,
    hostKey: parsed.type + " " + parsed.getPublicSSH().toString("base64"),
    username: "fixture",
    password,
    privateKey,
    calls,
    logSessions,
    vdomConfirmations,
    interfaceRows,
    policyOrder,
    controlSystem,
    ntpServers,
    sdwan,
    controlScopes,
    controlTables,
    controlWrites,
    outputs,
    mode(value) {
      mode = value;
      committedSinceMode = false;
    },
    pause(command) {
      paused = command;
      return new Promise((resolve) => (observed = resolve));
    },
    release,
    async close() {
      release();
      for (const client of clients) client.end();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
