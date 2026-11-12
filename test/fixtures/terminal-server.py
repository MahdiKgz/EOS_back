"""Disposable loopback SSH PTY fixture. Recognizes fixed test strings; executes no OS commands."""
import json
import sys
import logging
import signal
import socket
import threading
import time
import paramiko
import shlex
import hashlib

logging.disable(logging.CRITICAL)
key = paramiko.RSAKey.generate(2048)
other = paramiko.RSAKey.generate(2048)
stopping = threading.Event()
transports = []


# Independent, bounded CLI peer: no compiler imports and no OS command execution.
next_policy_id = 7000
next_network_id = 9000
next_sdwan_id = 9500
sdwan_sections = {"zone": {"virtual-wan-link": {"service-sla-tie-break": ["cfg-order"]}}, "members": {"1": {"interface": ["wan1"], "zone": ["virtual-wan-link"], "status": ["enable"]}}, "health-check": {}, "service": {}}
sdwan_status = "disable"
forti_tables = {
    "system admin": {"operator": {"accprofile": ["super_admin"], "vdom": ["root"], "password": ["ENC", "fixture"]}},
    "system api-user": {}, "system accprofile": {"limited": {}}, "system vdom": {"root": {}, "tenant": {}}, "system vdom-property": {},
    "router static": {}, "firewall central-snat-map": {},
    "firewall policy": {"10": {"name": ["existing"], "status": ["enable"]}},
    "system interface": {"lan": {"alias": ["Original"], "role": ["lan"], "status": ["up"], "ip": ["192.0.2.1", "255.255.255.0"]}},
    "firewall vip": {}, "firewall vipgrp": {}, "firewall ippool": {},
    "firewall address": {}, "firewall addrgrp": {},
    "firewall service custom": {}, "firewall service group": {},
    "firewall schedule recurring": {}, "system zone": {},
}
forti_system = {
    "system ha": {"mode": ["standalone"], "group-name": ["wire-cluster"], "priority": ["128"], "hbdev": ["ha1", "50", "ha2", "100"]},
    "system global": {"edit-vdom-prompt": ["enable"], "management-vdom": ["root"], "admin-sport": ["443"], "admin-telnet": ["enable"], "admin-ssh-v1": ["enable"], "admin-ssh-password": ["enable"], "admin-scp": ["enable"]},
    "system settings": {"central-nat": ["disable"], "ngfw-mode": ["profile-based"]},
    "system dns": {"primary": ["192.0.2.53"], "secondary": ["192.0.2.54"], "protocol": ["dot"]},
    "system ntp": {"type": ["fortiguard"], "ntpsync": ["disable"], "syncinterval": ["60"]},
}
ntp_servers = {"1": {"server": ["old.ntp.local"]}, "2": {"server": ["keep.ntp.local"]}}
def forti_shell(channel):
    global next_policy_id, next_network_id, next_sdwan_id
    pending = b""
    context, target, scope = None, None, None
    strict_vdom = "--fortigate-vdom" in sys.argv
    confirmation_target = None
    if strict_vdom: forti_tables["system interface"].setdefault("port3", {"vdom": ["root"], "alias": ["Preserved"], "status": ["up"]})
    strict_cluster = "--fortigate-cluster" in sys.argv
    strict_admin = "--fortigate-admin" in sys.argv
    strict_network = "--fortigate-network" in sys.argv or strict_admin or strict_cluster or strict_vdom
    def settings_lines(fields):
        return ["set " + key + " " + " ".join(json.dumps(v, ensure_ascii=False) for v in values) for key, values in fields.items()]
    def allowed(table):
        if strict_vdom and table in ["system interface", "system vdom", "system vdom-property", "system global", "system admin"]: return scope == "global"
        return not strict_network or scope == ("global" if table in ["system dns", "system ntp", "system global", "system ha", "system admin", "system api-user", "system accprofile", "system vdom"] else "root")
    vdom_question = "The input VDOM name doesn't exist.\r\nDo you want to create a new VDOM?\r\nPlease press 'y' to continue, or press 'n' to cancel. (y/n)"
    try:
        channel.sendall(b"\x1b[32mFGT (root) # \x1b[0m")
        while not stopping.is_set():
            chunk = channel.recv(32768)
            if not chunk: return
            pending += chunk
            while b"\n" in pending:
                raw, pending = pending.split(b"\n", 1)
                command = raw.decode().strip()
                output, words = "", shlex.split(command)
                if strict_vdom and confirmation_target:
                    if command == "y":
                        forti_tables["system vdom"].setdefault(confirmation_target, {})
                        print(json.dumps({"event": "vdom-confirmed", "name": confirmation_target}), flush=True)
                        if "--vdom-repeat-prompt" in sys.argv:
                            channel.sendall(vdom_question.encode()); continue
                        confirmation_target = None
                        channel.sendall((command + "\r\ncurrent vf=" + target + "\r\nFGT (" + target + ") # ").encode()); continue
                    channel.sendall(b"Command fail. Return code -61\r\nFGT (global) # "); continue
                if command == "get system status":
                    output = "Version: FortiGate-60F v7.4.4,build2662\nHostname: independent\nCurrent virtual domain: root" + ("\nVirtual domain configuration: enable" if strict_network else "")
                elif strict_vdom and command == "config vdom" and scope == "global": context, target = "vdom-list", None
                elif strict_vdom and context == "vdom-list" and words[:1] == ["edit"] and len(words) == 2:
                    target = words[1]
                    if target not in forti_tables["system vdom"] and forti_system["system global"]["edit-vdom-prompt"] == ["enable"]:
                        confirmation_target = target
                        question = "Do you want to delete every VDOM? (y/n)" if "--vdom-wrong-prompt" in sys.argv else vdom_question
                        payload = (command + "\r\n" + question).encode()
                        channel.sendall(payload[:len(payload)//2]); time.sleep(0.01); channel.sendall(payload[len(payload)//2:]); continue
                    forti_tables["system vdom"].setdefault(target, {})
                elif strict_vdom and context == "vdom-list" and words[:1] == ["delete"] and len(words) == 2:
                    candidate = words[1]
                    if candidate == "root" or any(row.get("vdom") == [candidate] for row in forti_tables["system interface"].values()): output = "Command fail. Return code -23"
                    else:
                        forti_tables["system vdom"].pop(candidate, None)
                        forti_tables["system vdom-property"].pop(candidate, None)
                elif command in ["config global", "config vdom"]:
                    scope, context, target = ("global" if command == "config global" else "vdom"), None, None
                elif words[:1] == ["edit"] and scope == "vdom" and context is None:
                    if words[1:] == ["root"]: scope = "root"
                    else: output = "Command fail. Return code -61"
                elif strict_cluster and command == "get system ha status":
                    mode = forti_system["system ha"]["mode"][0]
                    output = "HA Health Status: OK\nMode: " + ("Standalone" if mode == "standalone" else "HA " + mode.upper())
                elif strict_cluster and command == "config system sdwan":
                    if scope != "root": output = "Permission denied"
                    else: context, target = "system sdwan", None
                elif strict_cluster and context == "system sdwan" and words[:1] == ["config"] and " ".join(words[1:]) in sdwan_sections:
                    context, target = "sdwan:" + " ".join(words[1:]), None
                elif strict_cluster and context and context.startswith("sdwan:") and words[:1] == ["edit"] and len(words) == 2:
                    part, target = context[6:], words[1]
                    if part in ["members", "service"] and not target.isdecimal(): output = "Command fail. Return code -61"
                    elif part in ["members", "service"] and target == "0": target, next_sdwan_id = str(next_sdwan_id), next_sdwan_id + 1
                    sdwan_sections[part].setdefault(target, {})
                elif strict_cluster and context and context.startswith("sdwan:") and target and words[:1] == ["set"] and len(words) >= 3:
                    part, key, values = context[6:], words[1], words[2:]
                    valid = {"zone": ["service-sla-tie-break"], "members": ["interface", "zone", "gateway", "status", "comment"], "health-check": ["server", "protocol", "members"], "service": ["name", "mode", "priority-members", "src", "dst", "status", "comment"]}
                    if key not in valid[part]: output = "Command fail. Return code -61"
                    elif part == "members" and key == "interface" and values[0] not in forti_tables["system interface"]: output = "Command fail. Return code -61"
                    elif part == "members" and key == "zone" and values[0] not in sdwan_sections["zone"]: output = "Command fail. Return code -61"
                    elif key in ["priority-members", "members"] and any(v != "0" and v not in sdwan_sections["members"] for v in values): output = "Command fail. Return code -61"
                    else: sdwan_sections[part][target][key] = values
                elif strict_cluster and context and context.startswith("sdwan:") and command == "next": target = None
                elif strict_cluster and context and context.startswith("sdwan:") and command == "end": context, target = "system sdwan", None
                elif strict_cluster and command == "show full-configuration system sdwan":
                    if scope != "root": output = "Permission denied"
                    else:
                        lines = ["config system sdwan", "set status " + sdwan_status]
                        for part, rows in sdwan_sections.items():
                            lines += ["config " + part]
                            for row_id, fields in rows.items():
                                lines += ["edit " + json.dumps(row_id)] + settings_lines(fields)
                                if part == "health-check": lines += ["config sla", "edit 1", "set latency-threshold 50", "next", "end"]
                                lines += ["next"]
                            lines += ["end"]
                        output = "\n".join(lines + ["end"])
                elif command.startswith("show full-configuration "):
                    table = command.removeprefix("show full-configuration ")
                    if not allowed(table): output = "Permission denied"
                    elif table in forti_system:
                        lines = ["config " + table] + settings_lines(forti_system[table])
                        if table == "system ntp":
                            lines += ["config ntpserver"]
                            for key, fields in ntp_servers.items(): lines += ["edit " + key] + settings_lines(fields) + ["next"]
                            lines += ["end"]
                        output = "\n".join(lines + ["end"])
                    elif table in forti_tables:
                        lines = ["config " + table]
                        for key, fields in forti_tables[table].items(): lines += ["edit " + json.dumps(key)] + settings_lines(fields) + ["next"]
                        output = "\n".join(lines + ["end"])
                    else: output = "Unknown action"
                elif command == "config ntpserver" and context == "system ntp": context = "ntpserver"
                elif words[:1] == ["config"] and " ".join(words[1:]) in [*forti_tables, *forti_system]:
                    table = " ".join(words[1:])
                    if allowed(table): context, target = table, None
                    else: output = "Permission denied"
                elif words[:1] == ["edit"] and context and len(words) == 2:
                    target = words[1]
                    if context == "firewall policy" and target == "0": target, next_policy_id = str(next_policy_id), next_policy_id + 1
                    if context in ["router static", "firewall central-snat-map"] and target == "0": target, next_network_id = str(next_network_id), next_network_id + 1
                    if context == "ntpserver": ntp_servers.setdefault(target, {})
                    elif context in forti_tables: forti_tables[context].setdefault(target, {})
                    else: output = "Unknown action"
                elif words[:1] == ["set"] and context and len(words) >= 3:
                    key, values = words[1], words[2:]
                    if strict_vdom and context == "system interface" and key == "vdom" and values[0] not in forti_tables["system vdom"]: output = "Command fail. Return code -61"
                    elif strict_admin and context == "system admin" and key == "password":
                        if values == ["__EOS_PRIVATE_ADMIN_PASSWORD__"]: output = "Command fail. Return code -61"
                        else: forti_tables[context][target][key] = ["ENC", hashlib.sha256(" ".join(values).encode()).hexdigest()]
                    elif strict_admin and context == "system global" and key not in ["admin-sport", "admin-telnet", "admin-ssh-v1", "admin-ssh-password", "admin-scp"]: output = "Command fail. Return code -61"
                    elif strict_admin and context == "system admin" and key == "status": output = "Command fail. Return code -61"
                    elif values == ["fail"]: output = "Command fail. Return code -61"
                    elif values == ["stderr"]: channel.send_stderr(b"Permission denied")
                    elif context == "firewall address" and key == "type" and values[0] not in ["ipmask", "iprange", "fqdn", "geography"]: output = "value parse error. Command fail. Return code -61"
                    elif context == "firewall service custom" and key == "protocol" and values != ["TCP/UDP/SCTP"]: output = "value parse error. Command fail. Return code -61"
                    elif context == "firewall central-snat-map" and key in ["orig-addr", "dst-addr"] and any(v != "all" and v not in forti_tables["firewall address"] and v not in forti_tables["firewall addrgrp"] for v in values): output = "value parse error. Command fail. Return code -61"
                    elif context == "router static" and key == "dst" and len(values) != 2: output = "value parse error. Command fail. Return code -61"
                    elif context in forti_system: forti_system[context][key] = values
                    elif context == "ntpserver" and target: ntp_servers[target][key] = values
                    elif target: forti_tables[context][target][key] = values
                    else: output = "Unknown action"
                elif words[:1] == ["unset"] and context in forti_tables and target and len(words) == 2: forti_tables[context][target].pop(words[1], None)
                elif words[:1] == ["delete"] and context in forti_tables and len(words) == 2: forti_tables[context].pop(words[1], None)
                elif words[:1] == ["move"] and context == "firewall policy" and len(words) == 4:
                    source, direction, destination = words[1:]
                    if source not in forti_tables[context] or destination not in forti_tables[context]: output = "Command fail. Return code -61"
                    else:
                        row, ordered = forti_tables[context].pop(source), {}
                        for key, fields in forti_tables[context].items():
                            if key == destination and direction == "before": ordered[source] = row
                            ordered[key] = fields
                            if key == destination and direction == "after": ordered[source] = row
                        forti_tables[context] = ordered
                elif command == "next": target = None
                elif command == "end":
                    context, target = ("system ntp" if context == "ntpserver" else None), None
                else: output = "Unknown action"
                prompt = target or context or scope or "root"
                payload = (command + "\r\n" + output + "\r\nFGT (" + prompt + ") # ").encode()
                cut = next((index for index, byte in enumerate(payload) if byte >= 128), -1)
                if "--fortigate-split-utf8" in sys.argv and cut >= 0:
                    channel.sendall(payload[:cut + 1]); time.sleep(0.03); channel.sendall(payload[cut + 1:])
                else: channel.sendall(payload)
    except Exception: pass
    finally: channel.close()

def shell(channel):
    if "--fortigate" in sys.argv:
        return forti_shell(channel)
    cwd = "/fixture"
    pending = b""
    try:
        channel.sendall(b"\x1b[32mfixture\x1b[0m $ ")
        while not stopping.is_set():
            chunk = channel.recv(32768)
            if not chunk:
                return
            if b"\x03" in chunk:
                pending = b""
                channel.sendall(b"^C\r\nfixture $ ")
                continue
            pending += chunk.replace(b"\r", b"\n")
            while b"\n" in pending:
                command, pending = pending.split(b"\n", 1)
                if command == b"exit":
                    channel.sendall(b"goodbye\r\n")
                    return
                if command == b"cd /tmp":
                    cwd = "/tmp"
                if command == b"burst":
                    channel.sendall(b"A" * (320 * 1024))
                elif command == b"pwd":
                    channel.sendall(cwd.encode() + b"\r\nfixture $ ")
                else:
                    channel.sendall(command + b"\r\nfixture $ ")
            if len(pending) > 32768:
                return
    except Exception:
        pass
    finally:
        try:
            channel.send_exit_status(0)
        except Exception:
            pass
        channel.close()


class Authentication(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if username == "fixture" and password == "fixture-secret" else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        channel.sendall(("\r\nwindow:%dx%d\r\n" % (width, height)).encode())
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=shell, args=(channel,), daemon=True).start()
        return True


listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(8)


def accept():
    while not stopping.is_set():
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        transport = paramiko.Transport(connection)
        transports.append(transport)
        transport.add_server_key(key)
        try:
            transport.start_server(server=Authentication())
        except Exception:
            transport.close()


signal.signal(signal.SIGTERM, lambda *_: stopping.set())
signal.signal(signal.SIGINT, lambda *_: stopping.set())
threading.Thread(target=accept, daemon=True).start()
print(json.dumps({"port": listener.getsockname()[1], "hostKey": key.get_name() + " " + key.get_base64(), "wrongHostKey": other.get_name() + " " + other.get_base64()}), flush=True)
stopping.wait()
listener.close()
for transport in transports:
    transport.close()
