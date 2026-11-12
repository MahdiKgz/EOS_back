"""Loopback-only SSH/SFTP fixture using the host's Paramiko package; files stay under argv[1]."""
import json
import logging
import os
import re
import signal
import socket
import sys
import threading
import paramiko

logging.disable(logging.CRITICAL)
root = os.path.realpath(sys.argv[1])
key = paramiko.RSAKey.generate(2048)
alternate = paramiko.RSAKey.generate(2048)
stopping = threading.Event()
transports = []


class Authentication(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if username == "fixture" and password == "fixture-secret" else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=cli, args=(channel,), daemon=True).start()
        return True


def cli(channel):
    """A fixed CLI transcript to verify hostname/prompt changes; never executes shell text."""
    try:
        channel.settimeout(10)
        channel.sendall(b"Old#")
        pending = b""
        while True:
            chunk = channel.recv(4096)
            if not chunk:
                break
            pending += chunk
            if len(pending) > 4096:
                break
            while b"\n" in pending:
                command, pending = pending.split(b"\n", 1)
                text = command.decode("ascii").strip()
                if text == "exit":
                    return
                channel.sendall(command + b"\r\n")
                if re.fullmatch(r"configure replace flash:/soar-[a-f0-9]{32}\.cfg force time 3", text):
                    channel.sendall(b"Replacement complete.\r\nNew#")
                else:
                    channel.sendall(b"% Invalid input detected.\r\nOld#")
    finally:
        channel.send_exit_status(0)
        channel.close()


class Filesystem(paramiko.SFTPServerInterface):
    def open(self, path, flags, attr):
        if not re.fullmatch(r"soar-[a-f0-9]{32}\.rsc", path):
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            descriptor = os.open(os.path.join(root, path), flags, 0o600)
            handle = paramiko.SFTPHandle(flags)
            handle.writefile = os.fdopen(descriptor, "wb")
            return handle
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)


class Subsystem(paramiko.SFTPServer):
    def finish_subsystem(self):
        try:
            self.sock.send_exit_status(0)
        finally:
            super().finish_subsystem()


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
        transport.set_subsystem_handler("sftp", Subsystem, Filesystem)
        try:
            transport.start_server(server=Authentication())
        except Exception:
            transport.close()


def stop(*_):
    stopping.set()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
threading.Thread(target=accept, daemon=True).start()
print(json.dumps({"port": listener.getsockname()[1], "hostKey": key.get_name() + " " + key.get_base64(), "wrongHostKey": alternate.get_name() + " " + alternate.get_base64()}), flush=True)
stopping.wait()
listener.close()
for transport in transports:
    transport.close()
