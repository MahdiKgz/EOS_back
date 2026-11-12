// Linux restore receiver is fixed code; configuration is supplied only on stdin.
export const LINUX_ETC_RECEIVER = String.raw`
import os, sys, json, stat, base64, hashlib, secrets
p = json.load(sys.stdin)
entries, intent = p["entries"], p["intent"]
assert intent in ("preflight", "apply", "verify") and os.geteuid() == 0 and len(entries) <= 10000
rootfd = os.open("/etc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
seen, total = set(), 0
for e in entries:
    parts = e["path"].split("/")
    assert parts[0] == "etc" and all(v not in ("", ".", "..") for v in parts)
    assert e["path"] not in seen and e["kind"] in ("file", "directory", "symlink")
    seen.add(e["path"])
    assert 0 <= e["mode"] <= 511 and 0 <= e["uid"] < 4294967295 and 0 <= e["gid"] < 4294967295
    if e["kind"] == "file":
        b = base64.b64decode(e["data"], validate=True)
        assert hashlib.sha256(b).hexdigest() == e["sha256"]
        total += len(b)
    if e["kind"] == "symlink":
        assert e["link"] and len(e["link"]) <= 4096 and chr(0) not in e["link"]
assert total <= 67108864
links = set(e["path"] for e in entries if e["kind"] == "symlink")
assert not any("/".join(e["path"].split("/")[:i]) in links for e in entries for i in range(1, len(e["path"].split("/"))))
def parent(path, create=False):
    parts, fd = path.split("/")[1:], os.dup(rootfd)
    try:
        for part in parts[:-1]:
            try:
                newfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    os.close(fd)
                    return None, parts[-1] if parts else ""
                os.mkdir(part, 493, dir_fd=fd)
                newfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = newfd
        return fd, parts[-1] if parts else ""
    except:
        os.close(fd)
        raise
def check(e):
    fd, name = parent(e["path"])
    if fd is None: return
    try:
        if not name: return
        try: s = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: return
        assert stat.S_ISDIR(s.st_mode) if e["kind"] == "directory" else stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode)
    finally: os.close(fd)
for e in entries: check(e)
if intent == "apply":
    for e in sorted(entries, key=lambda v: (v["kind"] != "directory", v["path"].count("/"))):
        fd, name = parent(e["path"], True)
        try:
            if not name: continue
            check(e)
            if e["kind"] == "directory":
                try: os.mkdir(name, e["mode"], dir_fd=fd)
                except FileExistsError: pass
                continue
            tmp = ".soar-restore-" + secrets.token_hex(16)
            try:
                if e["kind"] == "symlink":
                    os.symlink(e["link"], tmp, dir_fd=fd)
                    os.chown(tmp, e["uid"], e["gid"], dir_fd=fd, follow_symlinks=False)
                else:
                    out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=fd)
                    with os.fdopen(out, "wb") as f:
                        f.write(base64.b64decode(e["data"], validate=True))
                        f.flush()
                        os.fsync(f.fileno())
                        os.fchown(f.fileno(), e["uid"], e["gid"])
                        os.fchmod(f.fileno(), e["mode"])
                os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
                os.fsync(fd)
            finally:
                try: os.unlink(tmp, dir_fd=fd)
                except FileNotFoundError: pass
        finally: os.close(fd)
if intent in ("apply", "verify"):
    for e in entries:
        fd, name = parent(e["path"])
        assert fd is not None
        try:
            if not name: continue
            s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if e["kind"] == "directory": assert stat.S_ISDIR(s.st_mode)
            elif e["kind"] == "symlink":
                assert stat.S_ISLNK(s.st_mode) and os.readlink(name, dir_fd=fd) == e["link"] and s.st_uid == e["uid"] and s.st_gid == e["gid"]
            else:
                assert stat.S_ISREG(s.st_mode)
                with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd), "rb") as f:
                    assert hashlib.sha256(f.read()).hexdigest() == e["sha256"]
                assert stat.S_IMODE(s.st_mode) == e["mode"] and s.st_uid == e["uid"] and s.st_gid == e["gid"]
        finally: os.close(fd)
os.close(rootfd)
print(json.dumps({"receiver":"SOAR_ETC_RESTORE_V1", "intent":intent, "verified":True, "entries":len(entries)}))
`;
export function linuxReceiverCommand(rootUser: boolean) {
  return (
    (rootUser ? "" : "sudo -n ") + "python3 -c '" + LINUX_ETC_RECEIVER.replace(/'/g, "'\\''") + "'"
  );
}
