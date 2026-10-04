#!/usr/bin/env python3
"""Closed, Linux-container-only Samba feasibility probe; never coverage evidence.

The outer supervisor verifies the image and Docker isolation, enforces a hard
deadline, and destroys its exact container/image. This driver additionally checks
the namespace, identity, mounts and capabilities before starting any executable.
Raw diagnostics and generated credentials never leave the private tmpfs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time

BASE = Path("/opt/synthetic-smb")
ROOT = Path("/run/synthetic-smb")
SMBD = Path("/usr/sbin/smbd")
TESTPARM = Path("/usr/bin/testparm")
RCLONE = BASE / "rclone"
PORT = 15445
USER = "synthetic-smb"
UID = 10001
FILES = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/space name.txt": b"Nested synthetic payload.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
}
STAMP_NS = 1704067200123000000
CHECKS = ("environment", "version_binding", "config_validation", "good_listing_before",
          "good_downloads_before", "bad_password_rejected", "good_listing_after",
          "good_downloads_after", "missing_rejected", "source_preserved",
          "config_preserved", "seed_preserved")
MAX_OUTPUT = 512 * 1024
MAX_COMMANDS = 20
MAX_SECONDS = 150
# rclone v1.75.1 connpool.newConnection + go-smb2 d8c5600d73b8
# ResponseError/erref.STATUS_LOGON_FAILURE (0xC000006D), not generic access denial.
AUTH_CAUSE = ("couldn't connect SMB: response error: The attempted logon is invalid. "
              "This is either due to a bad username or authentication information.")


class ProbeError(Exception):
    """Arguments are static, reviewed codes, never child output."""


def require(value, code):
    if not value:
        raise ProbeError(code)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def strict_json(body):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def invalid(_):
        raise ProbeError("invalid_json_number")
    try:
        return json.loads(body, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise ProbeError("invalid_json") from exc


def regular(path, *, private=False):
    path = Path(path)
    require(path.is_absolute(), "absolute_path_required")
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), "symlink_refused")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "regular_file_required")
    if private:
        require(info.st_uid == UID and stat.S_IMODE(info.st_mode) == 0o600,
                "private_seed_required")
    return info


def read_runtime_pins(path):
    """Read the sole repository runtime pin format without executing anything."""
    path = Path(path)
    require(regular(path).st_size <= 4096, "rclone_manifest_size_limit")
    with path.open("rb") as stream:
        body = stream.read(4097)
    require(len(body) <= 4096, "rclone_manifest_size_limit")
    try:
        text = body.decode("ascii")
    except UnicodeError:
        raise ProbeError("rclone_manifest_invalid") from None
    keys = {"RCLONE_VERSION", "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256",
            "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256"}
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        require(separator and key in keys and key not in values, "rclone_manifest_invalid")
        values[key] = value
    require(set(values) == keys
            and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", values["RCLONE_VERSION"]),
            "rclone_manifest_invalid")
    require(all(re.fullmatch(r"[a-f0-9]{64}", values[key]) for key in keys - {"RCLONE_VERSION"}),
            "rclone_manifest_invalid")
    return {"version": values["RCLONE_VERSION"], "sha256": values["RCLONE_LINUX_EXE_SHA256"]}


def bind_runtime_identity(report):
    pins = read_runtime_pins(BASE / "rclone-version.env")
    regular(RCLONE)
    require(sha256(RCLONE) == pins["sha256"], "rclone_pin_mismatch")
    report["runtime"].update(rclone_version=pins["version"], rclone_sha256=pins["sha256"])
    return pins


def private_write(path, body):
    with Path(path).open("xb") as stream:
        stream.write(body if isinstance(body, bytes) else body.encode("utf-8"))
    Path(path).chmod(0o600)


def tree_snapshot(root):
    result = {}
    for path in sorted(Path(root).rglob("*")):
        require(not path.is_symlink(), "tree_symlink_refused")
        info = path.lstat()
        name = path.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            result[name + "/"] = ("directory", stat.S_IMODE(info.st_mode))
        else:
            regular(path)
            require(info.st_size <= 4 * 1024 * 1024, "tree_size_limit")
            result[name] = (info.st_size, sha256(path), info.st_mtime_ns,
                            stat.S_IMODE(info.st_mode))
    return result


def remove_owned_contents(identity):
    require(not ROOT.is_symlink() and (ROOT.stat().st_dev, ROOT.stat().st_ino) == identity,
            "runtime_root_replaced")
    mount_checks(Path("/proc/self/mountinfo").read_text())
    # Unix-domain sockets may remain as directory entries after smbd exits.
    # They are unlinked only inside the same empty-at-start owned tmpfs.
    for path in ROOT.rglob("*"):
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == UID
                and (stat.S_ISDIR(info.st_mode) or stat.S_ISSOCK(info.st_mode)
                     or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)),
                "cleanup_entry_refused")
    for path in ROOT.iterdir():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    return not any(ROOT.iterdir())


def proc_status(text):
    values = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
    require(all(values.get(key, "").split() == [str(UID)] * 4 for key in ("Uid", "Gid")),
            "identity_mismatch")
    require(values.get("Groups", "").split() in ([], [str(UID)]), "supplementary_groups_refused")
    require(values.get("NoNewPrivs", "").strip() == "1", "no_new_privileges_required")
    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        require(re.fullmatch(r"0{16}", values.get(key, "").strip()), "capabilities_present")


def mount_checks(text):
    entries = {}
    for line in text.splitlines():
        left, separator, right = line.partition(" - ")
        require(separator and len(left.split()) >= 6 and len(right.split()) >= 3,
                "mount_table_invalid")
        cols, fs = left.split(), right.split()
        entries[cols[4]] = (set(cols[5].split(",")), fs[0])
    require("/" in entries and "ro" in entries["/"][0], "readonly_root_required")
    target = ROOT.as_posix()
    require(target in entries and entries[target][1] == "tmpfs"
            and {"rw", "nosuid", "nodev", "noexec"} <= entries[target][0],
            "private_tmpfs_required")
    require(not any(path.startswith(target + "/") for path in entries), "nested_mount_refused")


def tcp_listeners(text):
    result = []
    for line in text.splitlines()[1:]:
        columns = line.split()
        require(len(columns) >= 10, "socket_table_invalid")
        if columns[3] == "0A":
            result.append(columns[1])
    return sorted(result)


def listeners():
    return (tcp_listeners(Path("/proc/net/tcp").read_text()),
            tcp_listeners(Path("/proc/net/tcp6").read_text()))


def proc_identity(pid):
    # starttime prevents signalling a PID which has been recycled.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    info = Path(f"/proc/{pid}").stat()
    return (int(fields[19]), info.st_uid, int(fields[1]), fields[0])


def namespace_processes():
    result = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdecimal():
            try:
                result[int(entry.name)] = proc_identity(int(entry.name))
            except FileNotFoundError:
                pass
    return result


def environment_checks():
    require(sys.platform == "linux" and platform.machine() == "x86_64", "linux_amd64_required")
    proc_status(Path("/proc/self/status").read_text())
    mount_checks(Path("/proc/self/mountinfo").read_text())
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()
                  if ":" in line}
    require(interfaces == {"lo"}, "loopback_namespace_required")
    require(listeners() == ([], []), "preexisting_listener_refused")
    init = Path("/proc/1/cmdline").read_bytes().split(b"\0")[0].rsplit(b"/", 1)[-1]
    require(init in (b"docker-init", b"tini"), "container_init_required")
    require(set(namespace_processes()) == {1, os.getpid()}, "unexpected_initial_process")
    require(ROOT.is_dir() and not any(p.is_symlink() for p in (ROOT, *ROOT.parents)),
            "runtime_root_invalid")
    info = ROOT.stat()
    require(info.st_uid == UID and info.st_gid == UID and stat.S_IMODE(info.st_mode) == 0o700
            and not any(ROOT.iterdir()), "runtime_root_not_private_empty")


def samba_config(root=ROOT):
    # No interpolation of user input, external includes, scripts or VFS plugins.
    require(root == ROOT, "fixed_runtime_root_required")
    root = root.as_posix()
    return f"""[global]
server role = standalone server
security = user
workgroup = SYNTHETIC
netbios name = SYNTHETIC
interfaces = 127.0.0.1
bind interfaces only = yes
smb ports = {PORT}
server min protocol = SMB2_02
server max protocol = SMB3
server signing = mandatory
map to guest = Never
restrict anonymous = 2
ntlm auth = ntlmv2-only
disable netbios = yes
dns proxy = no
load printers = no
printing = bsd
printcap name = /dev/null
disable spoolss = yes
rpc_server:default = disabled
rpc_daemon:spoolssd = disabled
passdb backend = tdbsam:{root}/private/passdb.tdb
private dir = {root}/private
state directory = {root}/state
cache directory = {root}/cache
lock directory = {root}/lock
pid directory = {root}/pid
ncalrpc dir = {root}/ncalrpc
log file = {root}/logs/smbd.log
max log size = 64
log level = 1
logging = file
deadtime = 1
max smbd processes = 8
max connections = 4
wide links = no
follow symlinks = no
allow insecure wide links = no
unix extensions = no
[SYNTHETIC]
path = {root}/source
valid users = {USER}
read only = yes
guest ok = no
browseable = no
printable = no
follow symlinks = no
wide links = no
"""


def rclone_config(obscured):
    require(re.fullmatch(r"[A-Za-z0-9_-]{20,256}", obscured), "invalid_obscured_password")
    return (f"[loopback]\ntype = smb\nhost = 127.0.0.1\nport = {PORT}\nuser = {USER}\n"
            f"pass = {obscured}\ndomain = SYNTHETIC\nuse_kerberos = false\n"
            "case_insensitive = false\nidle_timeout = 1s\n")


def listing_matches(body):
    try:
        data = strict_json(body)
        if type(data) is not dict or set(data) != {"list"} or type(data["list"]) is not list:
            return False
        found = {}
        for item in data["list"]:
            if (type(item) is not dict or set(item) != {"Path", "Name", "Size", "ModTime", "IsDir"}
                    or type(item["Path"]) is not str or item["Path"] not in FILES
                    or item["Path"] in found or item["Name"] != item["Path"].rsplit("/", 1)[-1]
                    or type(item["Size"]) is not int or item["Size"] != len(FILES[item["Path"]])
                    or item["IsDir"] is not False or type(item["ModTime"]) is not str):
                return False
            match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\.123(Z|[+-]\d\d:\d\d)", item["ModTime"])
            if not match or match[2] == "-00:00":
                return False
            if datetime.fromisoformat(match[1] + match[2].replace("Z", "+00:00")).astimezone(timezone.utc) != datetime(2024, 1, 1, tzinfo=timezone.utc):
                return False
            found[item["Path"]] = True
        return set(found) == set(FILES)
    except (ProbeError, ValueError, TypeError, OverflowError):
        return False


def rejection_matches(body, kind):
    try:
        data = strict_json(body)
        cause = {"password": AUTH_CAUSE, "missing": "object not found"}[kind]
        return (type(data) is dict and set(data) == {"error", "path", "status"}
                and type(data["status"]) is int and data["status"] == 500
                and data["path"] == "operations/copyfile"
                and data["error"] == "loopback: call failed: " + cause)
    except (ProbeError, KeyError, TypeError):
        return False


class Children:
    """Only fixed binaries, private bounded output, namespace-owned PID cleanup."""
    def __init__(self, hashes):
        self.hashes = hashes
        self.records = []
        self.count = 0
        self.deadline = time.monotonic() + MAX_SECONDS
        self.server = None
        self.env = {"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                    "HOME": str(ROOT), "TMPDIR": str(ROOT), "XDG_CONFIG_HOME": str(ROOT),
                    "XDG_CACHE_HOME": str(ROOT), "NO_PROXY": "*"}

    def guard(self):
        require(time.monotonic() < self.deadline, "probe_deadline")
        if self.server:
            require(self.server.poll() is None, "samba_exited")
        for _, out, err in self.records:
            require(out.stat().st_size <= MAX_OUTPUT and err.stat().st_size <= MAX_OUTPUT,
                    "child_output_limit")
        require(sum(p.stat().st_size for p in (ROOT / "logs").glob("*") if p.is_file()) <= MAX_OUTPUT,
                "samba_log_limit")

    def start(self, binary, args, stdin=None, *, keep_stdin=False):
        self.guard()
        require(binary in self.hashes and self.count < MAX_COMMANDS, "command_not_allowed")
        require(not keep_stdin or (binary == SMBD and stdin is None), "daemon_stdin_invalid")
        regular(binary)
        require(sha256(binary) == self.hashes[binary], "executable_changed")
        self.count += 1
        out, err = ROOT / f"child-{self.count}.out", ROOT / f"child-{self.count}.err"
        input_path = ROOT / f"child-{self.count}.in"
        private_write(input_path, stdin or b"")
        # Samba's atexit killkids() sends SIGTERM to its process group:
        # samba-team/samba tag samba-4.22.11, source3/smbd/server.c:125-128.
        # Isolate only the daemon, retaining --no-process-group inside Samba.
        with input_path.open("rb") as inp, out.open("xb") as stdout, err.open("xb") as stderr:
            child = subprocess.Popen([str(binary), *args], stdin=subprocess.PIPE if keep_stdin else inp, stdout=stdout, stderr=stderr,
                                     cwd=ROOT, env=self.env, close_fds=True, start_new_session=keep_stdin)
        self.records.append((child, out, err))
        return child, out, err

    def run(self, binary, args, stdin=None, timeout=12):
        child, out, err = self.start(binary, args, stdin)
        deadline = min(self.deadline, time.monotonic() + timeout)
        while child.poll() is None:
            self.guard()
            require(time.monotonic() < deadline, "child_timeout")
            time.sleep(0.03)
        self.guard()
        return child.returncode, out.read_bytes(), err.read_bytes()

    def rclone(self, args, config=None, stdin=None):
        return self.run(RCLONE, ["--config", str(config or ROOT / "empty.conf"), "--cache-dir", str(ROOT / "cache"),
                                "--log-level", "ERROR", "--stats", "0", "--retries", "1", "--low-level-retries", "1",
                                "--contimeout", "2s", "--timeout", "4s", "--transfers", "1", "--checkers", "1", *args], stdin)

    def close(self):
        # Preflight establishes an otherwise empty PID namespace. Only processes
        # created during this probe, owned by UID10001, are candidates; exclude init/self.
        for sig, seconds in ((signal.SIGTERM, 2), (signal.SIGKILL, 2)):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                candidates = {pid: identity for pid, identity in namespace_processes().items()
                              if pid not in (1, os.getpid()) and identity[3] != "Z"}
                if not candidates:
                    break
                for pid, identity in candidates.items():
                    require(identity[1] == UID, "foreign_process_refused")
                    try:
                        if proc_identity(pid) == identity:
                            os.kill(pid, sig)
                    except ProcessLookupError:
                        pass
                    except FileNotFoundError:
                        pass
                for child, _, _ in self.records:
                    child.poll()
                time.sleep(0.03)
        waited = True
        for child, _, _ in self.records:
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                waited = False
            finally:
                if child.stdin is not None:
                    child.stdin.close()
        # Tini may need a scheduling turn to reap orphaned Samba workers.
        # Zombies do not count as removed until their /proc entries disappear.
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if not {pid for pid in namespace_processes() if pid not in (1, os.getpid())}:
                return waited
            time.sleep(0.03)
        return False


def new_report():
    return {"schema_version": 1, "scope": "smb_samba_feasibility_only", "status": "failed", "ledger_eligible": False,
            "runtime": {"platform": "linux/amd64", "uid": UID, "gid": UID, "samba_version": None,
                        "rclone_version": None, "smbd_sha256": None, "rclone_sha256": None,
                        "probe_sha256": None, "lock_sha256": None},
            "checks": dict.fromkeys(CHECKS, False),
            "cleanup": dict.fromkeys(("children_stopped", "listeners_closed", "temporary_removed"), False),
            "commands_total": 0, "errors": []}


def verify_build(report):
    lock_path, manifest_path = BASE / "build-lock.json", BASE / "runtime-manifest.json"
    pins = bind_runtime_identity(report)
    for path in (lock_path, manifest_path, SMBD, TESTPARM, RCLONE, BASE / "probe_samba.py"):
        regular(path)
    lock = strict_json(lock_path.read_bytes())
    manifest = strict_json(manifest_path.read_bytes())
    keys = {"schema_version", "smbd_sha256", "testparm_sha256", "rclone_sha256", "probe_sha256",
            "lock_sha256", "samba_version", "rclone_version", "rclone_manifest_sha256"}
    require(type(manifest) is dict and set(manifest) == keys and type(manifest["schema_version"]) is int
            and manifest["schema_version"] == 1, "runtime_manifest_invalid")
    for key in keys - {"schema_version", "samba_version", "rclone_version"}:
        require(type(manifest[key]) is str and re.fullmatch(r"[0-9a-f]{64}", manifest[key]), "runtime_manifest_invalid")
    expected = lock.get("runtime_expected", {}) if type(lock) is dict else {}
    version = manifest["samba_version"]
    require(type(version) is str and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.+-]+)?", version)
            and expected.get("samba_version") == version and expected.get("uid") == UID
            and expected.get("gid") == UID and expected.get("username") == USER,
            "build_identity_mismatch")
    paths = {SMBD: "smbd_sha256", TESTPARM: "testparm_sha256", RCLONE: "rclone_sha256",
             BASE / "probe_samba.py": "probe_sha256", lock_path: "lock_sha256",
             BASE / "rclone-version.env": "rclone_manifest_sha256"}
    for path, key in paths.items():
        require(sha256(path) == manifest[key], "build_hash_mismatch")
    require(manifest["rclone_sha256"] == pins["sha256"] and manifest["rclone_version"] == pins["version"],
            "rclone_pin_mismatch")
    for key in ("samba_version", "smbd_sha256", "probe_sha256", "lock_sha256"):
        report["runtime"][key] = manifest[key]
    return {path: manifest[paths[path]] for path in (SMBD, TESTPARM, RCLONE)}


def prepare():
    seed = BASE / "seed"
    require(seed.is_dir() and not seed.is_symlink() and seed.stat().st_uid == UID
            and stat.S_IMODE(seed.stat().st_mode) == 0o700, "seed_directory_invalid")
    names = {p.name for p in seed.iterdir()}
    require({"credential.json", "passdb.tdb"} <= names <= {"credential.json", "passdb.tdb", "secrets.tdb"}, "seed_inventory_invalid")
    for name in names:
        info = regular(seed / name, private=True)
        require(info.st_size <= 4 * 1024 * 1024, "seed_size_limit")
    credential = strict_json((seed / "credential.json").read_bytes())
    require(type(credential) is dict and set(credential) == {"schema_version", "username", "password"}
            and type(credential["schema_version"]) is int and credential["schema_version"] == 1
            and credential["username"] == USER and type(credential["password"]) is str
            and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", credential["password"]), "seed_credential_invalid")
    for name in ("private", "state", "cache", "lock", "pid", "ncalrpc", "logs", "source", "output"):
        (ROOT / name).mkdir(mode=0o700)
    for name in names - {"credential.json"}:
        shutil.copyfile(seed / name, ROOT / "private" / name)
        (ROOT / "private" / name).chmod(0o600)
    for name, payload in FILES.items():
        path = ROOT / "source" / name
        path.parent.mkdir(exist_ok=True, mode=0o700)
        private_write(path, payload)
        os.utime(path, ns=(STAMP_NS, STAMP_NS))
        path.chmod(0o400)
    private_write(ROOT / "empty.conf", "")
    private_write(ROOT / "smb.conf", samba_config())
    return credential["password"]


def probe_cases(children, report):
    def copy(name, target, config):
        return children.rclone(["rc", "--loopback", "operations/copyfile", "srcFs=loopback:SYNTHETIC/",
                                "srcRemote=" + name, "dstFs=" + str(target), "dstRemote=payload"], config)
    for phase in ("before", "after"):
        code, body, _ = children.rclone(["rc", "--loopback", "operations/list", "fs=loopback:SYNTHETIC/", "remote=",
                                        'opt={"recurse":true,"filesOnly":true,"noMimeType":true,"noModTime":false}'], ROOT / "good.conf")
        require(code == 0 and listing_matches(body), "listing_mismatch")
        report["checks"]["good_listing_" + phase] = True
        for index, (name, payload) in enumerate(FILES.items()):
            target = ROOT / "output" / f"{phase}-{index}"
            target.mkdir(mode=0o700)
            code, body, _ = copy(name, target, ROOT / "good.conf")
            require(code == 0 and strict_json(body) == {}, "download_failed")
            require(set(p.name for p in target.iterdir()) == {"payload"}, "download_tree_mismatch")
            regular(target / "payload")
            require((target / "payload").read_bytes() == payload
                    and sha256(target / "payload") == hashlib.sha256(payload).hexdigest(), "download_hash_mismatch")
        report["checks"]["good_downloads_" + phase] = True
        if phase == "before":
            target = ROOT / "output" / "denied"
            target.mkdir(mode=0o700)
            code, body, _ = copy("README-synthetic.txt", target, ROOT / "bad.conf")
            require(code != 0 and rejection_matches(body, "password") and not any(target.iterdir()), "password_rejection_mismatch")
            report["checks"]["bad_password_rejected"] = True
    target = ROOT / "output" / "missing"
    target.mkdir(mode=0o700)
    code, body, _ = copy("absent-synthetic.txt", target, ROOT / "good.conf")
    require(code != 0 and rejection_matches(body, "missing") and not any(target.iterdir()), "missing_rejection_mismatch")
    report["checks"]["missing_rejected"] = True


def run_probe():
    report = new_report()
    children = None
    root_identity = source_before = config_before = seed_before = None
    try:
        # Read-only binding preserves legitimate identity on later preflight failure.
        bind_runtime_identity(report)
        environment_checks()
        report["checks"]["environment"] = True
        root_identity = (ROOT.stat().st_dev, ROOT.stat().st_ino)
        hashes = verify_build(report)
        seed_before = tree_snapshot(BASE / "seed")
        password = prepare()
        children = Children(hashes)
        code, body, _ = children.run(SMBD, ["--version"])
        require(code == 0 and body.decode("ascii").strip() == "Version " + report["runtime"]["samba_version"], "samba_version_mismatch")
        code, body, _ = children.rclone(["version"])
        require(code == 0 and body.splitlines()
                and body.splitlines()[0] == ("rclone v" + report["runtime"]["rclone_version"]).encode("ascii"),
                "rclone_version_mismatch")
        report["checks"]["version_binding"] = True
        for label, value in (("good", password), ("bad", password + "-wrong")):
            code, body, _ = children.rclone(["obscure", "-"], stdin=(value + "\n").encode())
            require(code == 0, "password_obscure_failed")
            private_write(ROOT / (label + ".conf"), rclone_config(body.decode("ascii").strip()))
        password = None
        code, body, error = children.run(TESTPARM, ["--suppress-prompt", str(ROOT / "smb.conf")])
        require(code == 0 and b"Unknown parameter" not in body + error and b"Ignoring unknown parameter" not in body + error,
                "samba_config_invalid")
        report["checks"]["config_validation"] = True
        config_before = {name: sha256(ROOT / name) for name in ("smb.conf", "empty.conf", "good.conf", "bad.conf")}
        source_before = tree_snapshot(ROOT / "source")
        children.server = children.start(SMBD, ["--foreground", "--no-process-group", "--configfile=" + str(ROOT / "smb.conf")], keep_stdin=True)[0]
        ready_deadline = time.monotonic() + 10
        while listeners() != ([f"0100007F:{PORT:04X}"], []):
            children.guard()
            require(time.monotonic() < ready_deadline, "samba_not_ready")
            require(listeners() in (([], []), ([f"0100007F:{PORT:04X}"], [])), "unexpected_listener")
            time.sleep(0.04)
        probe_cases(children, report)
    except ProbeError as exc:
        report["errors"].append(str(exc))
    except Exception:
        report["errors"].append("probe_internal_failure")
    finally:
        if children:
            report["commands_total"] = children.count
            try:
                report["cleanup"]["children_stopped"] = children.close()
            except Exception:
                report["errors"].append("child_cleanup_failed")
        elif root_identity:
            report["cleanup"]["children_stopped"] = True
        if root_identity:
            try:
                report["cleanup"]["listeners_closed"] = listeners() == ([], [])
            except Exception:
                report["errors"].append("listener_cleanup_failed")
            for key, check in (
                    ("source_preserved", lambda: source_before is not None and tree_snapshot(ROOT / "source") == source_before),
                    ("config_preserved", lambda: config_before is not None and all(sha256(ROOT / name) == value for name, value in config_before.items())),
                    ("seed_preserved", lambda: seed_before is not None and tree_snapshot(BASE / "seed") == seed_before)):
                try:
                    report["checks"][key] = bool(check())
                except Exception:
                    report["errors"].append("preservation_check_failed")
            try:
                require(report["cleanup"]["children_stopped"], "live_child_blocks_removal")
                report["cleanup"]["temporary_removed"] = remove_owned_contents(root_identity)
            except Exception:
                report["errors"].append("private_cleanup_failed")
    if not all(report["cleanup"].values()):
        report["errors"].append("cleanup_incomplete")
    if not all(report["checks"].values()):
        report["errors"].append("feasibility_incomplete")
    report["errors"] = sorted(set(report["errors"]))
    if not report["errors"]:
        report["status"] = "passed"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, choices=[str(BASE / "build-lock.json")])
    parser.parse_args(argv)
    os.umask(0o077)
    report = run_probe()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
