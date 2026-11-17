"""Finite command-only helper. Control is in the owned case cwd, never /opt."""
import contextlib
import itertools
import json
import os
from pathlib import Path
import re
import stat
import sys

CASES = {"renewal":3, "refresh_denied":102, "initial_nonzero":1, "initial_empty":11, "cancellation":3}
TOKENS = (b"synthetic-tokenA\n", b"synthetic-tokenB\n")
DENIAL = b"synthetic-command-denied\n"


class Invalid(ValueError):
    pass


def check(value):
    if not value:
        raise Invalid()


def decode(raw):
    check(type(raw) is bytes and len(raw) <= 1024)
    def pairs(rows):
        value = {}
        for key, item in rows:
            check(key not in value); value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=pairs)
    check(type(value) is dict and set(value) == {"schema_version", "case"} and type(value["schema_version"]) is int and value["schema_version"] == 1)
    check(type(value["case"]) is str and value["case"] in CASES)
    return value["case"]


def action(case, sequence):
    check(case in CASES and type(sequence) is int and 1 <= sequence <= CASES[case])
    name = "deny" if case == "initial_nonzero" or (case == "refresh_denied" and sequence > 2) else "empty" if case == "initial_empty" else "B" if sequence == 3 else "A"
    out = TOKENS[name == "B"] if name in ("A", "B") else b""
    err = DENIAL if name == "deny" else b""
    code = 70 if name == "deny" else 0
    return name, out, err, code


def record(value):
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    check(len(body) <= 256)
    return body


def run(io):
    try:
        case = decode(io.control())
        check(io.case_matches(case))
        with io.lock():
            names = io.names()
            check(type(names) is set and len(names) <= 204)
            sequence = len(names)//2 + 1
            check(names == {f"{i:03}-{kind}.json" for i in range(1, sequence) for kind in ("start", "done")})
            name, out, err, code = action(case, sequence)
            for i in range(1, sequence):
                previous_name, previous_out, previous_err, previous_code = action(case, i)
                check(io.read(f"{i:03}-start.json") == record(dict(sequence=i, action=previous_name)))
                check(io.read(f"{i:03}-done.json") == record(dict(sequence=i, action=previous_name, intended_exit=previous_code, stdout_bytes=len(previous_out), stderr_bytes=len(previous_err))))
            io.create(f"{sequence:03}-start.json", record(dict(sequence=sequence, action=name)))
            io.write(1, out); io.write(2, err)
            io.create(f"{sequence:03}-done.json", record(dict(sequence=sequence, action=name, intended_exit=code, stdout_bytes=len(out), stderr_bytes=len(err))))
            return code
    except (Invalid, ValueError, UnicodeError):
        return 71
    except OSError:
        return 72


class NativeIO:
    def __init__(self):
        self.root = Path.cwd()
        check(re.fullmatch(r"/work/case-(renewal|refresh_denied|initial_nonzero|initial_empty|cancellation)", str(self.root)) is not None)
        for path in (self.root, self.root.parent, self.root/"journal"):
            info = path.lstat()
            check(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)

    def case_matches(self, case):
        return self.root.name == "case-"+case

    def _read(self, path, limit):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= limit)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                body = stream.read(limit+1)
            check(len(body) <= limit)
            return body
        finally:
            os.close(fd)

    def control(self):
        return self._read(self.root/"control.json", 1024)

    @contextlib.contextmanager
    def lock(self):
        import fcntl
        fd = os.open(self.root/"helper.lock", os.O_WRONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def names(self):
        names={path.name for path in itertools.islice((self.root/"journal").iterdir(),205)}
        check(len(names)<=204)
        return names

    def read(self, name):
        return self._read(self.root/"journal"/name, 256)

    def create(self, name, body):
        fd = os.open(self.root/"journal"/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                check(stream.write(body) == len(body)); stream.flush()
        finally:
            os.close(fd)

    def write(self, fd, body):
        check(fd in (1, 2) and len(body) <= 32)
        for _ in range(len(body)):
            written = os.write(fd, body)
            check(0 < written <= len(body)); body = body[written:]
            if not body:
                break
        check(not body)


if __name__ == "__main__":
    try:
        check(len(sys.argv)==1)
        raise SystemExit(run(NativeIO()))
    except (Invalid, ValueError, UnicodeError):
        raise SystemExit(71) from None
    except OSError:
        raise SystemExit(72) from None
