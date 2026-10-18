"""Bounded declared Cargo source policy, not a Cargo/build-script interpreter.

Return portable sorted name/hash rows. Filesystem identities and excluded output
state are used only to detect changes during a scan and never enter the digest.
"""
import hashlib
import os
from pathlib import Path
import stat
import tomllib
import unicodedata

MAX_ENTRIES = 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_PACKAGES = 64
MAX_DEPTH = 64
WINDOWS = os.name == "nt"
APP = "rclone-triage"
FIXED = ("Cargo.toml", "Cargo.lock", "build.rs", ".cargo/config.toml")
DEPENDENCIES = ("dependencies", "build-dependencies", "dev-dependencies")


class SourceSnapshotError(ValueError):
    pass


def need(condition, code="source_invalid"):
    if not condition:
        raise SourceSnapshotError(code)


def identity(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), getattr(info, "st_file_attributes", 0) & 0x400


def stamp(info):
    return identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns


def open_stamp(info):
    # Windows path and handle APIs can expose different ctime meanings. Keep
    # ctime in both same-API before/after checks; compare common fields at open.
    return (identity(info), info.st_size, info.st_mtime_ns,
            None if WINDOWS else info.st_ctime_ns, getattr(info, "st_birthtime_ns", None))


def path_state(path, *, directory=False, optional=False):
    """Reject links/reparse paths; directory timestamps are deliberately omitted."""
    path = Path(path).absolute()
    result = []
    for index, item in enumerate((path, *path.parents)):
        try:
            info = item.lstat()
        except FileNotFoundError:
            need(optional, "source_unreadable")
            result.append((str(item), None))
            continue
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400)
        need(stat.S_ISDIR(info.st_mode) if index or directory else stat.S_ISREG(info.st_mode))
        result.append((str(item), identity(info) if index or directory else stamp(info)))
    return tuple(result)


def read_file(path, limit=MAX_FILE_BYTES, *, content=False):
    """Same-handle and final-path stability checks, including every ancestor."""
    path = Path(path).absolute()
    try:
        parents = path_state(path)
        before = path.lstat()
        need(before.st_size <= limit, "source_limit")
        digest, chunks, size = hashlib.sha256(), [], 0
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            need(open_stamp(opened) == open_stamp(before), "source_changed")
            while True:
                chunk = stream.read(min(1024 * 1024, limit - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                need(size <= limit, "source_limit")
                digest.update(chunk)
                if content:
                    chunks.append(chunk)
            need(stamp(os.fstat(stream.fileno())) == stamp(opened), "source_changed")
        need(size == before.st_size and path_state(path) == parents, "source_changed")
        return b"".join(chunks) if content else digest.hexdigest()
    except OSError:
        raise SourceSnapshotError("source_unreadable") from None


class Inventory:
    def __init__(self, root, reader):
        self.root = Path(root).absolute()
        path_state(self.root, directory=True)
        self.root = self.root.resolve(strict=True)
        self.reader = reader
        self.names, self.entries, self.states, self.captured = set(), set(), {}, {}
        self.spellings = {}
        self.packages, self.visiting, self.finished, self.declared = set(), set(), set(), set()
        self.excluded = {}
        self.total = 0

    def track(self, path, *, directory=False, optional=False):
        relative = path.relative_to(self.root)
        need(len(relative.parts) <= MAX_DEPTH, "source_limit")
        for length in range(1, len(relative.parts) + 1):
            spelling = "/".join(relative.parts[:length])
            need(spelling == unicodedata.normalize("NFC", spelling), "source_path_alias")
            key = spelling.casefold()
            need(key not in self.spellings or self.spellings[key] == spelling, "source_path_alias")
            self.spellings[key] = spelling
        state = path_state(path, directory=directory, optional=optional)
        name = path.relative_to(self.root).as_posix()
        self.entries.add(name)
        need(len(self.entries) <= MAX_ENTRIES, "source_limit")
        need(name not in self.states or self.states[name] == state, "source_changed")
        self.states[name] = state
        if state[0][1] is not None:
            need(str(path) == str(path.resolve(strict=True)), "source_path_alias")
        return state[0][1] is not None

    def file(self, path):
        self.track(path)
        name = path.relative_to(self.root).as_posix()
        if name not in self.names:
            size = path.lstat().st_size
            need(size <= MAX_FILE_BYTES, "source_limit")
            self.total += size
            need(self.total <= MAX_TOTAL_BYTES, "source_limit")
            self.names.add(name)
        return name

    def children(self, path):
        self.track(path, directory=True)
        result, aliases = [], set()
        with os.scandir(path) as entries:
            for entry in entries:
                self.entries.add(Path(entry.path).relative_to(self.root).as_posix())
                need(len(self.entries) <= MAX_ENTRIES, "source_limit")
                name = entry.name
                need(name == unicodedata.normalize("NFC", name) and name.rstrip(" .") == name and
                     name.casefold() not in aliases, "source_path_alias")
                aliases.add(name.casefold())
                result.append(Path(entry.path))
        return sorted(result)

    def literal(self, package, value):
        need(type(value) is str and value and not any(c in value for c in ("\\", ":", "\0")) and
             value == unicodedata.normalize("NFC", value) and not value.startswith("/"))
        need(all(part and part not in {"."} and (part == ".." or part.rstrip(" .") == part)
                 for part in value.split("/")), "source_path_alias")
        ordinary = False
        for part in value.split("/"):
            if part == "..":
                need(not ordinary, "source_path_alias")
            else:
                ordinary = True
        path = Path(os.path.abspath(package / value))
        need(path.is_relative_to(self.root), "source_escape")
        self.check_reserved(path)
        self.declared.add(path)
        return path

    def check_reserved(self, path):
        need(not any(path.is_relative_to(p / "target") for p in self.packages), "source_reserved_path")

    def reserve(self, package):
        need(len(self.packages) < MAX_PACKAGES, "source_limit")
        need(not any(package != p and (package.is_relative_to(p) or p.is_relative_to(package))
                     for p in self.packages), "source_overlapping_packages")
        self.packages.add(package)
        for path in self.declared | self.packages:
            self.check_reserved(path)
        target = package / "target"
        self.track(target, directory=True, optional=True)
        # Only identities/presence, never target timestamps, size or descendants.
        self.excluded[target.relative_to(self.root).as_posix()] = self.states[target.relative_to(self.root).as_posix()]

    def toml(self, path):
        name = self.file(path)
        data = self.reader(path, MAX_FILE_BYTES, content=True)
        need(type(data) is bytes and len(data) <= MAX_FILE_BYTES, "source_limit")
        self.captured[name] = hashlib.sha256(data).hexdigest()
        try:
            value = tomllib.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise SourceSnapshotError("source_manifest_invalid") from None
        need(path_state(path) == self.states[name], "source_changed")
        return value

    def config(self):
        # Only the checked-in application config is supported. Ancestor and local
        # package configs are rejected rather than silently changing path policy.
        need(not any(os.environ.get(name) for name in ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR")), "source_config_unsupported")
        app = self.root / APP
        value = self.toml(app / ".cargo/config.toml")
        need(set(value) <= {"target"}, "source_config_unsupported")
        targets = value.get("target", {})
        need(type(targets) is dict, "source_config_unsupported")
        for entry in targets.values():
            need(type(entry) is dict and set(entry) <= {"rustflags", "linker"}, "source_config_unsupported")
            need("linker" not in entry or type(entry["linker"]) is str, "source_config_unsupported")
            need("rustflags" not in entry or type(entry["rustflags"]) is list and
                 all(type(v) is str for v in entry["rustflags"]), "source_config_unsupported")
        for package in self.packages:
            for ancestor in (package, *package.parents):
                if not ancestor.is_relative_to(self.root):
                    break
                for basename in ("config", "config.toml"):
                    path = ancestor / ".cargo" / basename
                    if path != app / ".cargo/config.toml":
                        need(not self.track(path, optional=True), "source_config_unsupported")
                if ancestor not in self.packages:
                    need(not self.track(ancestor / "Cargo.toml", optional=True), "source_workspace_unsupported")

    def source_entry(self, package, literal):
        path = self.literal(package, literal)
        if package == self.root / APP:
            need(path.is_relative_to(package / "src") or path == package / "build.rs", "source_entry_outside_policy")
        else:
            need(path.is_relative_to(package), "source_entry_outside_policy")
        self.file(path)

    def visit(self, package):
        need(package not in self.visiting, "source_dependency_cycle")
        if package in self.finished:
            return
        if package not in self.packages:
            self.reserve(package)
        self.track(package, directory=True)
        self.visiting.add(package)
        value = self.toml(package / "Cargo.toml")
        need(not set(value) & {"workspace", "patch", "replace"}, "source_manifest_unsupported")
        metadata = value.get("package")
        need(type(metadata) is dict and type(metadata.get("name")) is str and
             "workspace" not in metadata and not any(type(v) is dict and "workspace" in v for v in metadata.values()),
             "source_workspace_unsupported")
        tables = [value]
        targets = value.get("target", {})
        need(type(targets) is dict, "source_manifest_invalid")
        for target in targets.values():
            need(type(target) is dict and set(target) <= set(DEPENDENCIES), "source_manifest_unsupported")
            tables.append(target)
        dependencies = set()
        for table in tables:
            for group in DEPENDENCIES:
                entries = table.get(group, {})
                need(type(entries) is dict, "source_manifest_invalid")
                for dependency in entries.values():
                    need(type(dependency) in (str, dict), "source_manifest_invalid")
                    if type(dependency) is dict:
                        need(not set(dependency) & {"workspace", "artifact", "lib", "target"}, "source_dependency_unsupported")
                        if "path" in dependency:
                            need(not set(dependency) & {"git", "branch", "rev", "tag", "registry"}, "source_dependency_unsupported")
                            dependencies.add(self.literal(package, dependency["path"]))
        for dependency in sorted(dependencies):
            if dependency not in self.packages:
                self.reserve(dependency)
        for target in ("lib", "bin", "example", "test", "bench"):
            entries = [value[target]] if target == "lib" and target in value else value.get(target, [])
            need(type(entries) is list, "source_manifest_invalid")
            for entry in entries:
                need(type(entry) is dict, "source_manifest_invalid")
                path = entry.get("path", "src/lib.rs" if target == "lib" else None)
                self.source_entry(package, path)
        build = metadata.get("build", None)
        need(build is None or type(build) in (str, bool), "source_manifest_invalid")
        if type(build) is str:
            self.source_entry(package, build)
        # Check standard entry locations as paths too, including optional absence.
        for name in ("src/lib.rs", "src/main.rs", "build.rs"):
            path = package / name
            self.check_reserved(path)
            if self.track(path, optional=True):
                self.source_entry(package, name)
        for dependency in sorted(dependencies):
            self.visit(dependency)
        self.visiting.remove(package)
        self.finished.add(package)

    def walk(self, path, package):
        for child in self.children(path):
            if path == package and child.name.casefold() == "target":
                need(child.name == "target", "source_path_alias")
            if child == package / "target":
                continue
            info = child.lstat()
            need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400)
            if stat.S_ISDIR(info.st_mode):
                self.walk(child, package)
            else:
                self.file(child)

    def collect(self):
        app = self.root / APP
        self.visit(app)
        self.config()
        for name in FIXED:
            self.file(app / name)
        self.walk(app / "src", app)
        need(any(name.startswith(APP + "/src/") for name in self.names), "source_empty")
        for package in sorted(self.packages - {app}):
            self.walk(package, package)
        return self


class Snapshot:
    """Keep ephemeral identities until the outer binding operation finishes."""
    def __init__(self, root, reader=read_file):
        try:
            self.first = Inventory(root, reader).collect()
            self.rows = [[name, self.first.captured[name] if name in self.first.captured else
                          reader(self.first.root / name, MAX_FILE_BYTES)] for name in sorted(self.first.names)]
            self.assert_current()
        except OSError:
            raise SourceSnapshotError("source_unreadable") from None

    def assert_current(self):
        try:
            first = self.first
            final = Inventory(first.root, first.reader).collect()
            need(first.names == final.names and first.packages == final.packages and first.declared == final.declared and
                 first.captured == final.captured and first.states == final.states and first.excluded == final.excluded,
                 "source_changed")
        except OSError:
            raise SourceSnapshotError("source_unreadable") from None


def source_rows(root, reader=read_file):
    """Discover from captured manifests, hash stable inputs, then rescan exactly."""
    return Snapshot(root, reader).rows
