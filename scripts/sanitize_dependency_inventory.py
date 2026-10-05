"""Publish only dependency identity/graph fields from private Cargo metadata."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_LOCK_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_PACKAGES = 10000
MAX_EDGES = 200000
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z", re.ASCII)
VERSION = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z", re.ASCII,
)
CODES = frozenset({
    "metadata_size", "lock_size", "metadata_json", "metadata_duplicate_key",
    "metadata_schema", "package_invalid", "package_duplicate", "graph_invalid",
    "graph_reference", "graph_incomplete", "workspace_invalid", "input_limit",
    "output_limit", "input_file", "output_file", "output_cleanup_failed",
    "arguments_invalid", "inventory_internal",
})


class InventoryError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in CODES else "inventory_internal"
        super().__init__(self.code)


def require(condition, code):
    if not condition:
        raise InventoryError(code)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "metadata_duplicate_key")
        value[key] = item
    return value


def reject_constant(_value):
    raise InventoryError("metadata_json")


def raw_id(value):
    require(type(value) is str and 0 < len(value) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 for c in value),
            "graph_invalid")
    return value


def reference_list(value, known, code):
    require(type(value) is list and len(value) <= MAX_PACKAGES, code)
    result = [raw_id(item) for item in value]
    require(len(set(result)) == len(result), code)
    require(all(item in known for item in result), code)
    return result


def serialize(value):
    data = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2)
            + "\n").encode("ascii")
    require(len(data) <= MAX_OUTPUT_BYTES, "output_limit")
    return data


def sanitize_metadata(metadata_bytes, lock_bytes):
    """Return a fresh allowlist object. A lock hash is a binding, not a consistency audit."""
    require(type(metadata_bytes) is bytes and 0 < len(metadata_bytes) <= MAX_METADATA_BYTES,
            "metadata_size")
    require(type(lock_bytes) is bytes and 0 < len(lock_bytes) <= MAX_LOCK_BYTES, "lock_size")
    try:
        data = json.loads(metadata_bytes.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
    except InventoryError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise InventoryError("metadata_json") from None
    require(type(data) is dict and type(data.get("version")) is int
            and data["version"] == 1, "metadata_schema")
    packages = data.get("packages")
    resolve = data.get("resolve")
    require(type(packages) is list and 0 < len(packages) <= MAX_PACKAGES, "input_limit")
    require(type(resolve) is dict and "root" in resolve, "graph_invalid")
    known = {}
    for index, package in enumerate(packages):
        require(type(package) is dict, "package_invalid")
        name, version = package.get("name"), package.get("version")
        require(type(name) is str and NAME.fullmatch(name) is not None, "package_invalid")
        require(type(version) is str and len(version) <= 128
                and VERSION.fullmatch(version) is not None, "package_invalid")
        identity = raw_id(package.get("id"))
        require(identity not in known, "package_duplicate")
        known[identity] = (name, version, index)
    # Never expose a raw ID or derive a public ID by hashing private path/source text.
    ordered = sorted(known, key=lambda identity: known[identity])
    public_ids = {identity: f"pkg{index:06d}" for index, identity in enumerate(ordered, 1)}
    nodes = resolve.get("nodes")
    require(type(nodes) is list and len(nodes) == len(known), "graph_incomplete")
    graphs = {}
    edge_count = 0
    for node in nodes:
        require(type(node) is dict, "graph_invalid")
        identity = raw_id(node.get("id"))
        require(identity in known and identity not in graphs, "graph_incomplete")
        flat = reference_list(node.get("dependencies"), known, "graph_reference")
        dependencies = node.get("deps")
        require(type(dependencies) is list, "graph_invalid")
        edge_count += len(dependencies)
        require(edge_count <= MAX_EDGES, "input_limit")
        by_package = {}
        for edge in dependencies:
            require(type(edge) is dict, "graph_invalid")
            target = raw_id(edge.get("pkg"))
            require(target in known, "graph_reference")
            kinds = edge.get("dep_kinds")
            require(type(kinds) is list and len(kinds) > 0, "graph_invalid")
            edge_count += len(kinds)
            require(edge_count <= MAX_EDGES, "input_limit")
            observed = by_package.setdefault(target, set())
            for kind in kinds:
                require(type(kind) is dict and "kind" in kind, "graph_invalid")
                value = kind["kind"]
                require(value is None or type(value) is str and value in {"build", "dev"},
                        "graph_invalid")
                observed.add("normal" if value is None else value)
        require(set(flat) == set(by_package), "graph_reference")
        graphs[identity] = [
            {"package_id": public_ids[target], "kinds": sorted(kinds)}
            for target, kinds in sorted(by_package.items(), key=lambda item: public_ids[item[0]])
        ]
    require(set(graphs) == set(known), "graph_incomplete")
    root = resolve["root"]
    if root is not None:
        root = raw_id(root)
        require(root in known, "graph_reference")
    members = reference_list(data.get("workspace_members"), known, "workspace_invalid")
    defaults = reference_list(data.get("workspace_default_members"), known, "workspace_invalid")
    require(len(members) > 0 and set(defaults) <= set(members), "workspace_invalid")
    result = {
        "schema_version": 1,
        "scope": "cargo_dependency_inventory",
        "cargo_metadata_version": 1,
        "lockfile_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "packages": [{"id": public_ids[identity], "name": known[identity][0],
                      "version": known[identity][1], "dependencies": graphs[identity]}
                     for identity in ordered],
        "resolve_root": public_ids[root] if root is not None else None,
        "workspace_members": sorted(public_ids[item] for item in members),
        "workspace_default_members": sorted(public_ids[item] for item in defaults),
        "limitations": {
            "source_identities_omitted": True,
            "target_conditions_omitted": True,
            "features_omitted": True,
            "build_usage_verified": False,
            "vulnerability_status_verified": False,
            "lockfile_consistency_verified": False,
        },
    }
    serialize(result)
    return result


def read_input(path, limit):
    try:
        value = Path(path)
        require(value.is_absolute() and not value.is_symlink(), "input_file")
        with value.open("rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, "input_file")
            data = stream.read(limit + 1)
        require(0 < len(data) <= limit, "input_file")
        return data
    except InventoryError:
        raise
    except (OSError, ValueError):
        raise InventoryError("input_file") from None


def read_metadata(path):
    if path != "-":
        return read_input(path, MAX_METADATA_BYTES)
    try:
        data = sys.stdin.buffer.read(MAX_METADATA_BYTES + 1)
    except (OSError, ValueError):
        raise InventoryError("input_file") from None
    require(type(data) is bytes and 0 < len(data) <= MAX_METADATA_BYTES, "metadata_size")
    return data


def write_output(path, data):
    if path == "-":
        try:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            return
        except (OSError, ValueError):
            raise InventoryError("output_file") from None
    value = Path(path)
    require(value.is_absolute(), "output_file")
    created = False
    try:
        with value.open("xb") as stream:
            created = True
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, ValueError):
        if created:
            try:
                value.unlink()
            except OSError:
                raise InventoryError("output_cleanup_failed") from None
        raise InventoryError("output_file") from None


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise InventoryError("arguments_invalid")


def main(argv=None):
    parser = PrivateArgumentParser(description=__doc__)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--lockfile", required=True)
    parser.add_argument("--output", required=True)
    try:
        args = parser.parse_args(argv)
        result = sanitize_metadata(read_metadata(args.metadata),
                                   read_input(args.lockfile, MAX_LOCK_BYTES))
        write_output(args.output, serialize(result))
    except InventoryError as exc:
        print("dependency_inventory_failed:" + exc.code, file=sys.stderr)
        return 2
    except Exception:
        print("dependency_inventory_failed:inventory_internal", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
