"""Pure Cargo JSON selection; never loads or executes a selected artifact."""
import argparse
import hashlib
import json
import re
from pathlib import Path

MAX_JSON = 16 * 1024 * 1024
TARGET = "aarch64-pc-windows-msvc"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def windows_path(value):
    if type(value) is not str or len(value) > 4096:
        raise ValueError("path type")
    value = value.replace("/", "\\")
    if not re.fullmatch(r"[A-Za-z]:\\[^\x00-\x1f:*?\"<>|]+", value):
        raise ValueError("absolute ordinary path")
    if any(part in ("", ".", "..") or part.endswith((".", " ")) for part in value[3:].split("\\")):
        raise ValueError("path component")
    return value


def select(raw, project, library_unit=False, cli_acquisition=False):
    if library_unit and cli_acquisition:
        raise ValueError("exclusive artifact mode")
    if library_unit:
        return select_library(raw, project)
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_JSON:
        raise ValueError("Cargo JSON bound")
    root = windows_path(project)
    manifest = root + "\\Cargo.toml"
    release = root + "\\target\\" + TARGET + "\\release\\"
    selected = {}
    finished = 0
    lines = raw.splitlines()
    if len(lines) > 10000:
        raise ValueError("Cargo record bound")
    for index, line in enumerate(lines):
        value = json.loads(line, object_pairs_hook=unique_object)
        if type(value) is not dict:
            raise ValueError("Cargo object")
        if value.get("reason") == "build-finished":
            if value.get("success") is not True or cli_acquisition and index != len(lines) - 1:
                raise ValueError("build failed")
            finished += 1
        if value.get("reason") != "compiler-artifact" or value.get("manifest_path") is None:
            continue
        if windows_path(value["manifest_path"]) != manifest:
            continue
        target = value["target"]
        name = target["name"]
        if name not in ("rclone-triage", "cli_acquisition"):
            continue
        # Reject a duplicate or wrong kind/profile for either expected target.
        key = "application" if name == "rclone-triage" else "test_harness"
        is_test = key == "test_harness"
        source = "tests\\cli_acquisition.rs" if is_test else "src\\main.rs"
        features = value["features"]
        if (key in selected or target["kind"] != (["test"] if is_test else ["bin"])
                or target["crate_types"] != ["bin"] or windows_path(target["src_path"]) != root + "\\" + source
                or value["profile"]["test"] is not is_test
                or type(features) is not list or sorted(features) != ["default", "runtime-cleanup-trace"]):
            raise ValueError("artifact identity")
        if cli_acquisition and (value["profile"].get("opt_level") != "3"
                or value["profile"].get("debug_assertions") is not False
                or value["profile"].get("overflow_checks") is not False):
            raise ValueError("acquisition release profile")
        executable = windows_path(value["executable"])
        if is_test:
            if not re.fullmatch(re.escape(release) + r"deps\\cli_acquisition-[0-9a-f]{16}\.exe", executable):
                raise ValueError("harness location")
        elif executable != release + "rclone-triage.exe":
            raise ValueError("application location")
        if type(value["filenames"]) is not list or executable not in [windows_path(p) for p in value["filenames"]]:
            raise ValueError("artifact filename")
        selected[key] = executable
    if finished != 1 or selected.keys() != {"application", "test_harness"}:
        raise ValueError("artifact count")
    result = dict(schema=1, **selected, cargo_json_sha256=hashlib.sha256(raw).hexdigest())
    if cli_acquisition:
        result.update(schema=3, artifact_kind="cli_acquisition")
    return result



def select_library(raw, project):
    """Closed ARM64 release libtest artifact; no CLI artifact is implied."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_JSON:
        raise ValueError("Cargo JSON bound")
    root = windows_path(project)
    release = root + "\\target\\" + TARGET + "\\release\\deps\\"
    lines = raw.splitlines()
    if not 1 <= len(lines) <= 10000:
        raise ValueError("Cargo record bound")
    selected, finished = None, 0
    for index, line in enumerate(lines):
        value = json.loads(line, object_pairs_hook=unique_object)
        if type(value) is not dict:
            raise ValueError("Cargo object")
        if value.get("reason") == "build-finished":
            if value.get("success") is not True or index != len(lines) - 1:
                raise ValueError("build failed or incomplete")
            finished += 1
        if value.get("reason") != "compiler-artifact" or value.get("manifest_path") is None:
            continue
        if windows_path(value["manifest_path"]) != root + "\\Cargo.toml":
            continue
        target = value["target"]
        if target["name"] != "rclone_triage":
            continue
        profile = value["profile"]
        if profile["test"] is not True and value.get("executable") is None:
            continue  # A non-executable library dependency cannot select a test.
        if (selected is not None or target["kind"] != ["lib"] or target["crate_types"] != ["lib"]
                or windows_path(target["src_path"]) != root + "\\src\\lib.rs"
                or profile["test"] is not True or profile["opt_level"] != "3"
                or profile["debug_assertions"] is not False or profile["overflow_checks"] is not False
                or type(value["features"]) is not list
                or sorted(value["features"]) != ["default", "runtime-cleanup-trace"]):
            raise ValueError("library artifact identity")
        executable = windows_path(value["executable"])
        if not re.fullmatch(re.escape(release) + r"rclone_triage-[0-9a-f]{16}\.exe", executable):
            raise ValueError("library harness location")
        if type(value["filenames"]) is not list or executable not in [windows_path(p) for p in value["filenames"]]:
            raise ValueError("artifact filename")
        selected = executable
    if finished != 1 or selected is None:
        raise ValueError("library artifact count")
    return dict(schema=2, artifact_kind="library_test", test_harness=selected,
                cargo_json_sha256=hashlib.sha256(raw).hexdigest())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-json", required=True, type=Path)
    parser.add_argument("--project", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--library-unit", action="store_true")
    mode.add_argument("--cli-acquisition", action="store_true")
    args = parser.parse_args()
    try:
        with args.cargo_json.open("rb") as stream:
            result = select(stream.read(MAX_JSON + 1), args.project, args.library_unit, args.cli_acquisition)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print('{"schema":1,"status":"invalid","reason":"artifact_selection_failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
