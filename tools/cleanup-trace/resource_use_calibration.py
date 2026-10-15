"""Closed libtest selection and independent synthetic RM calibration validation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import select_artifacts as artifacts

PREFIX = b"runtime_resource_use_calibration="
TEST = "resource_use_calibration::tests::hosted_held_file_then_closed"
BOUND = 4 * 1024 * 1024
KEYS = {"schema", "scope", "causal_owner", "runtime_executed", "hard_deadline", "setup", "creator_closed", "held", "released",
        "handle_closed", "identity_closed", "file_removed", "directory_closed", "directory_removed", "cleanup_complete", "reason", "passed"}
PHASE_KEYS = {"available", "api", "identity", "total", "caller"}
BINDINGS = {"commit", "source_tree", "source_sha256", "harness_sha256", "cargo_json_sha256",
            "runtime_manifest_sha256", "expected_runtime_sha256"}


def digest(value, width=64):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{" + str(width) + "}", value) is None:
        raise ValueError("binding_invalid")
    return value


def select(raw, project):
    if type(raw) is not bytes or not 0 < len(raw) <= artifacts.MAX_JSON:
        raise ValueError("cargo_bound")
    root = artifacts.windows_path(project)
    release = root + "\\target\\aarch64-pc-windows-msvc\\release\\deps\\"
    lines = raw.splitlines()
    if not 1 <= len(lines) <= 10000:
        raise ValueError("cargo_records")
    chosen, finished = None, 0
    for index, line in enumerate(lines):
        value = json.loads(line, object_pairs_hook=artifacts.unique_object)
        if type(value) is not dict:
            raise ValueError("cargo_object")
        if value.get("reason") == "build-finished":
            if value.get("success") is not True or index != len(lines) - 1:
                raise ValueError("cargo_completion")
            finished += 1
        if value.get("reason") != "compiler-artifact" or value.get("manifest_path") is None:
            continue
        if artifacts.windows_path(value["manifest_path"]) != root + "\\Cargo.toml":
            continue
        target, profile = value["target"], value["profile"]
        if target["name"] != "triage_cleanup_trace":
            continue
        if profile["test"] is not True and value.get("executable") is None:
            continue
        if (chosen is not None or target["kind"] != ["lib"] or target["crate_types"] != ["lib"]
                or artifacts.windows_path(target["src_path"]) != root + "\\src\\lib.rs"
                or profile["test"] is not True or profile["opt_level"] != "3"
                or profile["debug_assertions"] is not False or profile["overflow_checks"] is not False
                or type(value["features"]) is not list or value["features"] != []):
            raise ValueError("calibration_artifact")
        executable = artifacts.windows_path(value["executable"])
        if re.fullmatch(re.escape(release) + r"triage_cleanup_trace-[0-9a-f]{16}\.exe", executable) is None:
            raise ValueError("calibration_location")
        if type(value["filenames"]) is not list or executable not in [artifacts.windows_path(p) for p in value["filenames"]]:
            raise ValueError("calibration_filename")
        chosen = executable
    if chosen is None or finished != 1:
        raise ValueError("calibration_artifact_count")
    return dict(schema=1, artifact_kind="resource_use_calibration", test_harness=chosen,
                cargo_json_sha256=hashlib.sha256(raw).hexdigest())


def phase(value):
    if type(value) is not dict or value.keys() != PHASE_KEYS or type(value["available"]) is not bool:
        raise ValueError("phase_shape")
    api, identity = value["api"], value["identity"]
    if (type(api) is not list or len(api) != 4 or any(x is not None and (type(x) is not int or not 0 <= x <= 0xffffffff) for x in api)
            or type(identity) is not list or len(identity) != 4 or any(x is not None and type(x) is not bool for x in identity)
            or any(x is None for x in identity[:2])):
        raise ValueError("phase_types")
    if not all(identity[:2]):
        if api != [None] * 4 or identity[2:] != [None] * 2: raise ValueError("probe_order")
    elif api[0] is None:
        raise ValueError("start_missing")
    elif api[0] != 0:
        if api[1:] != [None] * 3 or identity[2:] != [None] * 2: raise ValueError("start_order")
    else:
        if api[1] is None or api[3] is None or None in identity[2:]: raise ValueError("end_obligation")
        if (api[1] != 0 and api[2] is not None) or (api[1] == 0 and api[2] is None): raise ValueError("register_order")
    if value["available"]:
        if (api != [0] * 4 or identity != [True] * 4 or type(value["total"]) is not int
                or not 0 <= value["total"] <= 64 or type(value["caller"]) is not bool
                or value["caller"] and value["total"] == 0): raise ValueError("available_counts")
    elif value["total"] is not None or value["caller"] is not None:
        raise ValueError("unavailable_counts")
    return identity[1] and (api[0] != 0 or api[3] == 0 and identity[3])


def validate(stderr, stdout, test_exit, bindings):
    if any(type(x) is not bytes or not 0 < len(x) <= BOUND for x in (stderr, stdout)):
        raise ValueError("log_bound")
    if type(bindings) is not dict or bindings.keys() != BINDINGS:
        raise ValueError("bindings_shape")
    for key, value in bindings.items(): digest(value, 40 if key in {"commit", "source_tree"} else 64)
    records = [line[len(PREFIX):] for line in stderr.splitlines() if line.startswith(PREFIX)]
    if len(records) != 1 or any(line.startswith(b"runtime_cleanup_") for line in stderr.splitlines()):
        raise ValueError("record_count")
    raw = records[0]
    if len(raw) + len(PREFIX) + 1 > 1024: raise ValueError("record_bound")
    value = json.loads(raw, object_pairs_hook=artifacts.unique_object)
    if type(value) is not dict or value.keys() != KEYS: raise ValueError("shape")
    fixed = dict(schema=1, scope="synthetic_rm_calibration", causal_owner=False, runtime_executed=False, hard_deadline=False)
    for key, expected in fixed.items():
        if type(value[key]) is not type(expected) or value[key] != expected: raise ValueError("scope")
    flags = ("setup", "creator_closed", "handle_closed", "identity_closed", "file_removed", "directory_closed", "directory_removed", "cleanup_complete", "passed")
    if any(type(value[key]) is not bool for key in flags): raise ValueError("flags")
    held, released = value["held"], value["released"]
    closed = False
    if value["setup"]:
        if not value["creator_closed"]: raise ValueError("creator_close")
        closed = phase(held)
        if held["available"] and value["handle_closed"]:
            closed = phase(released) and closed
        elif released is not None: raise ValueError("second_query_gate")
        cleanup = closed and all(value[k] for k in ("handle_closed", "identity_closed", "file_removed", "directory_closed", "directory_removed"))
        expected = ("cleanup_unverified" if not cleanup else "held_query_unavailable" if not held["available"]
                    else "caller_not_observed" if (held["total"], held["caller"]) != (1, True)
                    else "released_query_unavailable" if released is None or not released["available"]
                    else "control_not_empty" if (released["total"], released["caller"]) != (0, False) else "none")
        if value["reason"] != expected: raise ValueError("reason")
    else:
        if held is not None or released is not None or value["reason"] not in {"setup", "environment"}: raise ValueError("pre_query")
        cleanup = False
        if value["reason"] == "environment" and any(value[k] for k in flags): raise ValueError("environment_observations")
    if value["cleanup_complete"] != cleanup or value["passed"] != (value["reason"] == "none"):
        raise ValueError("qualification")
    if type(test_exit) is not int or test_exit != (0 if value["passed"] else 101): raise ValueError("test_exit")
    lines = stdout.decode("utf-8").splitlines()
    label = "ok" if value["passed"] else "FAILED"
    if ([line for line in lines if line.startswith("running ")] != ["running 1 test"]
            or [line for line in lines if line.startswith("test ") and not line.startswith("test result:")] != [f"test {TEST} ... {label}"]):
        raise ValueError("test_identity")
    results = [line for line in lines if line.startswith("test result:")]
    counts = "1 passed; 0 failed" if value["passed"] else "0 passed; 1 failed"
    if len(results) != 1 or re.fullmatch(re.escape(f"test result: {label}. {counts}; 0 ignored; 0 measured; ") + r"[0-9]{1,6} filtered out; finished in [0-9]+(?:\.[0-9]+)?s", results[0]) is None:
        raise ValueError("test_summary")
    return dict(schema=1, status="calibrated" if value["passed"] else "unavailable", scope="synthetic_rm_calibration",
                causal_pr115_owner=False, runtime_observed=False, test=TEST, test_native_exit=test_exit,
                bindings=bindings, observation=value, observation_sha256=hashlib.sha256(raw).hexdigest())


def read(path, bound):
    with path.open("rb") as stream: return stream.read(bound + 1)


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_subparsers(dest="mode", required=True)
    choice = mode.add_parser("select"); choice.add_argument("--cargo-json", type=Path, required=True); choice.add_argument("--project", required=True)
    choice = mode.add_parser("validate")
    for key in ("stderr", "stdout", "report"): choice.add_argument("--" + key, type=Path, required=True)
    choice.add_argument("--test-exit", type=int, required=True)
    for key in sorted(BINDINGS): choice.add_argument("--" + key.replace("_", "-"), required=True)
    args = parser.parse_args()
    try:
        if args.mode == "select":
            result = select(read(args.cargo_json, artifacts.MAX_JSON), args.project)
        else:
            result = validate(read(args.stderr, BOUND), read(args.stdout, BOUND), args.test_exit,
                              {key: getattr(args, key) for key in BINDINGS})
            payload = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
            if len(payload) > 8192: raise ValueError("report_bound")
            with args.report.open("xb") as stream: stream.write(payload)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if args.mode == "select" or result["status"] == "calibrated" else 1
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        try: print('{"schema":1,"status":"invalid","reason":"calibration_validation_failed"}')
        except BaseException: pass
        return 2

if __name__ == "__main__": raise SystemExit(main())
