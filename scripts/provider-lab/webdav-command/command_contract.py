"""Independent, closed Linux command-token evidence contract; import is inert."""
import hashlib
import json
import re

CASES = ("renewal", "refresh_denied", "initial_nonzero", "initial_empty", "cancellation")
BUDGETS = dict(zip(CASES, (60, 420, 30, 90, 120)))
MAX_HELPERS = dict(zip(CASES, (3, 102, 1, 11, 3)))
MAX_REQUESTS = dict(zip(CASES, (4, 102, 0, 10, 4)))
TOKENS = (b"synthetic-tokenA", b"synthetic-tokenB")
BODY = b"synthetic application fixture\n"
BODY_SHA = "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf"
CANCEL_SIZE = 16 * 1024 * 1024
EXTENTS = (262144, 524288)
EXTENT_SHAS = ("2312394bd99545d9de131c24efb781e765ac1aec243f2ed9347597a793a415e9", "33bc8aab40703678c3ebe94d2dd8f2afff285dd901f9234e841e4679f8204fd5")
BLOCK = bytes(range(256))
RUNTIME_SHA = "ed7ab1f17876bb006c3df3949a3044959671afd9112362dacaa5dd1647735bc1"
ERRORS = frozenset({"setup", "binding", "helper", "fixture", "deadline", "runtime", "stat", "copy", "output", "witness", "signal", "preservation", "cleanup", "unexpected"})
BINDINGS = frozenset({"source_revision", "source_sha256", "runtime_manifest_sha256", "runtime_sha256", "helper_sha256", "python_sha256"})
CLAIMS = dict(windows_application=False, provider=False, vendor=False, tls=False, ledger_eligible=False,
              helper_os_exits_independently_observed=False, helper_parent_link_independently_observed=False)
CHECKS = ("runtime_preserved", "source_preserved", "helper_preserved", "config_preserved", "control_preserved", "groups_empty", "children_reaped", "fixture_closed", "temporary_removed")


class Rejected(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Rejected(code)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def parse(raw, limit=65536):
    require(type(raw) is bytes and len(raw) <= limit, "json_bound")
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate_key")
            value[key] = item
        return value
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Rejected("json_number")))
    except (UnicodeError, json.JSONDecodeError):
        raise Rejected("json_invalid") from None


def integer(value, lo, hi):
    return type(value) is int and lo <= value <= hi


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), "shape")


def expected_helper(case, sequence):
    require(case in CASES and integer(sequence, 1, MAX_HELPERS[case]), "helper_sequence")
    action = ("deny" if case == "initial_nonzero" or (case == "refresh_denied" and sequence > 2)
              else "empty" if case == "initial_empty" else "B" if sequence == 3 else "A")
    return dict(sequence=sequence, action=action, intended_exit=70 if action == "deny" else 0,
                stdout_bytes=0 if action in ("deny", "empty") else len(TOKENS[0]) + 1,
                stderr_bytes=len(b"synthetic-command-denied\n") if action == "deny" else 0)


def expected_events(case):
    if case == "initial_nonzero":
        rows = []
    elif case == "initial_empty":
        rows = [("PROPFIND", "empty", 401, 0)] * 10
    else:
        rows = [("PROPFIND", "A", 207, 0)] * 2
        if case == "refresh_denied":
            rows += [("GET", "A", 401, 0)] * 100
        else:
            rows += [("GET", "A", 401, 0), ("GET", "B", 200, EXTENTS[-1] if case == "cancellation" else len(BODY))]
    return [dict(ordinal=i+1, method=m, credential=c, status=s, payload_bytes=b) for i, (m,c,s,b) in enumerate(rows)]


def empty_case(case):
    require(case in CASES, "case")
    return dict(case=case, status="failed", error="setup", elapsed_ms=0, children=[], helpers=[], events=[],
                helper_evidence="self_reported_completion", checks={k: None for k in CHECKS},
                output=None, cancellation=dict(signal_attempts=0, group_identity_checked=None, extents=[], reader_closed=None))


def validate_case(row):
    exact(row, ("case", "status", "error", "elapsed_ms", "children", "helpers", "events", "helper_evidence", "checks", "output", "cancellation"))
    case = row["case"]
    require(type(case) is str and case in CASES, "case")
    require(type(row["status"]) is str and row["status"] in ("passed", "failed") and (row["error"] is None or type(row["error"]) is str and row["error"] in ERRORS), "status")
    require(integer(row["elapsed_ms"], 0, 780000), "elapsed")
    require(row["helper_evidence"] == "self_reported_completion", "helper_claim")
    children = row["children"]
    require(type(children) is list and len(children) <= 2, "children")
    for index, child in enumerate(children):
        exact(child, ("role", "exit_code", "identity_checked", "reaped", "group_empty", "forced"))
        require(child["role"] == ("stat", "copy")[index], "child_order")
        require(child["exit_code"] is None or integer(child["exit_code"], -128, 255), "exit")
        for key in ("identity_checked", "reaped", "group_empty", "forced"):
            require(child[key] is None or type(child[key]) is bool, "child_flag")
    require(type(row["helpers"]) is list and len(row["helpers"]) <= MAX_HELPERS[case], "helpers")
    for i, item in enumerate(row["helpers"]):
        require(item == expected_helper(case, i+1) and all(type(item[k]) is int for k in ("sequence","intended_exit","stdout_bytes","stderr_bytes")), "helper_record")
    expected = expected_events(case)
    require(type(row["events"]) is list and len(row["events"]) <= len(expected), "events")
    for i, event in enumerate(row["events"]):
        exact(event, expected[i])
        require(all(type(event[k]) is int for k in ("ordinal", "status", "payload_bytes")), "event_type")
        # Only the final interrupted body may have sent a shorter prefix on failure.
        base = dict(event); base["payload_bytes"] = expected[i]["payload_bytes"]
        require(base == expected[i] and integer(event["payload_bytes"], 0, expected[i]["payload_bytes"]), "event")
    exact(row["checks"], CHECKS)
    require(all(v is None or type(v) is bool for v in row["checks"].values()), "checks")
    output = row["output"]
    require(output is None or output == {"kind":"exact_content", "bytes":30, "sha256":BODY_SHA} or output == {"kind":"empty", "bytes":0, "sha256":None}, "output")
    require(output is None or type(output["bytes"]) is int, "output_type")
    cancel = row["cancellation"]
    exact(cancel, ("signal_attempts", "group_identity_checked", "extents", "reader_closed"))
    require(integer(cancel["signal_attempts"], 0, 1), "signal_count")
    require(all(cancel[k] is None or type(cancel[k]) is bool for k in ("group_identity_checked","reader_closed")), "cancel_flag")
    require(type(cancel["extents"]) is list and len(cancel["extents"]) <= 2, "extents")
    for i, value in enumerate(cancel["extents"]):
        require(value == dict(bytes=EXTENTS[i], sha256=EXTENT_SHAS[i], identity_verified=True), "content_extent")
        require(type(value["bytes"]) is int and value["identity_verified"] is True, "extent_type")
    if row["status"] == "passed":
        require(row["error"] is None and row["elapsed_ms"] <= BUDGETS[case]*1000, "passed_failure")
        require(all(v is True for v in row["checks"].values()), "cleanup_or_preservation")
        require(len(children) == (1 if case.startswith("initial_") else 2), "launch_count")
        require(all(c["identity_checked"] is True and c["reaped"] is True and c["group_empty"] is True and c["forced"] is False and c["exit_code"] is not None for c in children), "native_completion")
        require((children[0]["exit_code"] != 0) == case.startswith("initial_"), "stat_result")
        if len(children) == 2:
            require((children[1]["exit_code"] == 0) == (case == "renewal"), "copy_result")
        require(len(row["helpers"]) == MAX_HELPERS[case] and row["events"] == expected, "full_sequence")
        require(output == ({"kind":"exact_content", "bytes":30, "sha256":BODY_SHA} if case == "renewal" else {"kind":"empty", "bytes":0, "sha256":None}), "final_output")
        if case == "cancellation":
            require(cancel["signal_attempts"] == 1 and cancel["group_identity_checked"] is True and cancel["reader_closed"] is True and len(cancel["extents"]) == 2, "cancel_proof")
        else:
            require(cancel == dict(signal_attempts=0, group_identity_checked=None, extents=[], reader_closed=None), "unexpected_cancel")
    else:
        require(row["error"] in ERRORS, "failure_reason")
    return row


def validate_bindings(expected_bindings):
    exact(expected_bindings, BINDINGS)
    for key, item in expected_bindings.items():
        require(type(item) is str and re.fullmatch("[a-f0-9]{40}" if key == "source_revision" else "[a-f0-9]{64}", item), "bindings")
    require(expected_bindings["runtime_sha256"]==RUNTIME_SHA, "runtime_binding")
    return expected_bindings


def validate(value, expected_bindings):
    exact(value, ("schema_version", "scope", "mode", "runtime", "bindings", "cases", "result", "claims"))
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["scope"] == "linux_network_none_protocol" and value["mode"] == "webdav_command_rc_v1", "scope")
    validate_bindings(expected_bindings)
    require(value["bindings"] == expected_bindings and expected_bindings["runtime_sha256"] == RUNTIME_SHA, "binding_mismatch")
    require(value["runtime"] == dict(version="1.75.2", platform="linux_amd64", sha256=RUNTIME_SHA), "runtime")
    require(value["claims"] == CLAIMS and all(v is False for v in value["claims"].values()), "claims")
    require(type(value["cases"]) is list and 1 <= len(value["cases"]) <= 5, "case_count")
    for index, row in enumerate(value["cases"]):
        require(row["case"] == CASES[index], "case_order"); validate_case(row)
        require(index == len(value["cases"])-1 or row["status"] == "passed", "continued_after_failure")
    passed = len(value["cases"]) == 5 and all(row["status"] == "passed" for row in value["cases"])
    require(value["result"] == ("passed" if passed else "failed"), "result")
    require(passed or value["cases"][-1]["status"] == "failed", "truncated_success")
    require(len(compact(value)) <= 65536, "report_bound")
    return value
