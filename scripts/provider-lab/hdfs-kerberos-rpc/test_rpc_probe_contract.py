"""Offline contracts and failure injection; no JVM, Docker, or network calls."""
import copy
from contextlib import ExitStack
from email.message import Message
import importlib.util
import io
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ticket_fixture_under_test", HERE / "rpc_probe_container.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


def varint(value):
    result = bytearray()
    while value > 127: result.append((value & 127) | 128); value >>= 7
    result.append(value); return bytes(result)


def wire_fields(overrides=None):
    # Independent literal expected wire values, not supervisor constants.
    fields = {1: 0xffffffff, 2: 2, 3: 9,
        4: b"org.apache.hadoop.security.AccessControlException",
        5: b"SIMPLE authentication is not enabled.  Available:[TOKEN, KERBEROS]",
        6: 15, 7: b"", 8: 1}
    fields.update(overrides or {})
    return fields


def wire(fields=None, suffix=b""):
    fields = wire_fields() if fields is None else fields
    header = b""
    for key, value in fields.items():
        if type(value) is bytes: header += varint(key * 8 + 2) + varint(len(value)) + value
        else: header += varint(key * 8) + varint(value)
    body = varint(len(header)) + header + suffix
    return len(body).to_bytes(4, "big") + body


def projected():
    value = positive(); del value["wire_hex"]; del value["rclone_wire_hex"]
    value["wire_oracle"] = dict(status="FATAL", detail="FATAL_UNAUTHORIZED",
        category="simple_disabled_kerberos_offered", rpc_version=9,
        endpoint="namenode_loopback", bounded_single_response=True)
    value["rclone_wire_oracle"] = value["wire_oracle"].copy()
    return value


def empty_thread_matrix():
    return {category: dict(kdc=0, owner_login=0, format=0, namenode=0, filesystem=0,
                          reader=0, controls=0, shutdown=0, unattributed=0)
            for category in ('probe_task', 'jdk_process_reaper', 'jdk_timer', 'jdk_executor', 'jdk_cleaner',
                             'hadoop_metrics', 'hadoop_rpc', 'hadoop_fs', 'hadoop_namenode',
                             'hadoop_blockmanagement', 'hadoop_util', 'jetty', 'kerby', 'other')}


def positive():
    # Independent literal wire record, including deliberately narrow evidence label.
    return dict(schema_version=1, scope="hdfs_kerberos_rpc_feasibility", success=True,
        expected_kerby_version="2.1.2", runtime_binding_required=True,
        checks=dict(environment=True, endpoint_settings=True, positive_tgt=True, file_cache_v3=True,
            nonrenewable=True, secure_namenode=True, listing_before=True, rclone_auth_boundary_rejection=True,
            wire_auth_boundary_rejection=True, listing_after=True, source_preserved=True, cache_preserved=True),
        cleanup=dict(children_reaped=True, relay_closed=True, filesystem_closed=True, namenode_stop_returned=True, owner_logged_out=True, kdc_stop_returned=True, threads_terminated=True, listeners_absent=True,
            private_material_removed=True, process_property_restored=True, cleanup_completed=True,
            gc_monitor_reaped=True, fs_statistics_cleaner_reaped=True, format_ssl_timer_reaped=True),
        owned_thread_cleanup=dict(gc_monitor='terminated', fs_statistics_cleaner='terminated', format_ssl_timer='terminated'),
        cache_bytes=400, observed_lifetime_seconds=119, stage="completed", wire_hex=wire().hex(), rclone_wire_hex=wire().hex(),
        relay=dict(before_connections=1, negative_connections=1, after_connections=1, none_headers=1,
                   fatal_responses=1, unexpected_connections=0, bytes_forwarded_unchanged=True), error=None, ledger_eligible=False,
        diagnostic=dict(category="none", origin="none"),
        remaining_threads=dict(probe_task=0, jdk_process_reaper=0, jdk_timer=0, jdk_executor=0,
            jdk_cleaner=0, hadoop_metrics=0, hadoop_rpc=0, hadoop_fs=0, hadoop_namenode=0,
            hadoop_blockmanagement=0, hadoop_util=0, jetty=0, kerby=0, other=0),
        thread_observation_complete=True,
        remaining_thread_intervals=dict(kdc=0, owner_login=0, format=0, namenode=0,
            filesystem=0, reader=0, controls=0, shutdown=0, unattributed=0),
        remaining_thread_matrix=empty_thread_matrix(),
        remaining_timer_kinds=dict(namenode_metrics=0, rpc_idle=0, snapshot_gc=0, shell_timeout=0, ssl_store=0, unknown=0),
        authentication_verified=False, hdfs_authenticated=False, renewal_verified=False,
        daemon_accepted=False, provider_accepted=False, application_accepted=False,
        vendor_accepted=False, vulnerability_audited=False)


def inspected(name, image, run_id):
    return dict(Id="c" * 64, Name="/" + name, Image=image,
        Config=dict(Labels={F.LABEL: run_id}, User="10001:10001", Entrypoint=["/usr/bin/env"],
            Cmd=["-i", "HOME=/work/home", "PATH=/opt/java/openjdk/bin:/usr/bin:/bin",
                 "JAVA_HOME=/opt/java/openjdk", "LANG=C", "LC_ALL=C", "/bin/sh", "/opt/rpc/driver.sh"]),
        HostConfig=dict(NetworkMode="none", ReadonlyRootfs=True, Privileged=False, CapDrop=["ALL"],
            SecurityOpt=["no-new-privileges"], Memory=2147483648, NanoCpus=2000000000,
            PidsLimit=128, Init=True, IpcMode="private", CgroupnsMode="private",
            Tmpfs={"/work": "rw,nosuid,nodev,noexec,size=128m,mode=0700,uid=10001,gid=10001"},
            LogConfig={"Type": "none"}), Mounts=[], State=dict(Status="created", Running=False))


class FakeDocker:
    def __init__(self, root, *, max_calls):
        assert max_calls == 40
        self.root, self.calls, self.built, self.container = root, [], None, None
        self.image = "sha256:" + "b" * 64
        self.java, self.exit_code, self.action = positive(), 0, None

    def call(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        output = b""
        if args[0] == "info": output = b'{"OSType":"linux","Architecture":"amd64"}'
        elif args[0] == "build":
            self.tag = args[args.index("--tag") + 1]
            self.run_id = args[args.index("--label") + 1].split("=", 1)[1]
            self.built = dict(Id=self.image, RepoTags=[self.tag + ":latest"],
                Config=dict(Labels={F.LABEL: self.run_id}, User="10001:10001"))
        elif args[0] == "create":
            self.container = inspected(args[args.index("--name") + 1], self.image, self.run_id)
        elif args[0] == "start":
            self.container["State"] = dict(Status="exited", Running=False, OOMKilled=False, ExitCode=self.exit_code)
            output = F.canonical(self.java)
            if self.action: self.action(self)
        elif args[:2] == ["container", "rm"]: self.container = None
        elif args[:2] == ["image", "rm"]: self.built = None
        path = self.root / ("result-%02d" % len(self.calls)); path.write_bytes(output)
        return types.SimpleNamespace(stdout=path, code=self.exit_code if args[0] == "start" else 0)

    def inspect(self, kind, reference, allow_missing=False):
        if kind == "image" and reference == F.BASE:
            return dict(Id=F.BASE_ID, Os="linux", Architecture="amd64", Config={})
        return copy.deepcopy(self.built if kind == "image" else self.container)


class TicketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(F.subprocess, "Popen", side_effect=AssertionError("native forbidden")))
        self.stack.enter_context(patch.object(F.urllib.request, "build_opener", side_effect=AssertionError("network forbidden")))

    def tearDown(self):
        try: self.stack.close()
        finally: self.temp.cleanup()

    def rejected(self, value, code=0):
        with self.assertRaisesRegex(F.ProbeError, "^java_report_invalid$"):
            F.validate_java(F.canonical(value), code)

    def test_literal_result_and_failure_are_distinct(self):
        self.assertEqual(F.validate_java(F.canonical(positive()), 0), projected())
        value = positive(); value.update(success=False, error="cleanup_failed")
        value["cleanup"]["threads_terminated"] = False
        self.assertFalse(F.validate_java(F.canonical(value), 1)["success"])
        self.rejected(value, 0)

    def test_closed_result_types_scopes_and_no_coverage_promotion(self):
        for field, bad in (("schema_version", True), ("cache_bytes", True), ("success", 1),
                           ("observed_lifetime_seconds", 119.0), ("authentication_verified", True),
                           ("scope", "provider_acceptance"), ("error", "private diagnostic"),
                           ("expected_kerby_version", "2.0.3"), ("extra", "private")):
            with self.subTest(field=field):
                value = positive(); value[field] = bad; self.rejected(value)
        value = positive(); value["checks"]["wrong_password_denied"] = value["checks"].pop("rclone_auth_boundary_rejection")
        self.rejected(value)
        value = positive(); value["cleanup"]["threads_terminated"] = 1; self.rejected(value)
        self.rejected(positive(), True)

    def test_corrupt_json_and_duplicate_fields_never_pass(self):
        for raw in (b"{}\n{}", b'{"success":true,"success":false}', b'{"value":NaN}', b"x" * 16385, b"\xff"):
            with self.subTest(raw=raw[:20]), self.assertRaises(F.ProbeError): F.validate_java(raw, 0)

    def startup_failure(self):
        value = positive(); value.update(success=False, error="unclassified", stage="namenode_start",
            wire_hex="", rclone_wire_hex="", relay=None, cache_bytes=0, observed_lifetime_seconds=0,
            diagnostic=dict(category="metrics_failure", origin="hadoop_metrics"))
        for key in value["checks"]: value["checks"][key] = key in ("environment", "endpoint_settings")
        value["remaining_threads"]["hadoop_metrics"] = 1
        value["remaining_thread_intervals"]["unattributed"] = 1
        value["remaining_thread_matrix"]["hadoop_metrics"]["unattributed"] = 1
        value["thread_observation_complete"] = False
        value["cleanup"].update(threads_terminated=False, private_material_removed=False)
        return value

    def test_finite_startup_diagnostic_and_residual_threads_never_grant_credit(self):
        value = self.startup_failure()
        result = F.validate_java(F.canonical(value), 1)
        self.assertEqual(result["diagnostic"], dict(category="metrics_failure", origin="hadoop_metrics"))
        self.assertEqual(result["remaining_threads"]["hadoop_metrics"], 1)
        self.assertFalse(result["success"])
        for key in ("threads_terminated", "private_material_removed"):
            self.assertIs(result["cleanup"][key], False)
        self.assertTrue(all(result[key] is False for key in F.JAVA_FALSE))
        self.rejected(value, 0)

    def test_diagnostic_schema_rejects_raw_unknown_and_incomplete_values(self):
        for bad in (None, {}, {"category": "metrics_failure"},
                    {"category": "none", "origin": "none"},
                    {"category": "private diagnostic", "origin": "none"},
                    {"category": "metrics_failure", "origin": "org.example.Private.method"},
                    {"category": True, "origin": "none"},
                    {"category": "metrics_failure", "origin": "none", "message": "private"}):
            value = self.startup_failure(); value["diagnostic"] = bad
            with self.subTest(bad=bad): self.rejected(value, 1)
        for field in ("diagnostic", "remaining_threads"):
            value = self.startup_failure(); del value[field]; self.rejected(value, 1)
        for category in F.DIAGNOSTIC_CATEGORIES - {"none"}:
            value = self.startup_failure(); value["diagnostic"]["category"] = category
            self.assertFalse(F.validate_java(F.canonical(value), 1)["success"])
            value = positive(); value["diagnostic"]["category"] = category; self.rejected(value)

    def test_thread_count_vector_is_closed_bounded_and_cannot_clear_cleanup_failure(self):
        for bad in (True, -1, 129, 1.0, "1"):
            value = self.startup_failure(); value["remaining_threads"]["other"] = bad
            with self.subTest(bad=bad): self.rejected(value, 1)
        for bad in ({}, [], {"private_thread_name": 1}):
            value = self.startup_failure(); value["remaining_threads"] = bad; self.rejected(value, 1)
        value = self.startup_failure(); value["remaining_threads"]["other"] = 128; self.rejected(value, 1)
        for category in positive()["remaining_threads"]:
            value = positive(); value["remaining_threads"][category] = 1; self.rejected(value)
        value = positive(); value["remaining_threads"] = None; self.rejected(value)
        value = self.startup_failure(); value["remaining_threads"] = None; value["remaining_thread_intervals"] = None
        value["remaining_thread_matrix"] = None
        value["remaining_timer_kinds"] = None
        self.assertFalse(F.validate_java(F.canonical(value), 1)["cleanup"]["threads_terminated"])
        value["remaining_threads"] = positive()["remaining_threads"]
        value["remaining_thread_intervals"] = positive()["remaining_thread_intervals"]
        value["remaining_thread_matrix"] = empty_thread_matrix()
        value["remaining_timer_kinds"] = positive()["remaining_timer_kinds"]
        self.assertFalse(F.validate_java(F.canonical(value), 1)["cleanup"]["threads_terminated"])

    def test_new_thread_categories_only_subdivide_failing_residuals(self):
        for category in ('hadoop_fs', 'hadoop_namenode', 'hadoop_blockmanagement', 'hadoop_util', 'jdk_cleaner'):
            value = self.startup_failure(); value['remaining_threads'] = positive()['remaining_threads']
            value['remaining_threads'][category] = 3
            value['remaining_thread_intervals']['unattributed'] = 3
            value['remaining_thread_matrix'] = empty_thread_matrix()
            value['remaining_thread_matrix'][category]['unattributed'] = 3
            result = F.validate_java(F.canonical(value), 1)
            self.assertEqual(sum(result['remaining_threads'].values()), 3)
            self.assertFalse(result['cleanup']['threads_terminated'])
            self.assertFalse(result['cleanup']['private_material_removed'])
            value['cleanup']['threads_terminated'] = True; self.rejected(value, 1)
    def test_result_lifetime_cache_and_success_contradictions(self):
        for field, bad in (("cache_bytes", 100), ("cache_bytes", 65537), ("observed_lifetime_seconds", 109),
                           ("observed_lifetime_seconds", 121), ("success", False)):
            value = positive(); value[field] = bad; self.rejected(value)
        value = positive(); value["cleanup"]["listeners_absent"] = False; self.rejected(value)
        value = positive(); value["checks"]["positive_tgt"] = False; self.rejected(value)

    def test_thread_intervals_are_closed_bounded_and_sum_to_all_residuals(self):
        for field in ('remaining_thread_intervals', 'thread_observation_complete'):
            value = self.startup_failure(); del value[field]; self.rejected(value, 1)
        for bad in (None, {}, [], {'private thread name': 1}):
            value = self.startup_failure(); value['remaining_thread_intervals'] = bad; self.rejected(value, 1)
        for bad in (True, -1, 129, 0.5, '1'):
            value = self.startup_failure(); value['remaining_thread_intervals']['unattributed'] = bad
            self.rejected(value, 1)
        value = self.startup_failure(); value['remaining_thread_intervals']['unattributed'] = 0; self.rejected(value, 1)
        value = self.startup_failure(); value['thread_observation_complete'] = 1; self.rejected(value, 1)
        value = self.startup_failure(); value['remaining_threads'] = None; self.rejected(value, 1)
        for phase in positive()['remaining_thread_intervals']:
            value = self.startup_failure(); value['thread_observation_complete'] = True
            value['remaining_thread_intervals'] = positive()['remaining_thread_intervals']
            value['remaining_thread_intervals'][phase] = 1
            value['remaining_thread_matrix'] = empty_thread_matrix()
            value['remaining_thread_matrix']['hadoop_metrics'][phase] = 1
            result = F.validate_java(F.canonical(value), 1)
            self.assertEqual(sum(result['remaining_threads'].values()), sum(result['remaining_thread_intervals'].values()))
            self.assertFalse(result['cleanup']['threads_terminated'])
            self.assertFalse(result['success'])

    def test_incomplete_observation_reports_unknown_and_never_passes(self):
        value = self.startup_failure()
        self.assertFalse(F.validate_java(F.canonical(value), 1)['thread_observation_complete'])
        value['remaining_thread_intervals'].update(unattributed=0, kdc=1)
        value['remaining_thread_matrix']['hadoop_metrics'].update(unattributed=0, kdc=1); self.rejected(value, 1)
        value = positive(); value['thread_observation_complete'] = False; self.rejected(value)
        value.update(success=False, error='cleanup_failed')
        self.assertFalse(F.validate_java(F.canonical(value), 1)['success'])

    def test_thread_matrix_preserves_joint_attribution_and_strict_cleanup(self):
        value = positive(); value.update(success=False, error='cleanup_failed')
        value['cleanup'].update(threads_terminated=False, private_material_removed=False)
        expected = [('hadoop_fs', 'format'), ('hadoop_util', 'kdc'), ('jdk_timer', 'namenode')]
        for category, phase in expected:
            value['remaining_threads'][category] = 1
            value['remaining_thread_intervals'][phase] = 1
            value['remaining_thread_matrix'][category][phase] = 1
        value['remaining_timer_kinds']['unknown'] = 1
        result = F.validate_java(F.canonical(value), 1)
        self.assertEqual(sum(sum(row.values()) for row in result['remaining_thread_matrix'].values()), 3)
        for category, phase in expected: self.assertEqual(result['remaining_thread_matrix'][category][phase], 1)
        self.assertFalse(result['success']); self.assertFalse(result['cleanup']['threads_terminated'])
        value['thread_observation_complete'] = False; self.rejected(value, 1)
        value['remaining_thread_intervals'] = positive()['remaining_thread_intervals']
        value['remaining_thread_intervals']['unattributed'] = 3
        value['remaining_thread_matrix'] = empty_thread_matrix()
        for category, _ in expected: value['remaining_thread_matrix'][category]['unattributed'] = 1
        result = F.validate_java(F.canonical(value), 1)
        self.assertFalse(result['success']); self.assertFalse(result['thread_observation_complete'])
        self.assertEqual(result['remaining_thread_intervals']['unattributed'], 3)

    def test_thread_matrix_rejects_row_column_and_total_mismatches(self):
        value = self.startup_failure()
        # Equal overall/column totals cannot conceal a different category.
        value['remaining_thread_matrix']['hadoop_metrics']['unattributed'] = 0
        value['remaining_thread_matrix']['hadoop_fs']['unattributed'] = 1
        self.rejected(value, 1)
        value = self.startup_failure(); value['thread_observation_complete'] = True
        # Equal overall/row totals cannot conceal a different interval.
        value['remaining_thread_matrix']['hadoop_metrics'].update(unattributed=0, kdc=1)
        self.rejected(value, 1)
        for count in (0, 2, 129):
            value = self.startup_failure(); value['remaining_thread_matrix']['hadoop_metrics']['unattributed'] = count
            self.rejected(value, 1)
        value = self.startup_failure()
        value['remaining_threads']['hadoop_metrics'] = 129
        value['remaining_thread_intervals']['unattributed'] = 129
        value['remaining_thread_matrix']['hadoop_metrics']['unattributed'] = 129
        self.rejected(value, 1)

    def test_thread_matrix_rejects_malformed_missing_unknown_or_raw_fields(self):
        value = self.startup_failure(); del value['remaining_thread_matrix']; self.rejected(value, 1)
        for bad in (None, {}, [], {'private thread': {}}, True):
            value = self.startup_failure(); value['remaining_thread_matrix'] = bad; self.rejected(value, 1)
        for bad in (None, {}, [], {'private interval': 1}):
            value = self.startup_failure(); value['remaining_thread_matrix']['hadoop_metrics'] = bad; self.rejected(value, 1)
        for bad in (True, -1, 1.0, '1', 'private stack', None):
            value = self.startup_failure(); value['remaining_thread_matrix']['hadoop_metrics']['unattributed'] = bad
            self.rejected(value, 1)
        value = self.startup_failure(); value['remaining_thread_matrix']['extra'] = {}; self.rejected(value, 1)
        value = self.startup_failure(); value['remaining_thread_matrix']['hadoop_metrics']['extra'] = 0; self.rejected(value, 1)
        value = self.startup_failure(); value['remaining_threads'] = value['remaining_thread_intervals'] = None
        self.rejected(value, 1)

    def test_owned_helper_missing_ambiguous_late_and_shutdown_failures_never_pass(self):
        for helper, category, phase in (('gc_monitor', 'hadoop_util', 'namenode'),
                                         ('fs_statistics_cleaner', 'hadoop_fs', 'filesystem'),
                                         ('format_ssl_timer', 'jdk_timer', 'format')):
            for state in F.OWNED_CLEANUP_STATES - {'terminated'}:
                value = positive(); value.update(success=False, error='cleanup_failed')
                value['owned_thread_cleanup'][helper] = state
                value['cleanup'].update(threads_terminated=False, private_material_removed=False)
                value['cleanup'][helper + '_reaped'] = False
                value['remaining_threads'][category] = 1
                value['remaining_thread_intervals'][phase] = 1
                value['remaining_thread_matrix'][category][phase] = 1
                if helper == 'format_ssl_timer':
                    value['remaining_timer_kinds']['ssl_store'] = 1
                with self.subTest(helper=helper, state=state):
                    result = F.validate_java(F.canonical(value), 1)
                    self.assertFalse(result['success'])
                    self.assertFalse(result['cleanup'][helper + '_reaped'])
                    self.assertFalse(result['cleanup']['threads_terminated'])
                    self.assertFalse(result['cleanup']['private_material_removed'])
                    self.assertTrue(all(result[key] is False for key in F.JAVA_FALSE))
                    self.rejected(value, 0)

    def test_owned_helper_report_rejects_raw_unknown_and_contradictory_success(self):
        for bad in (None, {}, [], {'gc_monitor': 'terminated'},
                    {'gc_monitor': 'private stack', 'fs_statistics_cleaner': 'terminated'},
                    {'gc_monitor': True, 'fs_statistics_cleaner': 'terminated'},
                    {'gc_monitor': 'terminated', 'fs_statistics_cleaner': 'terminated', 'extra': 'private'}):
            value = positive(); value['owned_thread_cleanup'] = bad; self.rejected(value)
        value = positive(); del value['owned_thread_cleanup']; self.rejected(value)
        for helper in ('gc_monitor', 'fs_statistics_cleaner', 'format_ssl_timer'):
            for bad in ('private stack', 'unknown_state', True, None, 1):
                value = positive(); value['owned_thread_cleanup'][helper] = bad; self.rejected(value)
            value = positive(); value['owned_thread_cleanup'][helper] = 'shutdown_failed'; self.rejected(value)
            value = positive(); value.update(success=False, error='cleanup_failed')
            value['cleanup'][helper + '_reaped'] = False; self.rejected(value, 1)

    def test_timer_hints_are_closed_exactly_counted_and_never_exempted(self):
        for kind in ('namenode_metrics', 'rpc_idle', 'snapshot_gc', 'shell_timeout', 'ssl_store', 'unknown'):
            value = positive(); value.update(success=False, error='cleanup_failed')
            value['cleanup'].update(threads_terminated=False, private_material_removed=False)
            value['remaining_threads']['jdk_timer'] = 1
            value['remaining_thread_intervals']['format'] = 1
            value['remaining_thread_matrix']['jdk_timer']['format'] = 1
            value['remaining_timer_kinds'][kind] = 1
            result = F.validate_java(F.canonical(value), 1)
            self.assertFalse(result['success']); self.assertFalse(result['cleanup']['threads_terminated'])
            value['remaining_timer_kinds'][kind] = 0; self.rejected(value, 1)
        for bad in (None, {}, [], {'Timer-123': 1}, True):
            value = positive(); value['remaining_timer_kinds'] = bad; self.rejected(value)
        for bad in (True, -1, 129, 1.0, 'private name'):
            value = positive(); value['remaining_timer_kinds']['unknown'] = bad; self.rejected(value)
        value = positive(); del value['remaining_timer_kinds']; self.rejected(value)

    def test_fixed_real_runtime_selection_is_exact_and_ordered(self):
        runtime = F.RUNTIME.read_bytes()
        lock = (F.DISCOVERY / "artifact-lock-kerberos.json").read_bytes()
        rows = F.runtime_rows(runtime, lock)
        self.assertEqual(len(rows), 142)
        self.assertEqual(sum(x["group"] == "org.apache.kerby" for x in rows), 15)
        modified = json.loads(runtime); modified["entries"].reverse()
        for wrong_runtime, wrong_lock in ((F.canonical(modified), lock), (runtime, lock + b" ")):
            with self.assertRaisesRegex(F.ProbeError, "input_invalid"): F.runtime_rows(wrong_runtime, wrong_lock)

    def test_security_inspection_and_build_have_closed_native_surface(self):
        run_id = "a" * 32; name = "kerberos-rpc-" + run_id; image = "sha256:" + "b" * 64
        value = inspected(name, image, run_id)
        F.inspect_container(value, name, image, run_id)
        for field, bad in (("NetworkMode", "bridge"), ("ReadonlyRootfs", False), ("Privileged", True),
                           ("CapAdd", ["SYS_ADMIN"]), ("Binds", ["/tmp:/work"]), ("PidsLimit", True),
                           ("PortBindings", {"19006/tcp": [{}]}), ("LogConfig", {"Type": "json-file"})):
            altered = copy.deepcopy(value); altered["HostConfig"][field] = bad
            with self.subTest(field=field), self.assertRaises(F.ProbeError): F.inspect_container(altered, name, image, run_id)
        files = F.build_files([dict(sha256="d" * 64)])
        self.assertIn(b"-proc:none -implicit:none", files["Dockerfile"])
        self.assertIn(b"--kill-after=5s 180s", files["driver.sh"])
        self.assertIn(b"-Duser.home=/work/home", files["driver.sh"])

    def fake_run(self, action=None, failure=None, *, profile="kerberos", real_helpers=False):
        here = self.root / "input"; discovery = self.root / "discovery"
        here.mkdir(); discovery.mkdir()
        java = b"inert Java source"
        (here / "HdfsKerberosRpcProbe.java").write_bytes(java)
        (here / "runtime-classpath.json").write_bytes(b"{}")
        binary = here / "rclone"; binary.write_bytes(b"inert rclone")
        pin = here / "rclone-version.env"
        pin.write_text("RCLONE_VERSION=1.75.2\nRCLONE_LINUX_EXE_SHA256=" + F.sha(b"inert rclone") + "\n")
        (discovery / "artifact-lock-kerberos.json").write_bytes(b"{}")
        (discovery / "artifact-lock-kerberos-remediation.json").write_bytes(b"{}")
        helper = discovery / "helper.py"; helper.write_bytes(b"# inert helper\n")
        rows = [dict(size=3, sha256=F.sha(b"jar"))]
        made = []
        def loader(): return types.SimpleNamespace(DiscoveryError=F.ProbeError), {helper: F.file_hash(helper)}
        def downloader(context, rows, *, profile):
            self.assertEqual(profile, selected_profile)
            self.assertTrue((context / F.profile_settings(profile)["lock"].name).is_file())
            (context / "jars").mkdir(); (context / "jars" / "000.jar").write_bytes(b"jar")
        def factory(root, **kwargs):
            docker = FakeDocker(root, **kwargs); made.append(docker)
            if failure:
                docker.java["checks"]["positive_tgt"] = False
                docker.java.update(success=False, error="positive_ticket_failed",
                    diagnostic=dict(category="assertion", origin="none")); docker.exit_code = 1
            if action: docker.action = lambda d: action(d, helper)
            return docker
        real_mkdtemp = tempfile.mkdtemp
        selected_profile = profile
        chosen_discovery = F.DISCOVERY if real_helpers else discovery
        with patch.multiple(F, HERE=here, DISCOVERY=chosen_discovery, JAVA_SHA=F.sha(java),
             RUNTIME=here / "runtime-classpath.json", REMEDIATION_RUNTIME=here / "runtime-classpath.json",
             PIN_FILE=pin, RCLONE_SHA=F.sha(b"inert rclone")), \
             patch.object(F, "hosted_guard"), patch.object(F, "runtime_rows", return_value=rows), \
             patch.object(F.shutil, "disk_usage", return_value=types.SimpleNamespace(free=1024**3)), \
             patch.object(F.tempfile, "mkdtemp", side_effect=lambda **kw: real_mkdtemp(prefix=kw["prefix"], dir=self.root)):
            report = F.run(binary, loader=F.load_helpers if real_helpers else loader,
                           downloader=downloader, runner_factory=factory, profile=profile)
        return report, made[0]

    def test_full_mock_success_binds_context_and_cleans(self):
        report, docker = self.fake_run()
        self.assertTrue(report["success"], report["errors"])
        self.assertTrue(all(report["cleanup"].values()))
        self.assertFalse(docker.root.exists())
        self.assertEqual(report["result"], projected())
        self.assertTrue(all(report[key] is False for key in F.FALSE_CLAIMS))
        self.assertEqual(report["cleanup_excludes"], ["shared_base_image", "shared_build_cache"])
        build = next(args for args, _ in docker.calls if args[0] == "build")
        self.assertEqual(build[1:4], ["--network", "none", "--pull=false"])
        start = next(options for args, options in docker.calls if args[0] == "start")
        self.assertEqual(start, dict(timeout=195, limit=32768, allow_failure=True))

    def test_failed_java_result_stays_failed_after_clean_removal(self):
        report, _ = self.fake_run(failure=True)
        self.assertFalse(report["success"])
        self.assertEqual(report["errors"], ["java_probe_failed"])
        self.assertTrue(all(report["cleanup"].values()))

    def test_late_source_mutation_cannot_promote_success(self):
        report, _ = self.fake_run(action=lambda d, source: source.write_bytes(b"# changed\n"))
        self.assertFalse(report["success"])
        self.assertIn("input_changed", report["errors"])

    def test_foreign_container_is_never_removed_and_raw_is_preserved(self):
        def change(docker, source): docker.container["Config"]["Labels"] = {F.LABEL: "foreign"}
        report, docker = self.fake_run(action=change)
        self.assertFalse(report["success"])
        self.assertFalse(report["cleanup"]["container_removed"])
        self.assertFalse(report["cleanup"]["raw_evidence_removed"])
        self.assertTrue(docker.root.is_dir())
        self.assertFalse(any(args[:2] == ["container", "rm"] for args, _ in docker.calls))

    def test_uncertain_command_reap_preserves_raw_even_if_resources_removed(self):
        def fail(docker, source): raise F.ProbeError("command_cleanup_failed")
        report, docker = self.fake_run(action=fail)
        self.assertFalse(report["success"])
        self.assertIn("command_cleanup_failed", report["errors"])
        self.assertTrue(docker.root.is_dir())
        self.assertTrue(report["cleanup"]["container_removed"])
        self.assertFalse(report["cleanup"]["context_removed"])

    def test_hosted_guard_precedes_helper_loading_and_writes(self):
        loader = Mock(side_effect=AssertionError("must not load"))
        with patch.object(F, "hosted_guard", side_effect=F.ProbeError("hosted_linux_required")):
            result = F.run(loader=loader)
        loader.assert_not_called()
        self.assertFalse(result["success"])
        self.assertEqual(result["inputs"], None)

    def test_downloader_child_envelope_and_successful_reap_are_bounded(self):
        context = self.root / "context"; context.mkdir()
        proc = Mock(pid=456); proc.wait.return_value = 0; proc.poll.return_value = 0
        with patch.object(F.subprocess, "Popen", return_value=proc) as launch, \
             patch.object(F, "verify_jars") as verify, patch.dict(F.os.environ, {"HTTP_PROXY": "private", "JAVA_TOOL_OPTIONS": "private"}):
            F.download(context, [])
        args, kwargs = launch.call_args
        self.assertEqual(args[0][1:4], ["-I", "-S", "-B"])
        self.assertEqual(args[0][5], "--download-worker")
        self.assertEqual(args[0][-1], "kerberos")
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn("HTTP_PROXY", kwargs["env"])
        self.assertNotIn("JAVA_TOOL_OPTIONS", kwargs["env"])
        self.assertEqual([c.kwargs["timeout"] for c in proc.wait.call_args_list], [300, 3])
        verify.assert_called_once_with(context, [])

    def test_downloader_timeout_kills_only_owned_group_and_reaps(self):
        context = self.root / "context"; context.mkdir()
        proc = Mock(pid=456); proc.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 300), 0]; proc.poll.return_value = None
        with patch.object(F.subprocess, "Popen", return_value=proc), \
             patch.object(F.os, "getpgid", return_value=456, create=True), \
             patch.object(F.os, "killpg", create=True) as kill, patch.object(F.signal, "SIGKILL", 9, create=True):
            with self.assertRaisesRegex(F.ProbeError, "^download_failed$"): F.download(context, [])
        kill.assert_called_once_with(456, 9)
        self.assertEqual(proc.wait.call_args.kwargs["timeout"], 3)

    def test_downloader_uncertain_identity_or_reap_is_sticky(self):
        context = self.root / "context"; context.mkdir()
        for foreign in (True, False):
            proc = Mock(pid=456); proc.wait.side_effect = subprocess.TimeoutExpired("synthetic", 300); proc.poll.return_value = None
            with self.subTest(foreign=foreign), patch.object(F.subprocess, "Popen", return_value=proc), \
                 patch.object(F.os, "getpgid", return_value=123 if foreign else 456, create=True), \
                 patch.object(F.os, "killpg", create=True) as kill, patch.object(F.signal, "SIGKILL", 9, create=True):
                with self.assertRaisesRegex(F.ProbeError, "^download_cleanup_failed$"): F.download(context, [])
                self.assertEqual(kill.call_count, 0 if foreign else 1)

    def test_transport_content_and_redirect_fail_closed_without_retry(self):
        class Response(io.BytesIO):
            status = 200
            url = "https://repo.maven.apache.org/maven2/synthetic/bytes/1/bytes-1.jar"
            def __init__(self, body, length):
                super().__init__(body); self.headers = Message(); self.headers["Content-Length"] = length
        row = dict(group="synthetic", artifact="bytes", version="1", classifier="", type="jar", size=3, sha256=F.sha(b"jar"))
        for index, (body, length) in enumerate(((b"jar", "3"), (b"bad", "3"), (b"jars", "3"), (b"jar", "4"))):
            context = self.root / str(index); context.mkdir()
            opener = Mock(); opener.open.return_value = Response(body, length)
            if index == 0: F.download_rows(context, [row], opener=opener)
            else:
                with self.assertRaises(F.ProbeError): F.download_rows(context, [row], opener=opener)
            opener.open.assert_called_once()
        with self.assertRaises(F.ProbeError): F.NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_helper_loading_is_exact_source_and_restores_imports(self):
        originals = {name: sys.modules.get(name) for name in F.HELPERS}
        old = object(); sys.modules["graph_export"] = old
        try:
            with patch.object(F.subprocess, "Popen", side_effect=AssertionError("native forbidden")):
                module, bindings = F.load_helpers()
            self.assertTrue(callable(module.Docker))
            self.assertEqual(len(bindings), 4)
            self.assertIs(sys.modules["graph_export"], old)
            self.assertEqual({p.stem for p in bindings}, set(F.HELPERS))
            for path, digest in bindings.items(): self.assertEqual(F.sha(path.read_bytes()), digest)
        finally:
            for name, value in originals.items():
                if value is None: sys.modules.pop(name, None)
                else: sys.modules[name] = value



class ProfileTests(unittest.TestCase):
    def setUp(self):
        TicketTests.setUp(self)
        self.sequence = 0

    tearDown = TicketTests.tearDown

    def invoke(self, **kwargs):
        self.sequence += 1
        saved = self.root
        self.root = saved / str(self.sequence); self.root.mkdir()
        try: return TicketTests.fake_run(self, **kwargs)
        finally: self.root = saved

    def test_real_profiles_validate_only_their_own_exact_runtime_and_lock(self):
        material = {}
        for profile, total in (("kerberos", 74090067), ("kerberos-remediation", 73104651)):
            pins = F.profile_settings(profile)
            runtime, lock = pins["runtime"].read_bytes(), pins["lock"].read_bytes()
            rows = F.runtime_rows(runtime, lock, profile=profile)
            self.assertEqual(len(rows), 142)
            self.assertEqual(sum(row["size"] for row in rows), total)
            self.assertEqual(sum(row["group"] == "org.apache.kerby" for row in rows), 15)
            self.assertEqual(F.sha(runtime), pins["runtime_sha256"])
            self.assertEqual(F.sha(F.canonical(rows)), pins["order_sha256"])
            material[profile] = runtime, lock
        for profile, (runtime, lock) in material.items():
            other = "kerberos-remediation" if profile == "kerberos" else "kerberos"
            wrong_runtime, wrong_lock = material[other]
            for pair in ((wrong_runtime, lock), (runtime, wrong_lock), (wrong_runtime, wrong_lock)):
                with self.subTest(profile=profile), self.assertRaises(F.ProbeError):
                    F.runtime_rows(*pair, profile=profile)
        self.assertEqual(F.runtime_rows(*material["kerberos"]), F.runtime_rows(*material["kerberos"], profile="kerberos"))

    def test_closed_profiles_fail_before_reads_workers_or_host_access(self):
        for bad in (None, True, 1, [], {}, "", "Kerberos", "kerberos/../kerberos-remediation", "PRIVATE_CANARY"):
            with self.subTest(kind=type(bad).__name__), \
                    patch.object(F, "directory") as directory, patch.object(F, "read") as read, \
                    patch.object(F, "file_hash") as hashed, patch.object(F, "hosted_guard") as host:
                with self.assertRaises(F.ProbeError): F.runtime_rows(b"", b"", profile=bad)
                with self.assertRaises(F.ProbeError): F.download(self.root / "context", [], profile=bad)
                loader = Mock(side_effect=AssertionError("helper forbidden"))
                report = F.run(profile=bad, loader=loader)
                self.assertFalse(report["success"])
                self.assertEqual(report["errors"], ["input_invalid"])
                self.assertIsNone(report["candidate_profile"])
                self.assertNotIn("PRIVATE_CANARY", json.dumps(report))
                for mocked in (directory, read, hashed, host, loader): mocked.assert_not_called()

    def test_order_count_and_membership_still_fail_after_outer_hash_rebinding(self):
        profile = "kerberos-remediation"
        pins = F.profile_settings(profile)
        original = json.loads(pins["runtime"].read_bytes()); lock = pins["lock"].read_bytes()
        changes = (lambda x: x["entries"].reverse(), lambda x: x["entries"].pop(),
                   lambda x: x["entries"].append(copy.deepcopy(x["entries"][0])),
                   lambda x: x["entries"].__setitem__(1, copy.deepcopy(x["entries"][0])))
        for index, change in enumerate(changes):
            value = copy.deepcopy(original); change(value)
            if index == 3:
                value["normalized_sha256"] = F.sha(F.canonical(value["entries"]))
            raw = F.canonical(value)
            with self.subTest(index=index), patch.object(F, "REMEDIATION_RUNTIME_SHA", F.sha(raw)), \
                    patch.object(F, "REMEDIATION_ORDER_SHA", value["normalized_sha256"] if index == 3 else pins["order_sha256"]):
                with self.assertRaises(F.ProbeError): F.runtime_rows(raw, lock, profile=profile)

    def test_download_child_argv_has_explicit_selected_profile_and_same_bounds(self):
        for profile in F.PROFILES:
            context = self.root / profile / "context"; context.mkdir(parents=True)
            process = Mock(pid=456); process.wait.return_value = 0; process.poll.return_value = 0
            with patch.object(F.subprocess, "Popen", return_value=process) as launch, patch.object(F, "verify_jars") as verify:
                F.download(context, [], profile=profile)
            argv, options = launch.call_args.args[0], launch.call_args.kwargs
            self.assertEqual(argv[5], "--download-worker")
            self.assertEqual(argv[-1], profile)
            self.assertEqual(len(argv[5:]), 6)
            self.assertEqual([call.kwargs["timeout"] for call in process.wait.call_args_list], [300, 3])
            self.assertTrue(options["start_new_session"])
            verify.assert_called_once_with(context, [])

    def test_worker_rejects_missing_extra_or_unknown_profile_before_file_io(self):
        prefix = ["--download-worker", str(self.root / "context"), "1", "2", "a" * 64]
        cases = (prefix, prefix + ["kerberos", "extra"], prefix + ["PRIVATE_CANARY"], prefix + [None])
        for args in cases:
            with patch.object(F, "hosted_guard") as host, patch.object(F, "directory") as directory, \
                    patch.object(F, "file_hash") as hashed, patch.object(F, "read") as read, \
                    patch.object(F, "download_rows") as download:
                self.assertEqual(F.main(args), 1)
                for mocked in (host, directory, hashed, read, download): mocked.assert_not_called()

    def test_worker_uses_exact_profile_basename_and_rejects_crossed_bytes(self):
        for profile in F.PROFILES:
            pins = F.profile_settings(profile)
            other = F.profile_settings("kerberos-remediation" if profile == "kerberos" else "kerberos")
            for wrong in (False, True):
                selected = other if wrong else pins
                runtime, lock = selected["runtime"].read_bytes(), selected["lock"].read_bytes()
                context = self.root / "context"
                paths = []
                def read(path, maximum):
                    self.assertEqual(maximum, 512 * 1024)
                    paths.append(path)
                    if path == context / "runtime-classpath.json": return runtime
                    self.assertEqual(path, context / pins["lock"].name)
                    return lock
                with patch.object(F, "hosted_guard"), patch.object(F, "directory"), \
                        patch.object(F, "file_hash", return_value="a" * 64), patch.object(F, "read", side_effect=read), \
                        patch.object(F, "download_rows") as download:
                    code = F.main(["--download-worker", str(context), "1", "2", "a" * 64, profile])
                self.assertEqual(code, 1 if wrong else 0)
                self.assertEqual(paths, [context / "runtime-classpath.json", context / pins["lock"].name])
                if wrong: download.assert_not_called()
                else:
                    download.assert_called_once()
                    self.assertEqual(len(download.call_args.args[1]), 142)

    def test_fake_profiles_with_real_helpers_bind_distinct_receipts_and_clean(self):
        receipts = {}
        for profile in F.PROFILES:
            report, docker = self.invoke(profile=profile, real_helpers=True)
            self.assertTrue(report["success"], report["errors"])
            self.assertTrue(all(report["cleanup"].values()))
            self.assertFalse(docker.root.exists())
            pins = F.profile_settings(profile)
            self.assertEqual(report["candidate_profile"], profile)
            self.assertEqual(report["inputs"]["candidate_profile"], profile)
            self.assertEqual(report["inputs"]["lock_sha256"], pins["lock_sha256"])
            self.assertEqual(report["inputs"]["runtime_file_sha256"], pins["runtime_sha256"])
            self.assertEqual(report["inputs"]["runtime_classpath_sha256"], pins["order_sha256"])
            self.assertIn(pins["lock"].name, report["inputs"]["source_sha256"])
            for name in F.HELPERS:
                self.assertEqual(report["inputs"]["source_sha256"][name + ".py"], F.sha((F.DISCOVERY / (name + ".py")).read_bytes()))
            for claim in F.FALSE_CLAIMS: self.assertIs(report[claim], False)
            self.assertLess(len(F.canonical(report)), 65536)
            receipts[profile] = report
        self.assertNotEqual(receipts["kerberos"]["inputs"]["lock_sha256"], receipts["kerberos-remediation"]["inputs"]["lock_sha256"])
        self.assertNotEqual(receipts["kerberos"]["inputs"]["runtime_classpath_sha256"], receipts["kerberos-remediation"]["inputs"]["runtime_classpath_sha256"])

    def test_new_profile_never_promotes_failed_controls_or_changed_sources(self):
        report, _ = self.invoke(profile="kerberos-remediation", failure=True)
        self.assertFalse(report["success"])
        self.assertIn("java_probe_failed", report["errors"])
        self.assertTrue(all(report["cleanup"].values()))
        report, _ = self.invoke(profile="kerberos-remediation", action=lambda docker, source: source.write_bytes(b"# changed\n"))
        self.assertFalse(report["success"])
        self.assertIn("input_changed", report["errors"])

    def test_new_profile_keeps_foreign_resource_and_uncertain_reap_failures(self):
        def foreign(docker, source): docker.container["Config"]["Labels"] = {F.LABEL: "foreign"}
        def uncertain(docker, source): raise F.ProbeError("command_cleanup_failed")
        for action in (foreign, uncertain):
            report, docker = self.invoke(profile="kerberos-remediation", action=action)
            self.assertFalse(report["success"])
            self.assertFalse(report["cleanup"]["raw_evidence_removed"])
            self.assertTrue(docker.root.exists())

    def test_new_profile_selected_lock_and_runtime_are_rechecked_after_execution(self):
        def change_lock(docker, source):
            (source.parent / "artifact-lock-kerberos-remediation.json").write_bytes(b"changed lock")
        def change_runtime(docker, source):
            (source.parent.parent / "input/runtime-classpath.json").write_bytes(b"changed runtime")
        for action in (change_lock, change_runtime):
            report, _ = self.invoke(profile="kerberos-remediation", action=action)
            self.assertFalse(report["success"])
            self.assertIn("input_changed", report["errors"])
            self.assertTrue(all(report["cleanup"].values()))

    def test_cli_defaults_old_and_passes_explicit_new_profile(self):
        for profile in F.PROFILES:
            report = self.root / (profile + ".json")
            args = ["--rclone", str(self.root / "rclone"), "--report", str(report)]
            if profile != "kerberos": args += ["--profile", profile]
            with patch.object(F, "hosted_guard"), patch.object(F, "directory"), \
                    patch.object(F, "run", return_value=dict(success=True, candidate_profile=profile)) as run:
                self.assertEqual(F.main(args), 0)
            run.assert_called_once_with(self.root / "rclone", profile=profile)
            self.assertEqual(json.loads(report.read_bytes())["candidate_profile"], profile)

    def test_receipt_limit_is_unchanged_for_remediation_profile(self):
        report = self.root / "oversize.json"
        with patch.object(F, "hosted_guard"), patch.object(F, "directory"), \
                patch.object(F, "run", return_value=dict(success=True, candidate_profile="kerberos-remediation", private="x" * 65536)), \
                patch.object(F.sys, "stderr", io.StringIO()) as error:
            self.assertEqual(F.main(["--rclone", str(self.root / "rclone"), "--report", str(report),
                                     "--profile", "kerberos-remediation"]), 1)
        self.assertEqual(error.getvalue(), "rpc_probe_failed\n")
        self.assertEqual(report.read_bytes(), b"")

    def test_new_workflow_is_separate_and_explicitly_selects_the_new_profile(self):
        workflows = HERE.parents[2] / ".github/workflows"
        new = (workflows / "hdfs-kerberos-rpc-remediation.yml").read_text()
        old = (workflows / "hdfs-kerberos-rpc.yml").read_text()
        self.assertIn("--profile kerberos-remediation", new)
        self.assertNotIn("--profile kerberos-remediation", old)
        for text in (old, new):
            self.assertIn("persist-credentials: false", text)
            self.assertIn("contents: read", text)
            self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", text)
            self.assertIn("timeout-minutes: 20", text)
        self.assertIn("artifact-lock-kerberos-remediation.json", new)
        self.assertIn("name: hdfs-kerberos-rpc-remediation-experiment", new)


class WireTests(unittest.TestCase):
    def rejected(self, raw):
        with self.assertRaisesRegex(F.ProbeError, "wire_invalid"): F.parse_wire(raw)

    def test_exact_single_auth_boundary_and_alignment(self):
        self.assertEqual(F.parse_wire(wire()), projected()["wire_oracle"])
        self.assertEqual(F.parse_wire(wire(wire_fields({9: 23}))), projected()["wire_oracle"])

    def test_transport_size_negative_zero_oversize_truncation_and_extra(self):
        raw = wire()
        for bad in (b"", b"\xff" * 4, b"\x00" * 4, (4097).to_bytes(4, "big") + b"x" * 4097,
                    raw[:-1], raw + b"\x00", wire(suffix=b"\x00"), raw[:4] + b"\x80" * 10):
            self.rejected(bad)

    def test_wrong_status_detail_version_class_or_message_never_auth(self):
        for field, bad in ((1, 0), (2, 1), (3, 8), (4, b"java.io.IOException"), (6, 1),
            (5, b"Permission denied: user=reader, access=READ_EXECUTE"),
            (5, b"SIMPLE authentication is not enabled.  Available:[SIMPLE, KERBEROS]"),
            (5, b"SIMPLE authentication is not enabled.  Available:[TOKEN]"),
            (5, b"SIMPLE authentication is not enabled.  Available:[TOKEN, KERBEROS] extra"),
            (7, b"private"), (8, 0), (9, 1 << 63)):
            with self.subTest(field=field, bad=bad): self.rejected(wire(wire_fields({field: bad})))

    def test_missing_duplicate_unknown_and_malformed_fields(self):
        fields = wire_fields(); del fields[3]; self.rejected(wire(fields))
        self.rejected(wire(wire_fields({10: b"extension"})))
        original = wire(); body = original[4:]
        # The first header length is a two-byte varint for this independent literal.
        offset = 0
        while body[offset] & 128: offset += 1
        header = body[offset + 1:]
        duplicate = header + b"\x10\x02"
        framed = varint(len(duplicate)) + duplicate
        self.rejected(len(framed).to_bytes(4, "big") + framed)
        for bad_header in (b"\x08\x80", b"\x0f\x00", b"\x08\x80\x00", b"\x22\xff\x7f"):
            framed = varint(len(bad_header)) + bad_header
            self.rejected(len(framed).to_bytes(4, "big") + framed)

    def test_no_control_or_cleanup_may_be_omitted_or_false(self):
        for group in ("checks", "cleanup"):
            for key in positive()[group]:
                for mutation in ("missing", "false", "extra"):
                    value = positive()
                    if mutation == "missing": del value[group][key]
                    elif mutation == "false": value[group][key] = False
                    else: value[group]["extra"] = True
                    with self.subTest(group=group, key=key, mutation=mutation), self.assertRaises(F.ProbeError):
                        F.validate_java(F.canonical(value), 0)

    def test_false_or_substituted_oracle_cannot_promote(self):
        for field, bad in (("wire_hex", wire(wire_fields({5: b"Permission denied"})).hex()),
                           ("wire_hex", ""), ("wire_hex", "zz"), ("stage", "reader_tgt")):
            value = positive(); value[field] = bad
            with self.assertRaises(F.ProbeError): F.validate_java(F.canonical(value), 0)

    def test_actual_rclone_capture_is_required_and_cannot_be_replaced_by_direct_oracle(self):
        for raw in ("", wire(wire_fields({2: 1})).hex(), wire(wire_fields({9: 77})).hex()):
            value = positive(); value["rclone_wire_hex"] = raw
            with self.assertRaises(F.ProbeError): F.validate_java(F.canonical(value), 0)

    def test_relay_rejects_missing_phase_misattribution_extra_connections_and_capture_loss(self):
        mutations = (("before_connections", 0), ("after_connections", 0), ("negative_connections", 0),
            ("negative_connections", 5), ("negative_connections", True), ("negative_connections", 2),
            ("none_headers", 0), ("none_headers", 2), ("fatal_responses", 0),
            ("unexpected_connections", 1), ("unexpected_connections", 2), ("bytes_forwarded_unchanged", False))
        for key, bad in mutations:
            value = positive(); value["relay"][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(F.ProbeError):
                F.validate_java(F.canonical(value), 0)
        for bad in (None, {}, dict(positive()["relay"], extra=1)):
            value = positive(); value["relay"] = bad
            with self.assertRaises(F.ProbeError): F.validate_java(F.canonical(value), 0)

    def test_partial_failed_relay_preserves_finite_diagnostics_without_credit(self):
        value = positive(); value.update(success=False, error="relay_invalid", stage="rclone_none")
        value["diagnostic"] = dict(category="assertion", origin="none")
        value["checks"]["listing_after"] = False
        value["relay"]["unexpected_connections"] = 1
        value["relay"]["bytes_forwarded_unchanged"] = False
        result = F.validate_java(F.canonical(value), 1)
        self.assertFalse(result["success"])
        self.assertNotIn("wire_hex", result); self.assertNotIn("rclone_wire_hex", result)


class JavaSourceTests(unittest.TestCase):
    def test_ssl_factory_is_captured_only_after_owned_format_not_initialized_during_cleanup(self):
        source = (HERE / 'HdfsKerberosRpcProbe.java').read_text()
        self.assertEqual(source.count('Util.connectionFactory'), 1)
        main = source[source.index('            stage = "format";'):source.index('            stage = "namenode_start";')]
        self.assertIn('try { NameNode.format(conf); formatSslFactory = Util.connectionFactory; }', main)
        self.assertIn('finally { rememberOwner(); } return null; }, 15, deadline)', main)
        self.assertLess(main.index('observeThreads("format", baseline)'), main.index('inspectFormatSslTimer(baseline, deadline, true)'))
        self.assertEqual(source.count('formatSslFactory = '), 1)
        cleanup = source[source.index('    private static OwnedCleanupState stopOwnedFormatSsl('):source.index('    private static String boolMap(')]
        for forbidden in ('Util.connectionFactory', 'new URLConnectionFactory', 'new Timer(', 'SSLFactory(', 'getDeclaredField', 'setAccessible'):
            self.assertNotIn(forbidden, cleanup)

    def test_ssl_timer_capture_and_rescan_reject_wrong_identity_phase_type_and_ambiguity(self):
        source = (HERE / 'HdfsKerberosRpcProbe.java').read_text()
        body = source[source.index('    private static OwnedCleanupState inspectFormatSslTimer('):
                      source.index('    private static OwnedCleanupState stopOwnedFormatSsl(')]
        capture = body.index('formatSslThread = target;')
        for condition in ('threadObservationIncomplete', '!OBSERVED_PHASES.contains("format")',
                          'formatSslFactory == null', 'formatSslFactory.getClass() != URLConnectionFactory.class',
                          'if (++live > 128)', 'System.nanoTime() >= until',
                          '!thread.getName().equals("SSL Certificates Store Monitor")',
                          '!thread.getClass().getName().equals("java.util.TimerThread")',
                          'if (target != null) return OwnedCleanupState.ambiguous',
                          'if (target == null) return OwnedCleanupState.missing',
                          'baseline.contains(target.getId())', '!THREAD_ORIGINS.containsKey(target)',
                          '!THREAD_ORIGINS.get(target).equals("format")', '!target.isDaemon()',
                          'if (formatSslThread != null) return OwnedCleanupState.ambiguous'):
            self.assertLess(body.index(condition), capture)
        self.assertIn('else if (target != formatSslThread) return OwnedCleanupState.unobserved', body)
        self.assertEqual(source.count('formatSslThread = target;'), 1)
        for forbidden in ('.interrupt(', '.destroy(', '.cancel(', 'startsWith(', 'matches(', 'baseline.add', 'getDeclaredField'):
            self.assertNotIn(forbidden, body)

    def test_ssl_timer_uses_only_retained_factory_lifecycle_and_same_remaining_budget(self):
        source = (HERE / 'HdfsKerberosRpcProbe.java').read_text()
        body = source[source.index('    private static OwnedCleanupState stopOwnedFormatSsl('):
                      source.index('    private static void cleanup(')]
        action = body.index('formatSslFactory.destroy();')
        for condition in ('if (sslCaptureFailure != null)', '!threadObservationsComplete()',
                          'OwnedCleanupState.services_not_stopped',
                          'inspectFormatSslTimer(baseline, until, false)', 'if (invalid != null) return invalid',
                          'System.nanoTime() >= until'):
            self.assertLess(body.index(condition), action)
        for user in ('children_reaped', 'relay_closed', 'filesystem_closed', 'namenode_stop_returned',
                     'owner_logged_out', 'kdc_stop_returned'):
            self.assertLess(body.index('"' + user + '"'), action)
        self.assertIn('long remaining = until - System.nanoTime()', body)
        self.assertIn('formatSslThread.join(remaining / 1_000_000L, (int)(remaining % 1_000_000L))', body)
        self.assertIn('formatSslThread.isAlive() ? OwnedCleanupState.still_alive : OwnedCleanupState.terminated', body)
        self.assertIn('catch (Throwable ignored) { return OwnedCleanupState.shutdown_failed; }', body)
        for forbidden in ('formatSslThread.interrupt(', '.stop(', '.cancel(', 'System.exit', 'TimeUnit.SECONDS',
                          'DefaultMetricsSystem', 'getDeclaredField', 'setAccessible'):
            self.assertNotIn(forbidden, body)

    def test_timer_classifier_publishes_only_exact_source_backed_enum_hints(self):
        source = (HERE / 'HdfsKerberosRpcProbe.java').read_text()
        body = source[source.index('    private static String timerKind('):source.index('    private static void observeThreads(')]
        pairs = re.findall(r'if \(name\.equals\("([^"\n]+)"\)\) return "([a-z_]+)";', body)
        self.assertEqual(dict(pairs), {"Timer for 'NameNode' metrics system": 'namenode_metrics',
            'IPC Server idle connection scanner for port 19000': 'rpc_idle',
            'SnapshotDeletionGc': 'snapshot_gc', 'Shell command timeout': 'shell_timeout',
            'SSL Certificates Store Monitor': 'ssl_store'})
        self.assertEqual(set(re.findall(r'return "([a-z_]+)";', body)),
                         {'namenode_metrics', 'rpc_idle', 'snapshot_gc', 'shell_timeout', 'ssl_store', 'unknown'})
        for forbidden in ('return name', 'System.', 'print', '.interrupt(', '.cancel(', 'startsWith(', 'matches('):
            self.assertNotIn(forbidden, body)
        self.assertIn('sum() == counts.get("jdk_timer")', source)
    def test_owned_cleanup_requires_exact_identity_type_phase_and_stopped_users(self):
        source = (HERE / 'HdfsKerberosRpcProbe.java').read_text()
        body = source[source.index('    private static OwnedCleanupState stopOwnedHelper('):
                      source.index('    private static OwnedCleanupState inspectFormatSslTimer(')]
        action = body.index('target.interrupt();')
        for condition in ('!threadObservationsComplete()', 'OwnedCleanupState.services_not_stopped',
                          'if (target != null) return OwnedCleanupState.ambiguous',
                          'if (target == null) return OwnedCleanupState.missing',
                          'baseline.contains(target.getId())', 'THREAD_ORIGINS.containsKey(target)',
                          'THREAD_ORIGINS.get(target).equals(gc ? "namenode" : "filesystem")',
                          '!target.isDaemon()', 'System.nanoTime() >= until'):
            self.assertLess(body.index(condition), action)
        self.assertIn('thread.getClass() == GcTimeMonitor.class', body)
        self.assertIn('thread.getClass() == SubjectInheritingThread.class && statisticsCleanerFrame(thread)', body)
        self.assertIn('if (gc) ((GcTimeMonitor) target).shutdown();', body)
        self.assertIn('target.join(remaining / 1_000_000L, (int)(remaining % 1_000_000L))', body)
        self.assertIn('target.isAlive() ? OwnedCleanupState.still_alive : OwnedCleanupState.terminated', body)
        self.assertIn('if (++live > 128)', body)
        for forbidden in ('baseline.add', 'baseline =', 'target.stop(', 'DefaultMetricsSystem.shutdown', 'getName('):
            self.assertNotIn(forbidden, body)
        frame = source[source.index('    private static boolean statisticsCleanerFrame('):
                       source.index('    private static OwnedCleanupState stopOwnedHelper(')]
        self.assertIn('i < frames.length && i < 32', frame)
        self.assertIn('equals("org.apache.hadoop.fs.FileSystem$Statistics$StatisticsDataReferenceCleaner")', frame)
        self.assertIn('getMethodName().equals("run")', frame)

    def test_owned_helpers_share_original_cleanup_deadline_and_private_gate(self):
        source = (HERE / 'HdfsKerberosRpcProbe.java').read_text()
        body = source[source.index('    private static void cleanup('):source.index('    private static String boolMap(')]
        self.assertEqual(body.count('TimeUnit.SECONDS.toNanos(3)'), 1)
        self.assertIn('gcCleanup = stopOwnedHelper(true, baseline, until)', body)
        self.assertIn('statisticsCleanup = stopOwnedHelper(false, baseline, until)', body)
        self.assertIn('sslCleanup = stopOwnedFormatSsl(baseline, until)', body)
        self.assertLess(body.index('long until ='), body.index('stopOwnedHelper(true'))
        self.assertLess(body.index('stopOwnedHelper(false'), body.index('remainingThreadCounts(baseline)'))
        private_gate = body[body.index('if (rootOwned'):body.index('try {\n                guardRoot();')]
        self.assertIn('"gc_monitor_reaped", "fs_statistics_cleaner_reaped", "format_ssl_timer_reaped"', private_gate)

    def test_thread_matrix_uses_the_same_single_residual_enumeration(self):
        source = (HERE / 'HdfsKerberosRpcProbe.java').read_text()
        body = source[source.index('    private static Map<String, Integer> remainingThreadCounts('):
                      source.index('    private static boolean statisticsCleanerFrame(')]
        self.assertEqual(body.count('Thread.getAllStackTraces()'), 1)
        self.assertEqual(body.count('for (Thread thread'), 1)
        for text in ('for (String category : THREAD_CATEGORIES)', 'for (String phase : THREAD_PHASES)',
                     'row.put(phase, row.get(phase) + 1)',
                     'sum() == counts.get(category)', 'sum() == intervals.get(phase)',
                     'remainingThreadMatrix = matrix'):
            self.assertIn(text, body)
        self.assertIn('remainingThreadIntervals = null; remainingThreadMatrix = null', source)
        writer = source[source.index('    private static String threadMatrixJson('):
                        source.index('    private static final class Relay')]
        self.assertIn('for (String category : THREAD_CATEGORIES)', writer)
        self.assertIn('threadCountsJson(remainingThreadMatrix.get(category), THREAD_PHASES)', writer)

    def test_thread_intervals_retain_exact_identity_without_expanding_baseline(self):
        source = (HERE / 'HdfsKerberosRpcProbe.java').read_text()
        self.assertIn('Map<Thread, String> THREAD_ORIGINS = new java.util.IdentityHashMap<>()', source)
        body = source[source.index('    private static void observeThreads('):
                      source.index('    private static boolean statisticsCleanerFrame(')]
        for text in ('THREAD_PHASES.subList(0, 8).contains(phase)', 'OBSERVED_PHASES.add(phase)',
                     'OBSERVED_PHASES.size() <= 8', 'need(++live <= 128', 'THREAD_ORIGINS.size() < 1024',
                     'THREAD_ORIGINS.containsKey(thread)', 'THREAD_ORIGINS.put(thread, phase)',
                     'THREAD_ORIGINS.getOrDefault(thread, "unattributed")',
                     'intervals.values().stream().mapToInt(Integer::intValue).sum() == total'):
            self.assertIn(text, body)
        self.assertIn('threadObservationIncomplete = true', body)
        self.assertIn('threadObservationsComplete() ? THREAD_ORIGINS.getOrDefault(thread, "unattributed") : "unattributed"', body)
        for forbidden in ('getName(', 'System.out', 'System.err', '.interrupt(', '.stop(', 'baseline.add', 'baseline ='):
            self.assertNotIn(forbidden, body)
        self.assertEqual(source.count('baseline = threadIds();'), 2)
        main = source[source.index('    public static void main('):]
        phases = re.findall(r'observeThreads\("([a-z_]+)", baseline\)', main)
        self.assertEqual(phases, ['kdc', 'owner_login', 'format', 'namenode', 'filesystem', 'reader', 'controls'])
        self.assertLess(main.index('observeThreads("controls", baseline)'), main.index('stopServices();'))
        self.assertIn('finally { THREAD_ORIGINS.clear(); }', main)
        self.assertIn('observeThreads("shutdown", baseline);', source)
        self.assertIn('deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90)', main)
        self.assertIn('controlDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)', main)
        self.assertIn('long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)', source)

    def test_negative_output_accepts_only_zero_item_lsjson_shapes(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        helper = source[source.index('    private static boolean emptyNegativeListing('):
                        source.index('    private static void negative(')]
        literal = re.search(r'return output\.matches\(("(?:\\.|[^"\\])*")\);', helper).group(1)
        expression = json.loads(literal)
        self.assertIn('new String(stdout, StandardCharsets.US_ASCII)', helper)
        self.assertNotIn('.trim()', helper)
        for text in ('', '[\n', '[\n]\n'):
            with self.subTest(valid=text): self.assertIsNotNone(re.fullmatch(expression, text, flags=re.ASCII))
        for text in ('[', '[]', '[\n]', '[\r\n', '[\n\n', ' [\n', '[\n]\n ', '\n', '\t', '\x00',
                     'null', '{}', '[{}]', '[0]', '["x"]', '[{', '[[', '][', '[]trailing', 'permission denied', '[\u00a0]'):
            with self.subTest(invalid=text): self.assertIsNone(re.fullmatch(expression, text, flags=re.ASCII))
        negative = source[source.index('    private static void negative('):source.index('    private static void wireOracle(')]
        for requirement in ('need(result.code != 0, Code.rclone_denial_exit_zero)',
                            'need(emptyNegativeListing(result.out), Code.rclone_denial_output_invalid)',
                            'relay.counts[1] > 0', 'relay.noneHeaders == relay.counts[1]',
                            'relay.fatalResponses == relay.counts[1]', '!rcloneWireHex.isEmpty()'):
            self.assertIn(requirement, negative)
        positive_body = source[source.index('    private static void positive('):
                               source.index('    private static boolean emptyNegativeListing(')]
        self.assertNotIn('emptyNegativeListing(', positive_body)
        self.assertIn('result.code == 0 && result.err.length == 0', positive_body)

    def test_finite_negative_result_errors_preserve_failure_and_cleanup(self):
        for code in ('rclone_denial_exit_zero', 'rclone_denial_output_invalid', 'rclone_denial_mismatch'):
            value = positive(); value.update(success=False, stage='rclone_none', error=code,
                diagnostic=dict(category='assertion', origin='none'), wire_hex='')
            value['checks'].update(rclone_auth_boundary_rejection=False, wire_auth_boundary_rejection=False,
                listing_after=False, source_preserved=False, cache_preserved=False)
            value['relay']['after_connections'] = 0
            value['cleanup'].update(threads_terminated=False, private_material_removed=False)
            value['remaining_threads']['jdk_timer'] = 1
            value['remaining_thread_intervals']['unattributed'] = 1
            value['remaining_thread_matrix']['jdk_timer']['unattributed'] = 1
            value['remaining_timer_kinds']['unknown'] = 1
            result = F.validate_java(F.canonical(value), 1)
            self.assertFalse(result['success'])
            self.assertEqual(result['rclone_wire_oracle']['category'], 'simple_disabled_kerberos_offered')
            self.assertFalse(result['checks']['rclone_auth_boundary_rejection'])
            self.assertFalse(result['cleanup']['threads_terminated'])
            self.assertFalse(result['cleanup']['private_material_removed'])
            self.assertTrue(all(result[key] is False for key in F.JAVA_FALSE))
            with self.assertRaises(F.ProbeError): F.validate_java(F.canonical(value), 0)

    def test_throwable_projection_preserves_causes_without_exporting_messages(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        self.assertIn('Failure(Code value, Throwable cause) { super(value.name(), cause); code = value; }', source)
        self.assertIn('throw new Failure(Code.unclassified, cause);', source)
        body = source[source.index('    private static String originFrame('):
                      source.index('    private static String threadCategory(')]
        self.assertIn('depth < 8 && seen.add(failure)', body)
        self.assertIn('new java.util.IdentityHashMap<>()', body)
        self.assertIn('i < frames.length && i < 32', body)
        for forbidden in ('getMessage(', 'getLocalizedMessage(', 'toString(', 'printStackTrace(', 'System.out', 'System.err'):
            self.assertNotIn(forbidden, body)
        for marker in ('"missing_class"', '"metrics_failure"', '"namenode_http"', '"http_authentication"'):
            self.assertIn(marker, body)

    def test_thread_projection_counts_all_residuals_and_keeps_cleanup_gate(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        body = source[source.index('    private static String threadCategory('):
                      source.index('    private static String boolMap(')]
        self.assertIn('i < frames.length && i < 32', body)
        self.assertIn('if (!thread.isAlive() || baseline.contains(thread.getId())) continue;', body)
        counter = body[body.index('    private static Map<String, Integer> remainingThreadCounts('):
                       body.index('    private static boolean statisticsCleanerFrame(')]
        self.assertEqual(counter.count('continue;'), 1)
        self.assertIn('need(++total <= 128, Code.cleanup_failed)', body)
        self.assertIn('remainingThreads.values().stream().allMatch(count -> count == 0)', body)
        self.assertIn('&& TASKS.stream().noneMatch(Thread::isAlive)', body)
        self.assertIn('rootOwned && stopped && threadsClean && noListeners', body)
        self.assertNotIn('getName(', body[:body.index('    private static String timerKind(')])
        self.assertNotIn('printStackTrace(', body)
        for category, marker in (('hadoop_fs', 'org.apache.hadoop.fs.'),
                ('hadoop_namenode', 'org.apache.hadoop.hdfs.server.namenode.'),
                ('hadoop_blockmanagement', 'org.apache.hadoop.hdfs.server.blockmanagement.'),
                ('hadoop_util', 'org.apache.hadoop.util.'), ('jdk_cleaner', 'jdk.internal.ref.CleanerImpl')):
            self.assertIn('"' + marker + '"', body)
            self.assertIn('category = "' + category + '"', body)

    def test_secure_namenode_requires_block_tokens_without_datanode(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        body = source[source.index('    private static Configuration configuration('):
                      source.index('    private static void topology()')]
        pairs = re.findall(r'conf\.set\("([^"\n]+)", "([^"\n]*)"\);', body)
        settings = dict(pairs)
        self.assertEqual(len(settings), len(pairs), 'duplicate configuration keys')
        self.assertEqual(settings['hadoop.security.authentication'], 'kerberos')
        self.assertEqual(settings['dfs.block.access.token.enable'], 'true')
        self.assertEqual(settings['ipc.client.fallback-to-simple-auth-allowed'], 'false')
        self.assertNotIn('DataNode.createDataNode', source)

    def test_secure_http_type_is_explicit_with_private_spnego_credentials(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        body = source[source.index('    private static Configuration configuration('):
                      source.index('    private static void topology()')]
        self.assertIn('new HdfsConfiguration(false)', body)
        pairs = re.findall(r'conf\.set\("([^"\n]+)", "([^"\n]*)"\);', body)
        settings = dict(pairs)
        self.assertEqual(len(settings), len(pairs), 'duplicate configuration keys')
        self.assertEqual(settings['hadoop.http.authentication.type'], 'kerberos')
        self.assertEqual(settings['hadoop.security.authentication'], 'kerberos')
        self.assertEqual(settings['dfs.http.policy'], 'HTTP_ONLY')
        self.assertEqual(settings['dfs.namenode.http-bind-host'], '127.0.0.1')
        self.assertEqual(settings['dfs.web.authentication.simple.anonymous.allowed'], 'false')
        expressions = dict(re.findall(r'conf\.set\("([^"\n]+)", ([^\n]+)\);', body))
        # The separate AuthFilter strips only hadoop.http.authentication.; the
        # internal SPNEGO filter obtains its principal/keytab from DFSUtil keys.
        auth = {key.removeprefix('hadoop.http.authentication.'): value
                for key, value in expressions.items() if key.startswith('hadoop.http.authentication.')}
        self.assertEqual(auth, {'type': '"kerberos"', 'kerberos.principal': '"HTTP/127.0.0.1@" + realm',
                                'kerberos.keytab': 'HTTP_KEYTAB.toString()'})
        self.assertEqual(auth['kerberos.principal'], expressions['dfs.namenode.kerberos.internal.spnego.principal'])
        self.assertEqual(auth['kerberos.principal'], expressions['dfs.web.authentication.kerberos.principal'])
        self.assertEqual(auth['kerberos.keytab'], expressions['dfs.web.authentication.kerberos.keytab'])
        self.assertNotIn('conf.addResource(', body)

    def test_version_child_uses_explicit_private_home_and_null_config(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        start = source.index('            stage = "rclone_version";')
        end = source.index('            baseline = threadIds();', start)
        version = source[start:end]
        self.assertIn('List.of("/opt/rpc/rclone", "version", "--config", "/dev/null", "--log-level", "ERROR")', version)
        self.assertIn('Map.of("HOME", "/work/home", "PATH", "/usr/bin:/bin", "LANG", "C", "LC_ALL", "C")', version)
        self.assertNotIn('KRB5_', version)
        for predicate, code in (
            ('version.code == 0', 'rclone_version_nonzero'),
            ('version.err.length == 0', 'rclone_version_stderr'),
            ('startsWith("rclone v1.75.2\\n")', 'rclone_version_mismatch'),
            ('processIds().equals(processBaseline)', 'child_process_drift')):
            self.assertIn(predicate, version); self.assertIn('Code.' + code, version)
        self.assertIn('builder.environment().clear()', source)

    def test_finite_version_and_child_failures_remain_failures(self):
        for code in ('rclone_version_nonzero', 'rclone_version_stderr', 'rclone_version_mismatch',
                     'child_descendant_found', 'child_reap_failed', 'child_streams_alive', 'child_process_drift'):
            value = positive(); value.update(success=False, error=code, stage='rclone_version')
            value['diagnostic'] = dict(category='assertion', origin='none')
            for key in value['checks']:
                value['checks'][key] = key == 'environment'
            value.update(wire_hex='', rclone_wire_hex='', relay=None, cache_bytes=0, observed_lifetime_seconds=0)
            value['cleanup']['threads_terminated'] = False
            result = F.validate_java(F.canonical(value), 1)
            self.assertFalse(result['success']); self.assertEqual(result['error'], code)
            self.assertFalse(result['cleanup']['threads_terminated'])
            self.assertTrue(all(result[key] is False for key in F.JAVA_FALSE))
            with self.assertRaises(F.ProbeError): F.validate_java(F.canonical(value), 0)

    def test_java_source_pin_and_fixed_runtime(self):
        raw = (HERE / "HdfsKerberosRpcProbe.java").read_bytes()
        self.assertEqual(F.sha(raw), F.JAVA_SHA)
        self.assertNotIn(b"MiniDFSCluster", raw)
        self.assertNotIn(b"DataNode.createDataNode", raw)
        self.assertNotIn(b"ignore.secure.ports.for.testing", raw)
        self.assertIn(b'"hadoop.security.authentication", "kerberos"', raw)
        self.assertIn(b'"ipc.client.fallback-to-simple-auth-allowed", "false"', raw)

    def test_same_reader_fixed_endpoint_and_no_inherited_environment(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        self.assertIn('builder.environment().clear()', source)
        self.assertIn('"--hdfs-username", reader', source)
        positive_block = source[source.index('        if (authenticated) {'):source.index('        return child(command, env);')]
        self.assertIn('"KRB5CCNAME", "FILE:" + CACHE', positive_block)
        self.assertIn('"--hdfs-service-principal-name", "hdfs/127.0.0.1"', positive_block)
        self.assertIn('"--hdfs-data-transfer-protection", "privacy"', positive_block)
        order = [source.index('stage = "' + stage + '";') for stage in
                 ('listing_before', 'rclone_none', 'wire_none', 'listing_after', 'preservation')]
        self.assertEqual(order, sorted(order))
        self.assertIn('socket.getOutputStream().write(new byte[]{\'h\',\'r\',\'p\',\'c\',9,0,0})', source)
        self.assertIn('length > 0 && length <= 4096', source)
        self.assertIn('frame.available() == 0', source)
        self.assertIn('input.read() == -1', source)

    def test_private_cleanup_never_precedes_service_shutdown(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        final = source[source.index('        finally {\n            observeThreads("controls", baseline);'):]
        self.assertLess(final.index('stopServices();'), final.index('cleanup(server, baseline)'))
        self.assertIn('entry.getValue().verify(entry.getKey()); Files.delete(entry.getKey())', source)
        self.assertIn('"children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned", "owner_logged_out"', source)
        self.assertIn('controlDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)', source)

    def test_relay_has_one_fixed_endpoint_bounded_unchanged_forwarding_and_owned_shutdown(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        self.assertIn('"--hdfs-namenode", "127.0.0.1:19007"', source)
        self.assertIn('new byte[]{127,0,0,1}), 19007), 4)', source)
        self.assertIn('counts[ownedPhase] >= 4', source)
        self.assertIn('total <= 131072', source)
        self.assertIn('incoming.getOutputStream().write(response)', source)
        self.assertIn('upstream.getOutputStream().write(header)', source)
        self.assertIn('need(phase == ownedPhase', source)
        self.assertIn('relay.noneHeaders == relay.counts[1]', source)
        self.assertIn('relay.fatalResponses == relay.counts[1]', source)
        self.assertIn('listener.isClosed() && sockets.stream().allMatch(Socket::isClosed)', source)
        self.assertIn('Arrays.fill(buffer, (byte)0)', source)


class DownloadDeadlineTests(unittest.TestCase):
    def download_at(self, late, when=270.0):
        clock=types.SimpleNamespace(now=0.0)
        class Response(io.BytesIO):
            status=200
            url='https://repo.maven.apache.org/maven2/synthetic/bytes/1/bytes-1.jar'
            def __init__(self):
                super().__init__(b'jar');self.headers=Message();self.headers['Content-Length']='3'
            def read(self,n=-1):
                value=super().read(n)
                if (late=='final_data' and value) or (late=='eof' and not value):clock.now=when
                return value
            def __exit__(self,*args):
                value=super().__exit__(*args)
                if late=='close':clock.now=when
                return value
        response=Response();opener=Mock();opener.open.return_value=response
        real_hash=F.hashlib.sha256
        class Digest:
            def __init__(self):self.inner=real_hash()
            def update(self,value):self.inner.update(value)
            def hexdigest(self):
                value=self.inner.hexdigest()
                if late=='digest':clock.now=when
                return value
        real_directory=F.directory;visits=[]
        def directory(path,identity=None):
            result=real_directory(path,identity);visits.append(path.name)
            if late=='return' and len(visits)==6:clock.now=when
            return result
        row=dict(group='synthetic',artifact='bytes',version='1',type='jar',classifier='',size=3,sha256=real_hash(b'jar').hexdigest())
        with tempfile.TemporaryDirectory() as temp:
            context=Path(temp)
            with patch.object(F.hashlib,'sha256',Digest),patch.object(F,'directory',side_effect=directory):
                if when>=270:
                    with self.assertRaisesRegex(F.ProbeError,'^download_failed$'):
                        F.download_rows(context,[row],opener=opener,clock=lambda:clock.now)
                else:
                    F.download_rows(context,[row],opener=opener,clock=lambda:clock.now)
            self.assertTrue(response.closed)
            opener.open.assert_called_once()
            self.assertEqual((context/'jars/000.jar').read_bytes(),b'' if late=='final_data' and when>=270 else b'jar')

    def test_late_final_data_is_rejected_before_writing_it(self):
        self.download_at('final_data')
        self.download_at('final_data',271)

    def test_late_eof_is_rejected_even_after_exact_size_and_hash(self):
        self.download_at('eof')
        self.download_at('eof',271)

    def test_close_digest_and_final_identity_work_cannot_outlive_acceptance(self):
        for late in ('close','digest','return'):
            with self.subTest(late=late):self.download_at(late)

    def test_arrival_before_original_deadline_remains_valid_without_extension(self):
        for late in ('final_data','eof','close','digest','return'):
            with self.subTest(late=late):self.download_at(late,269.999)


if __name__ == "__main__":
    unittest.main()


class CommonsIoRuntimePinTests(unittest.TestCase):
    def test_exact_io_selection_and_rebound_stale_descriptor_cannot_use_new_lock(self):
        pins=F.profile_settings('kerberos-remediation')
        descriptor=json.loads(pins['runtime'].read_bytes());lock=pins['lock'].read_bytes()
        rows=F.runtime_rows(pins['runtime'].read_bytes(),lock,profile='kerberos-remediation')
        selected=[row for row in rows if (row['group'],row['artifact'])==('commons-io','commons-io')]
        self.assertEqual(len(selected),1)
        self.assertEqual((selected[0]['version'],selected[0]['size'],selected[0]['sha256']),
            ('2.22.0',609182,'2b9a7b1f726fb86216dbd2c8321eabe0221dbd5b1be81c18e1cb53811b104758'))
        stale=json.loads(pins['runtime'].read_bytes())
        io=next(row for row in stale['entries'] if (row['group'],row['artifact'])==('commons-io','commons-io'))
        io.update(version='2.16.1',size=508826,sha256='f41f7baacd716896447ace9758621f62c1c6b0a91d89acee488da26fc477c84f')
        stale['normalized_sha256']=F.sha(F.canonical(stale['entries']));raw=F.canonical(stale)
        with patch.object(F,'REMEDIATION_RUNTIME_SHA',F.sha(raw)),patch.object(F,'REMEDIATION_ORDER_SHA',stale['normalized_sha256']):
            with self.assertRaises(F.ProbeError):F.runtime_rows(raw,lock,profile='kerberos-remediation')
