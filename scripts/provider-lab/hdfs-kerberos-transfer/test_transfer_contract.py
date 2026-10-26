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


spec = importlib.util.spec_from_file_location("ticket_fixture_under_test", HERE / "transfer_container.py")


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
    return {category: dict(tls=0, datanode=0, kdc=0, owner_login=0, format=0, namenode=0, filesystem=0,
                          reader=0, controls=0, shutdown=0, unattributed=0)
            for category in ('probe_task', 'jdk_process_reaper', 'jdk_timer', 'jdk_executor', 'jdk_cleaner',
                             'hadoop_metrics', 'hadoop_rpc', 'hadoop_fs', 'hadoop_namenode',
                             'hadoop_blockmanagement', 'hadoop_util', 'jetty', 'kerby', 'other')}


def positive():
    # Independent literal wire record, including deliberately narrow evidence label.
    return dict(schema_version=1, scope="hdfs_kerberos_transfer_feasibility", success=True,
        expected_kerby_version="2.1.2", runtime_binding_required=True,
        checks=dict(environment=True, endpoint_settings=True, positive_tgt=True, file_cache_v3=True,
            nonrenewable=True, secure_namenode=True, secure_datanode=True, tls_material=True, tls_endpoints=True, registered_datanode=True, seed_hashes=True, empty_acquired=True, small_acquired=True, missing_path_rejected=True, payload_before=True, payload_after=True, listing_before=True, rclone_auth_boundary_rejection=True,
            wire_auth_boundary_rejection=True, listing_after=True, source_preserved=True, cache_preserved=True),
        cleanup=dict(children_reaped=True, relay_closed=True, filesystem_closed=True, namenode_stop_returned=True, owner_logged_out=True, kdc_stop_returned=True, threads_terminated=True, listeners_absent=True,
            private_material_removed=True, process_property_restored=True, cleanup_completed=True,
            gc_monitor_reaped=True, fs_statistics_cleaner_reaped=True, format_ssl_timer_reaped=True, datanode_stop_returned=True, datanode_ssl_timer_reaped=True),
        owned_thread_cleanup=dict(gc_monitor='terminated', fs_statistics_cleaner='terminated', format_ssl_timer='terminated'),
        child_count=10, acquired_bytes=2109442, missing_category="directory_not_found",
        acquisitions=dict(empty=dict(bytes=0,sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            small=dict(bytes=4096,sha256="c8f5d0341d54d951a71b136e6e2afcb14d11ed8489a7ae126a8fee0df6ecf193"),
            missing=dict(bytes=0,sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            before=dict(bytes=1052673,sha256="ac6f8d639b2e2c683c08d7deae690d1b6120bd74bc80a39a895481450082c571"),
            negative=dict(bytes=0,sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            after=dict(bytes=1052673,sha256="ac6f8d639b2e2c683c08d7deae690d1b6120bd74bc80a39a895481450082c571")),
        cache_bytes=400, observed_lifetime_seconds=119, stage="completed", wire_hex=wire().hex(), rclone_wire_hex=wire().hex(),
        relay=dict(phase_connections=dict(inventory_before=1,empty=1,small=1,missing=1,before=1,negative=1,after=1,inventory_after=1), none_headers=1,
                   fatal_responses=1, unexpected_connections=0, bytes_forwarded_unchanged=True), error=None, ledger_eligible=False,
        diagnostic=dict(category="none", origin="none"),
        remaining_threads=dict(probe_task=0, jdk_process_reaper=0, jdk_timer=0, jdk_executor=0,
            jdk_cleaner=0, hadoop_metrics=0, hadoop_rpc=0, hadoop_fs=0, hadoop_namenode=0,
            hadoop_blockmanagement=0, hadoop_util=0, jetty=0, kerby=0, other=0),
        thread_observation_complete=True,
        remaining_thread_intervals=dict(tls=0, datanode=0, kdc=0, owner_login=0, format=0, namenode=0,
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
                 "JAVA_HOME=/opt/java/openjdk", "LANG=C", "LC_ALL=C", "/bin/sh", "/opt/transfer/driver.sh"]),
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
        value["acquisitions"] = {key: None for key in value["acquisitions"]}
        value["acquired_bytes"] = 0; value["missing_category"] = "not_observed"
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
        runtime = F.REMEDIATION_RUNTIME.read_bytes()
        lock = (F.DISCOVERY / "artifact-lock-kerberos-remediation.json").read_bytes()
        rows = F.runtime_rows(runtime, lock)
        self.assertEqual(len(rows), 142)
        self.assertEqual(sum(x["group"] == "org.apache.kerby" for x in rows), 15)
        modified = json.loads(runtime); modified["entries"].reverse()
        for wrong_runtime, wrong_lock in ((F.canonical(modified), lock), (runtime, lock + b" ")):
            with self.assertRaisesRegex(F.ProbeError, "input_invalid"): F.runtime_rows(wrong_runtime, wrong_lock)

    def test_security_inspection_and_build_have_closed_native_surface(self):
        run_id = "a" * 32; name = "kerberos-transfer-" + run_id; image = "sha256:" + "b" * 64
        value = inspected(name, image, run_id)
        F.inspect_container(value, name, image, run_id)
        for field, bad in (("NetworkMode", "bridge"), ("ReadonlyRootfs", False), ("Privileged", True),
                           ("CapAdd", ["SYS_ADMIN"]), ("Binds", ["/tmp:/work"]), ("PidsLimit", True),
                           ("PortBindings", {"19006/tcp": [{}]}), ("LogConfig", {"Type": "json-file"})):
            altered = copy.deepcopy(value); altered["HostConfig"][field] = bad
            with self.subTest(field=field), self.assertRaises(F.ProbeError): F.inspect_container(altered, name, image, run_id)
        files = F.build_files([dict(sha256="d" * 64)])
        self.assertIn(b"-proc:none -implicit:none", files["Dockerfile"])
        self.assertIn(b"--kill-after=5s 185s", files["driver.sh"])
        self.assertIn(b"-Duser.home=/work/home", files["driver.sh"])

    def fake_run(self, action=None, failure=None, *, profile="kerberos-remediation", real_helpers=False):
        here = self.root / "input"; discovery = self.root / "discovery"
        here.mkdir(); discovery.mkdir()
        java = b"inert Java source"
        (here / "HdfsKerberosTransferProbe.java").write_bytes(java)
        (here / "runtime-classpath.json").write_bytes(b"{}")
        binary = here / "rclone"; binary.write_bytes(b"inert rclone")
        pin = here / "rclone-version.env"
        pin.write_text("RCLONE_VERSION=1.75.2\nRCLONE_LINUX_EXE_SHA256=" + F.sha(b"inert rclone") + "\n")
        (discovery / "artifact-lock-kerberos-remediation.json").write_bytes(b"{}")
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
             REMEDIATION_RUNTIME=here / "runtime-classpath.json",
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
        self.assertEqual(args[0][-1], "kerberos-remediation")
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


class TransferTests(unittest.TestCase):
    def rejected(self,value):
        with self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),0)

    def test_acquisition_truncation_overrun_mutation_swap_and_wrong_total(self):
        for phase in ('empty','small','missing','before','negative','after'):
            for mutation in ('missing','size','hash','extra','null','boolean'):
                value=positive();row=value['acquisitions'][phase]
                if mutation=='missing':del value['acquisitions'][phase]
                elif mutation=='size':row['bytes']+=1
                elif mutation=='hash':row['sha256']='0'*64
                elif mutation=='extra':row['path']='private'
                elif mutation=='null':value['acquisitions'][phase]=None
                else:row['bytes']=True
                with self.subTest(phase=phase,mutation=mutation):self.rejected(value)
        value=positive();value['acquisitions']['before']=value['acquisitions']['small'];self.rejected(value)
        for total in (-1,True,2109441,2109443):
            value=positive();value['acquired_bytes']=total;self.rejected(value)

    def test_missing_path_never_claims_object_or_generic_denial(self):
        for category in ('object_not_found','permission_denied','timeout','not_observed','kerberos_error','dead_endpoint'):
            value=positive();value['missing_category']=category;self.rejected(value)
        value=positive();value['acquisitions']['missing']['bytes']=1;self.rejected(value)

    def test_none_denial_is_byte_empty_and_actual_connection_bound(self):
        for mutation in ('bytes','none','fatal','other_phase','duplicate','wire'):
            value=positive()
            if mutation=='bytes':value['acquisitions']['negative']['bytes']=1
            elif mutation=='none':value['relay']['none_headers']=0
            elif mutation=='fatal':value['relay']['fatal_responses']=0
            elif mutation=='other_phase':value['relay']['phase_connections']['negative']=0
            elif mutation=='duplicate':value['relay']['phase_connections']['negative']=2
            else:value['rclone_wire_hex']=''
            self.rejected(value)

    def test_all_eight_relay_phases_are_closed_single_and_no_reconnect(self):
        for phase in ('inventory_before','empty','small','missing','before','negative','after','inventory_after'):
            for count in (0,2,True,-1):
                value=positive();value['relay']['phase_connections'][phase]=count;self.rejected(value)
        for mutation in ('missing','extra','unattributed','changed'):
            value=positive()
            if mutation=='missing':del value['relay']['phase_connections']['small']
            elif mutation=='extra':value['relay']['phase_connections']['extra']=1
            elif mutation=='unattributed':value['relay']['unexpected_connections']=1
            else:value['relay']['bytes_forwarded_unchanged']=False
            self.rejected(value)

    def test_datanode_partial_constructor_or_stop_never_cleanup_credit(self):
        for gate in ('datanode_stop_returned','datanode_ssl_timer_reaped','threads_terminated','listeners_absent','private_material_removed'):
            value=positive();value['cleanup'][gate]=False;self.rejected(value)
            value.update(success=False,error='cleanup_failed')
            self.assertFalse(F.validate_java(F.canonical(value),1)['success'])

    def test_late_second_ssl_timer_is_residual_not_exemption(self):
        value=positive();value.update(success=False,error='cleanup_failed')
        value['remaining_threads']['jdk_timer']=1;value['remaining_thread_intervals']['datanode']=1
        value['remaining_thread_matrix']['jdk_timer']['datanode']=1;value['remaining_timer_kinds']['ssl_store']=1
        value['cleanup']['threads_terminated']=False;value['cleanup']['datanode_ssl_timer_reaped']=False
        self.assertFalse(F.validate_java(F.canonical(value),1)['success'])
        value['remaining_thread_matrix']['jdk_timer']['format']=1
        with self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),1)

    def test_exact_new_graph_and_cross_profile_rejection_before_reads(self):
        self.assertEqual(F.PROFILES,('kerberos-remediation',))
        p=F.profile_settings('kerberos-remediation');rows=F.runtime_rows(p['runtime'].read_bytes(),p['lock'].read_bytes())
        self.assertEqual((len(rows),sum(x['size'] for x in rows)),(142,73004295))
        old=(HERE.parent/'hdfs-kerberos-ticket/runtime-classpath.json').read_bytes()
        with self.assertRaises(F.ProbeError):F.runtime_rows(old,p['lock'].read_bytes())
        for profile in ('kerberos','simple','',None,True,{},'../kerberos-remediation'):
            with patch.object(F,'read',side_effect=AssertionError('read forbidden')),patch.object(F,'hosted_guard',side_effect=AssertionError('host forbidden')):
                with self.assertRaises(F.ProbeError):F.profile_settings(profile)
                self.assertFalse(F.run(profile=profile)['success'])
                self.assertEqual(F.main(['--download-worker','/tmp/context','1','2','a'*64,profile]),1)

    def test_worker_requires_exact_argv_and_fixed_lock_basename(self):
        for args in (['--download-worker'],['--download-worker','/tmp/context','1','2','a'*64],['--download-worker','/tmp/context','1','2','a'*64,'kerberos-remediation','extra']):
            with patch.object(F,'read',side_effect=AssertionError('file forbidden')):
                self.assertEqual(F.main(args),1)
        pins=F.profile_settings('kerberos-remediation'); paths=[]
        def reader(path,maximum):
            paths.append(path.name)
            return pins['runtime'].read_bytes() if path.name=='runtime-classpath.json' else pins['lock'].read_bytes()
        with patch.object(F,'hosted_guard'),patch.object(F,'directory'),patch.object(F,'file_hash',return_value='a'*64),patch.object(F,'read',side_effect=reader),patch.object(F,'download_rows') as downloader:
            self.assertEqual(F.main(['--download-worker',str(HERE/'context'),'1','2','a'*64,'kerberos-remediation']),0)
            downloader.assert_called_once()
        self.assertEqual(paths,['runtime-classpath.json','artifact-lock-kerberos-remediation.json'])

    def test_source_pin_webapps_classpath_and_receipt_limit(self):
        raw=(HERE/'HdfsKerberosTransferProbe.java').read_bytes();self.assertEqual(F.sha(raw),F.JAVA_SHA)
        files=F.build_files([dict(sha256='d'*64)])
        self.assertEqual(files['classpath'],b'/opt/transfer/classes:/opt/transfer/jars/000.jar:/work/tls-resources\n')
        self.assertIn('webapps/datanode/WEB-INF/web.xml',F.webapp_resources())
        self.assertIn(b'185s',files['driver.sh'])
        source=(HERE/'transfer_container.py').read_text()
        self.assertIn('len(data) <= 65536',source)
        self.assertIn('timeout=195, limit=32768',source)

    def test_native_surface_source_contains_no_secret_argv_or_test_bypass(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        self.assertIn('"-storepass:file", PASSWORD.toString(), "-keypass:file", PASSWORD.toString()',source)
        self.assertNotIn('"-storepass",',source);self.assertNotIn('"-keypass",',source)
        self.assertIn('conf.set("ignore.secure.ports.for.testing", "false")',source)
        self.assertIn('conf.set("dfs.data.transfer.protection", "privacy")',source)
        self.assertIn('conf.set("dfs.http.policy", "HTTPS_ONLY")',source)
        self.assertIn('conf.set("dfs.block.access.token.enable", "true")',source)
        self.assertIn('resolver.getClass() == org.apache.hadoop.hdfs.protocol.datatransfer.TrustedChannelResolver.class',source)
        self.assertNotIn('MiniDFSCluster',source);self.assertNotIn('SecureDataNodeStarter',source)
        self.assertNotIn('setAccessible(',source);self.assertNotIn('System.getenv("HOME")',source)

    def test_retained_ssl_identity_and_subjects_are_not_generic_cleanup(self):
        s=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        for required in ('formatSslFactory = Util.connectionFactory','thread == formatSslThread','"datanode".equals(THREAD_ORIGINS.get(thread))','datanodeSslThread == null','!baseline.contains(thread.getId())','datanodeSslThread.isAlive()','finally { rememberOwner(); }','OWNERS.add(current)','login.logoutUserFromKeytab()'):
            self.assertIn(required,s)
        cleanup=s[s.index('private static void stopServices()'):s.index('public static void main(')]
        self.assertNotIn('.interrupt()',cleanup);self.assertNotIn('Timer.cancel',cleanup)
        self.assertIn('boolean dnStopped = !datanodeAttempted',cleanup)
        self.assertIn('}, 35, dnUntil)',cleanup)

    def test_streaming_has_expected_plus_one_drain_and_exclusive_identity(self):
        s=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        for required in ('expected-total+1','need(total+n<=expected','FileChannel.open(target, StandardOpenOption.WRITE, NOFOLLOW)','original.key.equals(independentlyRead.key)','MessageDigest.isEqual(observed.digest,independentlyRead.digest)','process.destroyForcibly()','process.waitFor(Math.max(1,until-System.nanoTime())','CHILDREN.size()<10','streamed.isDone()','stderr.isDone()'):
            self.assertIn(required,s)
        self.assertNotIn('readAllBytes()',s)

    def test_deadlines_and_baseline_are_fixed_and_incomplete_observation_fails(self):
        s=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        for required in ('TimeUnit.SECONDS.toNanos(185)','TimeUnit.SECONDS.toNanos(70)','TimeUnit.SECONDS.toNanos(55)','TimeUnit.SECONDS.toNanos(60)','OBSERVED_PHASES.size() == 10','THREAD_ORIGINS.size() < 1280','new java.util.IdentityHashMap<>()','Math.min(cleanupDeadline, System.nanoTime() + TimeUnit.SECONDS.toNanos(3))'):
            self.assertIn(required,s)
        self.assertEqual(s.count('baseline = threadIds()'),2)

    def test_independent_dataset_digests_and_multiblock_boundary(self):
        import hashlib
        for size,expected in ((0,'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),(4096,'c8f5d0341d54d951a71b136e6e2afcb14d11ed8489a7ae126a8fee0df6ecf193'),(1052673,'ac6f8d639b2e2c683c08d7deae690d1b6120bd74bc80a39a895481450082c571')):
            data=bytes(range(256))*(size//256)+bytes(range(size%256))
            self.assertEqual(hashlib.sha256(data).hexdigest(),expected)
            if size:self.assertNotEqual(hashlib.sha256(data[:-1]+bytes([data[-1]^1])).hexdigest(),expected)
        self.assertGreater(1052673,1048576)

    def test_separate_workflow_exact_head_read_only_and_fixed_profile(self):
        workflow=(HERE.parents[2]/'.github/workflows/hdfs-kerberos-transfer.yml').read_text()
        for required in ('workflow_dispatch:','contents: read','persist-credentials: false','github.event.pull_request.head.sha || github.sha','--profile kerberos-remediation','hdfs-kerberos-transfer/transfer_container.py'):
            self.assertIn(required,workflow)
        self.assertNotIn('pull_request_target',workflow)

    def test_exact_child_count_and_no_additional_native_helper(self):
        for count in (0,9,11,True,128):
            value=positive();value['child_count']=count;self.rejected(value)
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        self.assertEqual(source.count('builder.start()'),1)
        self.assertIn('reservations.size() == 8',source)
        self.assertIn('port = 19000; port <= 19007',source)
        self.assertIn('value == nextPhase',source)

    def test_fake_native_stream_failure_codes_cannot_pass_after_clean_outer_reap(self):
        # Real supervisor, fake Docker: preserve each closed failure category and
        # independently require the same container/image/context removal gates.
        for code in ('acquisition_invalid','child_streams_alive','child_reap_failed','deadline_exceeded','missing_path_mismatch','datanode_failed','tls_invalid'):
            original=FakeDocker.__init__
            def initialize(fake,root,*,max_calls):
                original(fake,root,max_calls=max_calls)
                fake.java.update(success=False,error=code,diagnostic=dict(category='assertion',origin='none'))
                fake.exit_code=1
            helper=TicketTests(methodName='test_full_mock_success_binds_context_and_cleans');helper.setUp()
            try:
                with patch.object(FakeDocker,'__init__',initialize):report,docker=helper.fake_run()
                self.assertFalse(report['success']);self.assertEqual(report['errors'],['java_probe_failed'])
                self.assertEqual(report['result']['error'],code)
                self.assertTrue(all(report['cleanup'].values()));self.assertFalse(docker.root.exists())
            finally:helper.tearDown()

    def test_fake_tls_and_datanode_cleanup_uncertainty_is_sticky(self):
        for gate in ('datanode_stop_returned','datanode_ssl_timer_reaped','owner_logged_out','private_material_removed'):
            original=FakeDocker.__init__
            def initialize(fake,root,*,max_calls):
                original(fake,root,max_calls=max_calls)
                fake.java['cleanup'][gate]=False;fake.java.update(success=False,error='cleanup_failed');fake.exit_code=1
            helper=TicketTests(methodName='test_full_mock_success_binds_context_and_cleans');helper.setUp()
            try:
                with patch.object(FakeDocker,'__init__',initialize):report,docker=helper.fake_run()
                self.assertFalse(report['success']);self.assertFalse(report['result']['cleanup'][gate])
                self.assertTrue(all(report['cleanup'].values()))
            finally:helper.tearDown()

    def test_missing_log_parser_and_private_outputs_are_source_bounded(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        for required in ('error.size()==6','error listing: directory not found','error.path("objectType").asText().equals("string")','FAIL_ON_TRAILING_TOKENS','STRICT_DUPLICATE_DETECTION','privateBytes(target,new byte[0])','original.key.equals(independentlyRead.key)','actual.equals(OWNED_FILES.keySet())','PRIVATE_DIRS.get(path).equals(directory(path, true))'):
            self.assertIn(required,source)
        self.assertIn('boolean loggedOut = ownerCaptureComplete',source)
        self.assertIn('ownerCaptureComplete = false',source)
        self.assertIn('OWNERS.size() < 4',source)

    def test_lexical_java_delimiters_are_balanced_without_native_compilation(self):
        # Pure lexical smoke only, deliberately not advertised as javac/type proof.
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        token=re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}()\[\]]',re.S)
        stack=[];pairs={'}':'{',')':'(',']':'['}
        for match in token.finditer(source):
            value=match.group()
            if value in ('{','(','['):stack.append(value)
            elif value in pairs:self.assertTrue(stack);self.assertEqual(stack.pop(),pairs[value])
        self.assertEqual(stack,[])

class DeadlineTests(unittest.TestCase):
    def test_subtimeout_and_private_deletion_do_not_borrow_extra_budget(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        bounded=source[source.index('private static <T> T bounded('):source.index('private static String random(')]
        self.assertIn('long taskUntil = Math.min(until, System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds))',bounded)
        self.assertIn('long remaining = taskUntil - System.nanoTime()',bounded)
        self.assertIn('long left = Math.min(TimeUnit.MILLISECONDS.toNanos(200), taskUntil - System.nanoTime())',bounded)
        cleanup=source[source.index('materialDeadline = cap(2)'):source.index('CLEANUP.put("private_material_removed"')]
        self.assertEqual(cleanup.count('need(System.nanoTime() < materialDeadline'),2)
        self.assertIn('removed = System.nanoTime() < materialDeadline',cleanup)
        self.assertNotIn('System.nanoTime() < cleanupDeadline',cleanup)

class ReviewRegressionTests(unittest.TestCase):
    def test_generated_build_and_driver_reference_only_the_owned_transfer_root(self):
        generated=F.build_files([dict(sha256='a'*64),dict(sha256='b'*64)])
        for name,raw in generated.items():
            self.assertNotIn(b'/opt/rpc',raw,name)
            roots=set(re.findall(rb'/opt/[a-z][a-z0-9_-]*',raw))
            self.assertLessEqual(roots,{b'/opt/transfer',b'/opt/java'},name)
        docker=generated['Dockerfile']
        self.assertIn(b'COPY jars /opt/transfer/jars/',docker)
        self.assertIn(b'COPY HdfsKerberosTransferProbe.java checksums driver.sh classpath /opt/transfer/',docker)
        self.assertIn(b'cp -R /opt/transfer/resources/webapps /opt/transfer/classes/ && chmod -R a=rX /opt/transfer && chmod 0555 /opt/transfer/rclone',docker)
        self.assertTrue(all(line.split(b'  ',1)[1].startswith(b'/opt/transfer/') for line in generated['checksums'].splitlines()))

    def test_bounded_task_recomputes_after_start_and_rejects_late_completion(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        bounded=source[source.index('private static <T> T bounded('):source.index('private static String random(')]
        order=[bounded.index('final long taskUntil'),bounded.index('thread.start();'),
               bounded.index('long remaining = taskUntil - System.nanoTime()'),bounded.index('need(remaining > 0'),
               bounded.index('result = task.get(remaining, TimeUnit.NANOSECONDS)'),
               bounded.index('need(System.nanoTime() < taskUntil'),bounded.index('finally {'),
               bounded.index('if (!task.isDone()) task.cancel(true)'),bounded.index('long left = Math.min'),
               bounded.index('thread.join(left / 1_000_000L, (int)(left % 1_000_000L))')]
        self.assertEqual(order,sorted(order))
        self.assertEqual(bounded.count('taskUntil ='),1)
        self.assertEqual(bounded.count('need(System.nanoTime() < taskUntil'),2)
        self.assertLess(bounded.rindex('need(System.nanoTime() < taskUntil'),bounded.index('return result;'))
        self.assertNotIn('Math.max(1',bounded)
        self.assertNotIn('return task.get(',bounded)
        self.assertNotIn('never starts a DataNode or transfers bytes',source)

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

class TlsDiagnosticTests(unittest.TestCase):
    CODES=('tls_keytool_exit_invalid','tls_store_shape_invalid','tls_certificate_key_invalid',
           'tls_certificate_signature_invalid','tls_certificate_lifetime_invalid','tls_certificate_san_invalid',
           'tls_resource_missing','tls_resource_identity_invalid','tls_resource_ambiguous')

    def failed_tls(self,code):
        value=positive();value.update(success=False,error=code,stage='tls',child_count=2,acquired_bytes=0,
            missing_category='not_observed',cache_bytes=0,observed_lifetime_seconds=0,wire_hex='',rclone_wire_hex='',relay=None,
            diagnostic=dict(category='assertion',origin='none'),thread_observation_complete=False)
        value['checks']={key:key=='environment' for key in value['checks']}
        value['acquisitions']={key:None for key in value['acquisitions']}
        for helper in ('gc_monitor','fs_statistics_cleaner','format_ssl_timer'):
            value['cleanup'][helper+'_reaped']=False
            value['owned_thread_cleanup'][helper]='observation_incomplete'
        value['cleanup']['private_material_removed']=False
        return value

    def test_each_fixed_tls_label_preserves_failure_and_partial_cleanup(self):
        for code in self.CODES:
            value=self.failed_tls(code)
            with self.subTest(code=code):
                output=F.validate_java(F.canonical(value),1)
                self.assertEqual(output['error'],code)
                self.assertFalse(output['success']);self.assertFalse(output['cleanup']['private_material_removed'])
                self.assertFalse(output['thread_observation_complete'])
                self.assertTrue(all(output[key] is False for key in F.JAVA_FALSE))
                with self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),0)

    def test_tls_diagnostics_cannot_publish_text_or_promote_success(self):
        for bad in ('tls_private_detail',{'message':'private'},'tls_resource_missing: file:///private',True):
            value=self.failed_tls('tls_resource_missing');value['error']=bad
            with self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),1)
        value=self.failed_tls('tls_resource_missing');value['private_error']='private'
        with self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),1)
        for code in self.CODES:
            value=positive();value['error']=code
            with self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),0)

    def test_tls_assertions_keep_exact_original_success_requirements(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        method=source[source.index('private static void makeTls()'):source.index('private static void verifyTlsEndpoint(')]
        for predicate in ('keytool.code == 0','store.size() == 1 && store.isKeyEntry("owned")',
            'cert.checkValidity()','cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey',
            'getModulus().bitLength() == 2048','cert.getSigAlgName().equalsIgnoreCase("SHA256withRSA")',
            'cert.getNotAfter().getTime() - cert.getNotBefore().getTime() == 86400000L',
            'cert.getSubjectAlternativeNames().size() == 1','cert.getSubjectAlternativeNames().contains(List.of(7, "127.0.0.1"))',
            'urls.hasMoreElements()','urls.nextElement().toURI().equals(SSL_XML.toUri())','!urls.hasMoreElements()'):
            self.assertIn(predicate,method)
        for code in self.CODES:self.assertEqual(method.count('Code.'+code),1)
        self.assertNotIn('Code.tls_invalid',method)

    def test_keytool_buffers_are_erased_in_finally_before_store_inspection(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        exact='try { need(keytool.code == 0, Code.tls_keytool_exit_invalid); }\n            finally { Arrays.fill(keytool.out, (byte)0); Arrays.fill(keytool.err, (byte)0); }'
        self.assertIn(exact,source)
        self.assertLess(source.index(exact),source.index('OWNED_FILES.put(STORE, new FileState(STORE))'))
        method=source[source.index('private static void makeTls()'):source.index('private static void verifyTlsEndpoint(')]
        for forbidden in ('new String(keytool.','getMessage()','printStackTrace','System.out','System.err','report.'):
            self.assertNotIn(forbidden,method)

class ResourceDirectoryStartupTests(unittest.TestCase):
    def test_generated_driver_creates_exclusive_private_classpath_directory_before_java(self):
        files=F.build_files([dict(sha256='a'*64)])
        lines=files['driver.sh'].decode().splitlines()
        # Strict mkdir without -p must reject a preexisting file, link or directory.
        self.assertEqual(lines[:4],['#!/bin/sh','set -eu','umask 077',
            'mkdir /work/home /work/tmp /work/tls-resources'])
        self.assertEqual(len(lines),5)
        self.assertTrue(lines[4].startswith('exec /usr/bin/timeout --signal=TERM --kill-after=5s 185s /opt/java/openjdk/bin/java '))
        self.assertTrue(files['classpath'].endswith(b':/work/tls-resources\n'))
        self.assertEqual(files['classpath'].count(b'/work/'),1)
        checks=dict(line.split(b'  ',1)[::-1] for line in files['checksums'].splitlines())
        self.assertEqual(checks[b'/opt/transfer/driver.sh'],F.sha(files['driver.sh']).encode())
        self.assertEqual(checks[b'/opt/transfer/classpath'],F.sha(files['classpath']).encode())

    def test_resource_adoption_rejects_nonempty_changed_or_unowned_directory(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        adopt=source[source.index('private static void adoptResourceDirectory()'):source.index('private static void guardRoot()')]
        ordered=['guardRoot();','need(System.nanoTime() < deadline, Code.deadline_exceeded);',
            'need(!PRIVATE_DIRS.containsKey(RESOURCES), Code.source_changed);',
            'Object key = directory(RESOURCES, true);','try (DirectoryStream<Path> stream = Files.newDirectoryStream(RESOURCES))',
            'need(!stream.iterator().hasNext(), Code.unexpected_files);','guardRoot();',
            'need(key.equals(directory(RESOURCES, true)), Code.source_changed);',
            'need(System.nanoTime() < deadline, Code.deadline_exceeded);','PRIVATE_DIRS.put(RESOURCES, key);']
        offset=0
        for required in ordered:offset=adopt.index(required,offset)+len(required)
        self.assertEqual(adopt.count('PRIVATE_DIRS.put('),1)
        for forbidden in ('createDirectory','Files.delete','setAttribute','catch (','new ArrayList','toList('):
            self.assertNotIn(forbidden,adopt)
        directory=source[source.index('private static Object directory('):source.index('// The exclusive driver mkdir')]
        for required in ('BasicFileAttributes.class, NOFOLLOW','a.isDirectory() && !a.isSymbolicLink() && a.fileKey() != null',
            '"unix:uid", NOFOLLOW)).intValue() == 10001','"unix:gid", NOFOLLOW)).intValue() == 10001',
            '"unix:mode", NOFOLLOW)).intValue() & 07777) == 0700'):
            self.assertIn(required,directory)
        main=source[source.index('public static void main('):source.index('private static void privateBytes(')]
        self.assertEqual(main.count('adoptResourceDirectory();'),1)
        self.assertLess(main.index('PRIVATE_DIRS.put(ROOT, rootKey)'),main.index('adoptResourceDirectory();'))
        self.assertLess(main.index('adoptResourceDirectory();'),main.index('makeTls();'))
        self.assertIn('for (Path path : List.of(TLS, ACQUIRED))',main)
        self.assertNotIn('List.of(TLS, RESOURCES, ACQUIRED)',main)

    def test_precreated_resource_prevents_false_early_cleanup_credit(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        cleanup=source[source.index('// The driver creates RESOURCES before Java'):source.index('CLEANUP.put("private_material_removed"')]
        self.assertIn('boolean removed = false;',cleanup)
        self.assertNotIn('!rootCreated',cleanup)
        self.assertIn('if (rootOwned && PRIVATE_DIRS.containsKey(RESOURCES) && stopped && threadsClean && noListeners &&',cleanup)
        self.assertEqual(cleanup.count('removed ='),3)
        ordered=['PRIVATE_DIRS.containsKey(RESOURCES)','materialDeadline = cap(2); guardRoot();','inventory();',
            'need(PRIVATE_DIRS.get(path).equals(directory(path, true)), Code.source_changed);',
            'need(!stream.iterator().hasNext(), Code.unexpected_files);','Files.delete(path);',
            'removed = System.nanoTime() < materialDeadline && PRIVATE_DIRS.keySet().stream().noneMatch(p -> Files.exists(p, NOFOLLOW));',
            'catch (Throwable ignored) { removed = false; }']
        positions=[cleanup.index(s) for s in ordered];self.assertEqual(positions,sorted(positions))

    def test_adoption_failures_keep_finite_errors_and_incomplete_cleanup(self):
        for code in ('path_invalid','source_changed','unexpected_files','deadline_exceeded'):
            with self.subTest(code=code):
                value=TlsDiagnosticTests().failed_tls(code)
                value.update(stage='rclone_version',child_count=1)
                result=F.validate_java(F.canonical(value),1)
                self.assertFalse(result['success']);self.assertEqual(result['error'],code)
                self.assertFalse(result['cleanup']['private_material_removed'])
                self.assertFalse(result['thread_observation_complete'])
                self.assertTrue(all(result[key] is False for key in F.JAVA_FALSE))
                with self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),0)

class LinkageDiagnosticTests(unittest.TestCase):
    TYPES={
        'NoSuchMethodError':'linkage_no_such_method','NoSuchFieldError':'linkage_no_such_field',
        'AbstractMethodError':'linkage_abstract_method','IllegalAccessError':'linkage_illegal_access',
        'InstantiationError':'linkage_instantiation','IncompatibleClassChangeError':'linkage_incompatible_class',
        'ExceptionInInitializerError':'linkage_initializer','BootstrapMethodError':'linkage_bootstrap',
        'ClassCircularityError':'linkage_circularity','ClassFormatError':'linkage_class_format',
        'UnsupportedClassVersionError':'linkage_class_version','UnsatisfiedLinkError':'linkage_native',
        'VerifyError':'linkage_verify'}
    SITES={'metrics_system_register','metrics_system_register_source','datanode_metrics_constructor',
        'datanode_metrics_create','metrics_source_builder_constructor','metrics_source_builder_registry',
        'metrics_source_builder_add','metrics_source_builder_build','metrics_source_builder_info',
        'metrics_factory_field','metrics_factory_method','metrics_factory_info','metrics_factory_name',
        'metrics_annotations_builder','method_metric_constructor','jvm_metrics_create','jvm_metrics_register',
        'metrics_registry_counter','metrics_registry_gauge','metrics_registry_rate','metrics_registry_rates_aggregation',
        'metrics_registry_stat','metrics_registry_rolling','metrics_registry_quantiles'}

    def failure(self,category='linkage_no_such_method',origin='metrics_source_builder_add'):
        value=TlsDiagnosticTests().failed_tls('unclassified')
        value.update(stage='datanode_start',diagnostic=dict(category=category,origin=origin))
        value['cleanup'].update(datanode_stop_returned=False,datanode_ssl_timer_reaped=False,
            threads_terminated=False,private_material_removed=False)
        return value

    def test_exact_linkage_classes_have_finite_labels_and_unknown_fallback(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        method=source[source.index('private static String linkageCategory('):source.index('private static String originFrame(')]
        observed=dict(re.findall(r'case "java\.lang\.([A-Za-z]+)" -> "([a-z_]+)";',method))
        self.assertEqual(observed,self.TYPES)
        self.assertIn('switch (failure.getClass().getName())',method)
        self.assertIn('default -> "linkage_failure";',method)
        for forbidden in ('getMessage','getLocalizedMessage','toString()','print','instanceof','Class.forName'):
            self.assertNotIn(forbidden,method)
        self.assertLessEqual(set(self.TYPES.values()),F.DIAGNOSTIC_CATEGORIES)

    def test_known_callsites_are_exact_markers_not_private_target_text(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        method=source[source.index('private static String originFrame('):source.index('private static void projectFailure(')]
        self.assertLessEqual(self.SITES,F.DIAGNOSTIC_ORIGINS)
        for label in self.SITES:self.assertEqual(method.count('-> "'+label+'";'),1)
        for exact in ('"org.apache.hadoop.metrics2.lib.MetricsSourceBuilder"','"org.apache.hadoop.metrics2.lib.MutableMetricsFactory"',
            '"org.apache.hadoop.metrics2.lib.MethodMetric"','"org.apache.hadoop.hdfs.server.datanode.metrics.DataNodeMetrics"',
            'case "newSourceBuilder" -> "metrics_annotations_builder";',
            'case "newForField" -> "metrics_factory_field";',
            'case "registerSource" -> "metrics_system_register_source";'):
            self.assertIn(exact,method)
        self.assertIn('default -> null;',method)
        for forbidden in ('getMessage','getLineNumber','startsWith','substring','toString()','Class.forName'):
            self.assertNotIn(forbidden,method)

    def test_selected_cause_owns_marker_and_existing_bounds_priorities_remain(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        method=source[source.index('private static void projectFailure('):source.index('private static String threadCategory(')]
        self.assertIn('depth < 8 && seen.add(failure)',method)
        self.assertIn('frames.length && i < 32',method)
        self.assertIn('selected = category; selectedRank = rank; origin = "none";',method)
        self.assertEqual(method.count('failure.getStackTrace()'),1)
        self.assertLess(method.index('if (rank < selectedRank) {'),method.index('failure.getStackTrace()'))
        self.assertLess(method.index('failure instanceof ClassNotFoundException || failure instanceof NoClassDefFoundError'),
            method.index('failure instanceof LinkageError'))
        self.assertIn('category = linkageCategory((LinkageError) failure); rank = 4;',method)
        self.assertIn('A callsite identifies a frame, never the unresolved linkage target.',method)
        for forbidden in ('getMessage','getLocalizedMessage','printStackTrace','Class.forName','new Thread','interrupt('):
            self.assertNotIn(forbidden,method)

    def test_each_linkage_class_and_callsite_preserves_failed_cleanup(self):
        for category,origin in [(label,'metrics_system_register') for label in self.TYPES.values()]+[('linkage_no_such_method',label) for label in self.SITES]:
            with self.subTest(category=category,origin=origin):
                value=self.failure(category,origin);result=F.validate_java(F.canonical(value),1)
                self.assertEqual(result['diagnostic'],dict(category=category,origin=origin))
                self.assertFalse(result['success']);self.assertFalse(result['thread_observation_complete'])
                for key in ('datanode_stop_returned','datanode_ssl_timer_reaped','threads_terminated','private_material_removed'):
                    self.assertIs(result['cleanup'][key],False)
                self.assertTrue(all(result[key] is False for key in F.JAVA_FALSE))
                with self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),0)

    def test_raw_unknown_symbol_or_success_promotion_is_rejected(self):
        for diagnostic in (dict(category='java.lang.NoSuchMethodError',origin='metrics_system_register'),
            dict(category='linkage_no_such_method',origin='org.example.Private.method'),
            dict(category='linkage_no_such_method: private',origin='none'),
            dict(category='linkage_no_such_method',origin='metrics_system_register',symbol='private'),
            dict(category='linkage_no_such_method',origin='metrics_factory_field',message='private')):
            value=self.failure();value['diagnostic']=diagnostic
            with self.subTest(diagnostic=diagnostic),self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),1)
        for origin in self.SITES:
            value=positive();value['diagnostic']=dict(category='linkage_no_such_method',origin=origin)
            with self.subTest(origin=origin),self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),0)

class RemainingMetricsCallsiteTests(unittest.TestCase):
    METHODS={
        'org.apache.hadoop.metrics2.lib.DefaultMetricsSystem':set('getImpl init shutdownInstance setImpl initialize instance shutdown setInstance setMiniClusterMode inMiniClusterMode newMBeanName removeMBeanName removeSourceName sourceName newObjectName removeObjectName removeSource newSourceName'.split()),
        'org.apache.hadoop.metrics2.impl.MetricsSystemImpl':set('<init> init start stop register unregisterSource registerSource registerSink getProxyForCallback startMetricsMBeans stopMetricsMBeans currentConfig startTimer onTimerEvent publishMetricsNow sampleMetrics snapshotMetrics publishMetrics stopTimer stopSources stopSinks configure configureSystem configureSinks newSink configureSources clearConfigs getHostname registerSystemSource getMetrics initSystemMBean shutdown getSource getSourceAdapter getSinkAdapter initMode'.split())}

    def mappings(self):
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        origin=source[source.index('private static String originFrame('):source.index('private static void projectFailure(')]
        out={}
        for cls,methods in self.METHODS.items():
            pattern=r'case "'+re.escape(cls)+r'" -> switch \(frame.getMethodName\(\)\) \{(.*?)\n            \};'
            match=re.search(pattern,origin,re.S);self.assertIsNotNone(match)
            pairs=re.findall(r'case "([A-Za-z<>]+)" -> "([a-z_]+)";',match.group(1))
            self.assertEqual(len(pairs),len(methods));self.assertEqual({p[0] for p in pairs},methods)
            self.assertIn('default -> "hadoop_metrics";',match.group(1))
            out[cls]=dict(pairs)
        return out

    def test_only_declared_known_metrics_methods_are_exported_as_fixed_markers(self):
        mappings=self.mappings();labels=[label for m in mappings.values() for label in m.values()]
        self.assertEqual(len(labels),54);self.assertEqual(len(labels),len(set(labels)))
        self.assertLessEqual(set(labels),F.DIAGNOSTIC_ORIGINS)
        self.assertEqual(mappings['org.apache.hadoop.metrics2.lib.DefaultMetricsSystem']['newSourceName'],'default_metrics_new_source_name')
        self.assertEqual(mappings['org.apache.hadoop.metrics2.impl.MetricsSystemImpl']['getProxyForCallback'],'metrics_system_get_proxy_for_callback')
        self.assertEqual(mappings['org.apache.hadoop.metrics2.impl.MetricsSystemImpl']['configure'],'metrics_system_configure')
        self.assertEqual(mappings['org.apache.hadoop.metrics2.impl.MetricsSystemImpl']['register'],'metrics_system_register')

    def test_unknown_methods_keep_generic_fallback_without_prefix_or_text_matching(self):
        self.mappings()
        source=(HERE/'HdfsKerberosTransferProbe.java').read_text()
        origin=source[source.index('private static String originFrame('):source.index('private static void projectFailure(')]
        self.assertEqual(origin.count('default -> "hadoop_metrics";'),2)
        for forbidden in ('getMessage','getLocalizedMessage','getLineNumber','startsWith','substring','toString()','Class.forName'):
            self.assertNotIn(forbidden,origin)
        for cls in self.METHODS:self.assertEqual(origin.count('case "'+cls+'"'),1)

    def test_every_refined_method_preserves_the_failed_native_boundary(self):
        for methods in self.mappings().values():
            for method,label in methods.items():
                with self.subTest(method=method,label=label):
                    value=LinkageDiagnosticTests().failure(origin=label)
                    result=F.validate_java(F.canonical(value),1)
                    self.assertEqual(result['diagnostic'],dict(category='linkage_no_such_method',origin=label))
                    self.assertFalse(result['success']);self.assertFalse(result['thread_observation_complete'])
                    self.assertFalse(result['cleanup']['datanode_stop_returned']);self.assertFalse(result['cleanup']['private_material_removed'])
                    self.assertTrue(all(result[k] is False for k in F.JAVA_FALSE))
                    with self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),0)

    def test_unmapped_private_symbols_and_success_promotion_are_rejected(self):
        for label in ('default_metrics_private','metrics_system_private','default_metrics_initialize(private)',
            'org.apache.hadoop.metrics2.impl.MetricsSystemImpl.configure','getProxyForCallback',True):
            value=LinkageDiagnosticTests().failure(origin=label)
            with self.subTest(label=label),self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),1)
        for methods in self.mappings().values():
            for label in methods.values():
                value=positive();value['diagnostic']=dict(category='linkage_no_such_method',origin=label)
                with self.subTest(label=label),self.assertRaises(F.ProbeError):F.validate_java(F.canonical(value),0)
