"""Pure adversarial receipt replay; no application or provider execution."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "azureblob_application_evidence.py"
E = types.ModuleType("azureblob_evidence_test"); E.__file__ = str(PATH)
exec(compile(PATH.read_bytes(), str(PATH), "exec"), E.__dict__)
RUNTIME = dict(version="1.75.2", sha256="1"*64, platform="windows")
BINDINGS = {key: "2"*64 for key in E.A.BINDING_KEYS}
BINDINGS.update(build_commit="3"*40, build_target="x86_64-pc-windows-msvc", build_profile="release")
NOW = datetime(2026,10,15,12,tzinfo=timezone.utc)


def fixture(name):
    rows = [("head_authenticated","stat",200,0),("head_authenticated","copy",200,0),("content_authenticated","copy",200,26)] if name=="acquisition" else [("wrong_key_denied","stat",403,0)]
    if name == "download_denial":
        rows = [("head_authenticated","stat",200,0),("head_authenticated","copy",200,0),("download_denied","copy",403,0)]
    return dict(case=name, requests=len(rows), payload_bytes=26 if name=="acquisition" else 0,
        response_bytes=1000, source_preserved=True, errors=[], events=[dict(ordinal=i+1,kind=k,role=r,status=s,object_bytes=b)
        for i,(k,r,s,b) in enumerate(rows)])


def receipt(mode=E.MODE):
    cases=E.empty_cases(mode)
    for name,row in cases.items():
        n=1 if name=="denial" else 2
        row.update(status="passed",exit_code=0 if name=="acquisition" else 1,runtime_sha256=RUNTIME["sha256"],
            checks=dict.fromkeys(E.CHECKS[name],True),fixture=fixture(name),observation=dict(runtime_launch_count=n,
            peak_runtime_processes=1,system_helper_sha256=None,system_helper_launch_count=0,peak_system_helper_processes=0,debug_event_count=20))
    return dict(schema_version=1,scope=E.SCOPE,fixture_mode=mode,backend="azureblob",platform="windows",created_at="2026-10-15T12:00:00Z",
        runtime=deepcopy(RUNTIME),bindings=deepcopy(BINDINGS),cases=cases,experiment=dict(status="passed",failure_code=None,
        checks=dict.fromkeys(E.GROUP_CHECKS,True)),authentication="static_shared_key",claims=dict.fromkeys(E.FALSE_CLAIMS,False),
        cleanup_complete=True,errors=[],result="passed",capabilities=E.derive_capabilities(cases,True,mode))


class EvidenceTests(unittest.TestCase):
    def validate(self,value,mode=E.MODE): return E.validate_receipt(value,RUNTIME,BINDINGS,now=NOW,mode=mode)
    def reject(self,value,mode=E.MODE):
        with self.assertRaises((E.A.ApplicationEvidenceError,ValueError,TypeError)): self.validate(value,mode)

    def test_independent_literal_oracle_and_partial_scope(self):
        value=receipt();self.assertIs(self.validate(value),value)
        body=b"Nested synthetic payload.\n";manifest=E.fixture_manifest()
        self.assertEqual((manifest["size"],manifest["sha256"],manifest["md5"]),(len(body),hashlib.sha256(body).hexdigest(),hashlib.md5(body).hexdigest()))
        self.assertTrue(all(v is False for v in value["claims"].values()))
        self.assertEqual(set(value["capabilities"]),{"configured_acquisition","shared_key_authentication","wrong_key_rejection","cleanup"})

    def test_shapes_booleans_and_claims_fail_closed(self):
        for key in E.RECEIPT_KEYS:
            value=receipt();del value[key];self.reject(value)
        for field,bad in (("schema_version",True),("cleanup_complete",1),("authentication","oauth"),("fixture_mode","b2_native_token_replacement_cli_v1")):
            value=receipt();value[field]=bad;self.reject(value)
        for name in E.CASES:
            for key in E.CHECKS[name]:
                for bad in (False,None,1):
                    value=receipt();value["cases"][name]["checks"][key]=bad;self.reject(value)
            value=receipt();value["cases"][name]["continuity"]={};self.reject(value)
        for key in E.FALSE_CLAIMS:
            value=receipt();value["claims"][key]=True;self.reject(value)
        value=receipt();value["private"]="private canary";self.reject(value)

    def test_binding_runtime_freshness_and_launch_count(self):
        for key in BINDINGS:
            value=receipt();value["bindings"][key]="f"*64;self.reject(value)
        for key,bad in (("sha256","f"*64),("version","1.75.1"),("platform","linux")):
            value=receipt();value["runtime"][key]=bad;self.reject(value)
        for stamp in ("2020-01-01T00:00:00Z","2026-10-15T12:06:00Z","2026-99-15T12:00:00Z"):
            value=receipt();value["created_at"]=stamp;self.reject(value)
        for name in E.CASES:
            for key,bad in (("runtime_launch_count",3),("runtime_launch_count",True),("peak_runtime_processes",2),("debug_event_count",4097),("system_helper_sha256","private canary")):
                value=receipt();value["cases"][name]["observation"][key]=bad;self.reject(value)

    def test_strict_event_order_authentication_status_counts_and_no_denial_payload(self):
        for name in E.CASES:
            for key,bad in (("requests",0),("requests",True),("payload_bytes",1),("response_bytes",524289),("source_preserved",False),("errors",["worker_failed"])):
                value=receipt();value["cases"][name]["fixture"][key]=bad;self.reject(value)
            for key,bad in (("ordinal",0),("kind","head"),("role","other"),("status",401),("object_bytes",True)):
                value=receipt();value["cases"][name]["fixture"]["events"][0][key]=bad;self.reject(value)
            value=receipt();value["cases"][name]["fixture"]["events"].append(deepcopy(value["cases"][name]["fixture"]["events"][0]));self.reject(value)
        value=receipt();value["cases"]["acquisition"]["fixture"]["events"].reverse();self.reject(value)
        value=receipt();value["cases"]["acquisition"]["fixture"]["events"][-1]["status"]=206;self.validate(value)

    def test_cleanup_group_late_failure_and_not_run_are_not_credit(self):
        for key in E.GROUP_CHECKS:
            value=receipt();value["experiment"]["checks"][key]=False;self.reject(value)
        value=receipt();value["cases"]["denial"]=E.empty_cases()["denial"];self.reject(value)
        value=receipt();value["errors"]=["unexpected_failure"];self.reject(value)
        value=receipt();value["cases"]["denial"]["exit_code"]=0;self.reject(value)
        value=receipt();value["cases"]=E.empty_cases();value["experiment"]=E.empty_group()
        value.update(errors=["binding_failed"],result="failed",capabilities=E.derive_capabilities(value["cases"],True))
        self.validate(value);self.assertNotIn("passed",value["capabilities"].values())

    def test_download_denial_is_separate_closed_mode_and_manifest_binding(self):
        mode=E.DOWNLOAD_DENIAL_MODE;value=receipt(mode)
        self.assertIs(self.validate(value,mode),value)
        self.assertEqual(set(value["cases"]),{"acquisition","download_denial"})
        self.assertEqual(set(value["capabilities"]),{"configured_acquisition","shared_key_authentication","authenticated_download_rejection","cleanup"})
        self.assertTrue(all(v is False for v in value["claims"].values()))
        self.reject(value);self.reject(receipt(),mode)
        old=E.fixture_manifest();new=E.fixture_manifest(mode)
        self.assertEqual(old["denial"],"known_wrong_key_stat_403_AuthenticationFailed")
        self.assertEqual(new["denial"],"correct_key_HEAD_200_HEAD_200_GET_403_AuthorizationFailure_single_stderr_block")
        self.assertEqual({k:v for k,v in old.items() if k!="denial"},{k:v for k,v in new.items() if k!="denial"})
        with patch.object(E.A,"file_hash",return_value=E._SHA), patch.object(E.W,"compute_bindings",side_effect=lambda *a,**kw:deepcopy(BINDINGS)):
            a=E.compute_bindings("unused","unused",BINDINGS["build_commit"])
            b=E.compute_bindings("unused","unused",BINDINGS["build_commit"],mode)
        self.assertNotEqual(a["fixture_manifest_sha256"],b["fixture_manifest_sha256"])
        value["bindings"]=a
        with self.assertRaises(E.A.ApplicationEvidenceError): E.validate_receipt(value,RUNTIME,b,now=NOW,mode=mode)
        for bad in (None,True,{},"azureblob_sharedkey_download_denial_cli_v2"):
            with self.assertRaises(E.A.ApplicationEvidenceError): E.empty_cases(bad)

    def test_both_modes_bind_local_inputs_and_reject_late_harness_source_changes(self):
        files = {
            "rclone-triage/Cargo.toml": b'[package]\nname="synthetic"\nversion="0.0.0"\n[dependencies]\nfixture={path="../local/fixture"}\n',
            "rclone-triage/Cargo.lock": b"version = 4\n",
            "rclone-triage/build.rs": b"fn main() {}\n",
            "rclone-triage/.cargo/config.toml": b"",
            "rclone-triage/src/main.rs": b"fn main() {}\n",
            "local/fixture/Cargo.toml": b'[package]\nname="fixture"\nversion="0.0.0"\n',
            "local/fixture/src/lib.rs": b'const _: &str = include_str!("../NOTES");\n',
            "local/fixture/NOTES": b"synthetic included bytes\n",
        }
        expected_rows = [[name, hashlib.sha256(data).hexdigest()] for name, data in sorted(files.items())]
        expected_hash = hashlib.sha256(json.dumps(expected_rows, separators=(",", ":")).encode("ascii")).hexdigest()
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"CARGO_TARGET_DIR": "", "CARGO_BUILD_TARGET_DIR": ""}):
            root = Path(directory)
            for name, data in files.items():
                path = root / name;path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(data)
            for name in E.HARNESS_FILES:
                path = root / name;path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((PATH.parents[1] / name).read_bytes())
            application = root / "application.data";application.write_bytes(b"inert")
            (root / "rclone-version.env").write_bytes(b"synthetic runtime binding\n")
            helper = "scripts/application_source_snapshot.py"
            self.assertEqual(E.HARNESS_FILES.count(helper), 1)
            manifests = []
            dependency = root / "local/fixture/NOTES"
            for mode in E.MODES:
                current = E.compute_bindings(root, application, "d" * 40, mode)
                self.assertEqual(current["application_source_sha256"], expected_hash)
                self.assertEqual(current["harness_sha256"], E.A.tree_hash(root, E.HARNESS_FILES))
                manifests.append(current["fixture_manifest_sha256"])
                dependency.write_bytes(b"changed included input\n")
                self.assertNotEqual(E.compute_bindings(root, application, "d" * 40, mode)["application_source_sha256"], expected_hash)
                dependency.write_bytes(files["local/fixture/NOTES"])
                original_tree_hash = E.A.tree_hash;seen = []
                def late_harness(path, names):
                    value = original_tree_hash(path, names)
                    if Path(path) == root and tuple(names) == E.HARNESS_FILES:
                        seen.append(True);dependency.write_bytes(b"changed after final Azure harness read\n")
                    return value
                try:
                    with patch.object(E.A, "tree_hash", side_effect=late_harness), self.assertRaises(E.A.ApplicationEvidenceError):
                        E.compute_bindings(root, application, "d" * 40, mode)
                    self.assertEqual(seen, [True])
                finally:
                    dependency.write_bytes(files["local/fixture/NOTES"])
            self.assertNotEqual(manifests[0], manifests[1])
            path = root / helper;path.write_bytes(path.read_bytes() + b"# changed helper\n")
            for mode in E.MODES:
                with self.assertRaises(E.A.ApplicationEvidenceError): E.compute_bindings(root, application, "d" * 40, mode)

    def test_download_denial_requires_every_evidence_gate(self):
        mode=E.DOWNLOAD_DENIAL_MODE
        for name in ("acquisition","download_denial"):
            for key in E.CHECKS[name]:
                for bad in (False,None,1):
                    value=receipt(mode);value["cases"][name]["checks"][key]=bad;self.reject(value,mode)
        for key in E.GROUP_CHECKS:
            value=receipt(mode);value["experiment"]["checks"][key]=False;self.reject(value,mode)
        for key in E.FALSE_CLAIMS:
            value=receipt(mode);value["claims"][key]=True;self.reject(value,mode)
        for key,bad in (("exit_code",0),("exit_code",True),("runtime_sha256","f"*64),("status","not_run")):
            value=receipt(mode);value["cases"]["download_denial"][key]=bad;self.reject(value,mode)
        for key,bad in (("runtime_launch_count",1),("runtime_launch_count",3),("peak_runtime_processes",2)):
            value=receipt(mode);value["cases"]["download_denial"]["observation"][key]=bad;self.reject(value,mode)
        value=receipt(mode);value["cleanup_complete"]=False;self.reject(value,mode)
        value=receipt(mode);value["errors"]=["preservation_failed"];self.reject(value,mode)
        value=receipt(mode);value["bindings"]["fixture_manifest_sha256"]="f"*64;self.reject(value,mode)

    def test_download_denial_requires_committed_authenticated_head_head_get403(self):
        mode=E.DOWNLOAD_DENIAL_MODE
        for replacement in ([],fixture("denial")["events"],fixture("acquisition")["events"],
                fixture("download_denial")["events"][:1],fixture("download_denial")["events"][:2],
                list(reversed(fixture("download_denial")["events"]))):
            value=receipt(mode);value["cases"]["download_denial"]["fixture"]["events"]=replacement;self.reject(value,mode)
        for key,bad in (("requests",2),("requests",4),("payload_bytes",1),("response_bytes",0),
                        ("source_preserved",False),("errors",["connection_failed"])):
            value=receipt(mode);value["cases"]["download_denial"]["fixture"][key]=bad;self.reject(value,mode)
        for index,key,bad in ((0,"kind","wrong_key_denied"),(0,"status",403),(1,"role","stat"),
                (2,"kind","content_authenticated"),(2,"status",200),(2,"status",206),(2,"status",401),
                (2,"role","stat"),(2,"object_bytes",26),(2,"object_bytes",True),(2,"ordinal",2)):
            value=receipt(mode);value["cases"]["download_denial"]["fixture"]["events"][index][key]=bad;self.reject(value,mode)

    def test_normalizer_rejects_private_unknown_receipt_and_writes_only_closed_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"receipt.json";out=root/"out.json"
            source.write_text('{"private":"PRIVATE-CANARY"}')
            with patch.object(E,"runtime_binding",return_value=RUNTIME),patch.object(E,"compute_bindings",return_value=BINDINGS):
                self.assertEqual(E.main(["--receipt",str(source),"--application","unused","--build-commit",BINDINGS["build_commit"],"--report",str(out)]),2)
            normalized=out.read_text();self.assertNotIn("PRIVATE-CANARY",normalized)
            result=json.loads(normalized);self.assertEqual(result["errors"],["validation_failed"]);self.assertIsNone(result["receipt"])


if __name__=="__main__": unittest.main()
