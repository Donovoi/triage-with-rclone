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
    return dict(case=name, requests=len(rows), payload_bytes=26 if name=="acquisition" else 0,
        response_bytes=1000, source_preserved=True, errors=[], events=[dict(ordinal=i+1,kind=k,role=r,status=s,object_bytes=b)
        for i,(k,r,s,b) in enumerate(rows)])


def receipt():
    cases=E.empty_cases()
    for name,row in cases.items():
        n=2 if name=="acquisition" else 1
        row.update(status="passed",exit_code=0 if name=="acquisition" else 1,runtime_sha256=RUNTIME["sha256"],
            checks=dict.fromkeys(E.CHECKS[name],True),fixture=fixture(name),observation=dict(runtime_launch_count=n,
            peak_runtime_processes=1,system_helper_sha256=None,system_helper_launch_count=0,peak_system_helper_processes=0,debug_event_count=20))
    return dict(schema_version=1,scope=E.SCOPE,fixture_mode=E.MODE,backend="azureblob",platform="windows",created_at="2026-10-15T12:00:00Z",
        runtime=deepcopy(RUNTIME),bindings=deepcopy(BINDINGS),cases=cases,experiment=dict(status="passed",failure_code=None,
        checks=dict.fromkeys(E.GROUP_CHECKS,True)),authentication="static_shared_key",claims=dict.fromkeys(E.FALSE_CLAIMS,False),
        cleanup_complete=True,errors=[],result="passed",capabilities=E.derive_capabilities(cases,True))


class EvidenceTests(unittest.TestCase):
    def validate(self,value): return E.validate_receipt(value,RUNTIME,BINDINGS,now=NOW)
    def reject(self,value):
        with self.assertRaises((E.A.ApplicationEvidenceError,ValueError,TypeError)): self.validate(value)

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

    def test_normalizer_rejects_private_unknown_receipt_and_writes_only_closed_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"receipt.json";out=root/"out.json"
            source.write_text('{"private":"PRIVATE-CANARY"}')
            with patch.object(E,"runtime_binding",return_value=RUNTIME),patch.object(E,"compute_bindings",return_value=BINDINGS):
                self.assertEqual(E.main(["--receipt",str(source),"--application","unused","--build-commit",BINDINGS["build_commit"],"--report",str(out)]),2)
            normalized=out.read_text();self.assertNotIn("PRIVATE-CANARY",normalized)
            result=json.loads(normalized);self.assertEqual(result["errors"],["validation_failed"]);self.assertIsNone(result["receipt"])


if __name__=="__main__": unittest.main()
