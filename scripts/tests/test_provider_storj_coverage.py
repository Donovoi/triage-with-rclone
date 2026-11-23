"""Native Storj evidence admission tests; no services, compiler or credentials."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT/"scripts/provider-lab/storj-native"

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

E=load("storj_contract",FIXTURE/"protocol_evidence.py")
C=load("storj_coverage",ROOT/"scripts/provider_coverage.py")
# The runner imports only these local definition modules.
with patch.dict(sys.modules,{"protocol_evidence":E,
                            "build_fixture":load("build_fixture",FIXTURE/"build_fixture.py")}):
    R=load("storj_runner",FIXTURE/"run_container.py")

def receipt():
    return json.loads((FIXTURE/"test-data/passed.json").read_text())

def assign(value,path,replacement):
    for key in path[:-1]:
        value=value[key]
    value[path[-1]]=replacement

class StorjContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bindings=E.compute_bindings(FIXTURE)
        cls.runtime={**receipt()["runtime"],"platform":"linux"}
        cls.now=E.utc(receipt()["finished_utc"])+timedelta(minutes=1)

    def check(self,value):
        E.validate_evidence(value,self.runtime,self.bindings,self.now)

    def test_observed_native_receipt_passes_current_source_bindings(self):
        self.check(receipt())
        self.assertEqual(len(receipt()["native_evidence"]["probe"]["native_checks"]),44)

    def test_every_command_is_required_for_each_backend(self):
        for index in range(44):
            value=receipt();del value["native_evidence"]["probe"]["native_checks"][index]
            with self.subTest(index=index),self.assertRaisesRegex(ValueError,"native_command_count"):
                self.check(value)

    def test_every_command_exit_is_checked_without_bool_integer_coercion(self):
        for index in range(44):
            for substitute in (True,False,255):
                value=receipt();value["native_evidence"]["probe"]["native_checks"][index]["exit"]=substitute
                with self.subTest(index=index,substitute=substitute),self.assertRaises(ValueError):
                    self.check(value)

    def test_denied_read_output_cannot_be_promoted(self):
        source=receipt()["native_evidence"]["probe"]["native_checks"]
        for index,row in enumerate(source):
            if row["case"] in ("cat-denied","copy-denied","missing-copy"):
                value=receipt();value["native_evidence"]["probe"]["native_checks"][index]["bytes"]=1
                with self.subTest(index=index),self.assertRaises(ValueError):self.check(value)

    def test_omissions_alias_substitution_and_extra_fields_fail(self):
        for path,replacement in [
            (("backends",0,"backend"),"tardigrade"),
            (("backends",1,"backend"),"s3"),
            (("native_evidence","probe","backends"),["storj"]),
            (("native_evidence","probe","remote_segments"),0),
            (("native_evidence","probe","remote_pieces"),0),
            (("native_evidence","probe","inline_segments"),True),
            (("native_evidence","probe","source_preserved"),False),
            (("native_evidence","probe","configuration_preserved"),False),
            (("native_evidence","isolation_verified"),False),
            (("native_evidence","exit_code"),True),
            (("native_evidence","oom_killed"),True),
            (("native_evidence","stdout_bytes"),0),
            (("native_evidence","stderr_bytes"),5*1024*1024),
            (("cleanup_passed",),False),
            (("success",),False),
            (("schema_version",),35),
            (("architecture",),"arm64"),
            (("runtime","sha256"),"0"*64),
            (("runtime","version"),"1.75.2"),
            (("harness_sha256",),"0"*64),
            (("fixture_manifest_sha256",),"0"*64),
            (("native_evidence","source_sha256","planet_test.go"),"0"*64),
            (("native_evidence","build","source_archive_sha256"),"0"*64),
            (("native_evidence","build","helper_sha256"),"0"*64),
            (("native_evidence","build","compiler_image"),"golang:latest"),
            (("native_evidence","build","seconds"),True),
            (("native_evidence","build","seconds"),float("nan")),
            (("native_evidence","build","resources_sha256"),{}),
            (("errors",),["fixture_failed"]),
            (("backends",0,"capabilities","download_hash"),"skipped"),
        ]:
            value=receipt();assign(value,path,replacement)
            with self.subTest(path=path),self.assertRaises(ValueError):self.check(value)
        value=receipt();value["native_evidence"]["probe"]["account"]="untrusted"
        with self.assertRaises(ValueError):self.check(value)

    def test_each_resource_and_cleanup_result_is_bound(self):
        for key in ("builder_removed","scratch_removed"):
            value=receipt();value["native_evidence"]["build"][key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):self.check(value)
        for key in ("container_removed","image_removed","temporary_removed"):
            value=receipt();value["native_evidence"]["cleanup"][key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):self.check(value)
        for key in receipt()["native_evidence"]["build"]["resources_sha256"]:
            value=receipt();value["native_evidence"]["build"]["resources_sha256"][key]="0"*64
            with self.subTest(resource=key),self.assertRaises(ValueError):self.check(value)

    def test_freshness_and_native_duration_are_required(self):
        value=receipt();value["finished_utc"]=(self.now+timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaises(ValueError):self.check(value)
        value=receipt();value["started_utc"]=(self.now-timedelta(minutes=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaises(ValueError):self.check(value)
        with self.assertRaises(ValueError):
            E.validate_evidence(receipt(),self.runtime,self.bindings,self.now+timedelta(days=2))

    def test_probe_parser_rejects_skipped_failed_missing_or_duplicate_results(self):
        marker="TRIAGE_STORJ_NATIVE_RESULT "+json.dumps(receipt()["native_evidence"]["probe"])
        output=marker+"\n--- PASS: TestSyntheticNetwork (4.0s)\n    --- PASS: TestSyntheticNetwork/Postgres (4.0s)\nPASS\n"
        self.assertEqual(R.parse_probe(output),receipt()["native_evidence"]["probe"])
        for changed in (output.replace("--- PASS","--- SKIP"),output+marker,
                        output.replace("TRIAGE_STORJ_NATIVE_RESULT","MISSING"),output+"--- FAIL: anything\n"):
            with self.subTest(output=changed[-40:]),self.assertRaises(ValueError):R.parse_probe(changed)

    def test_source_links_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/"source";target.write_text("synthetic")
            link=Path(directory)/"link"
            try:link.symlink_to(target)
            except OSError:self.skipTest("symlink privilege unavailable")
            with self.assertRaises(ValueError):E.file_bytes(link.absolute())

class StorjCoverageTests(unittest.TestCase):
    setUpClass = classmethod(StorjContractTests.setUpClass.__func__)
    def evaluate(self,values,**kwargs):
        original=json.loads((ROOT/"provider-coverage-policy.json").read_text())
        catalog=C.catalog_from_schemas([{"Name":name,"Prefix":name,"Options":[]} for name in ("storj","tardigrade")])
        entries={}
        profiles={}
        for row in catalog:
            entry=copy.deepcopy(original["providers"][row["backend"]])
            entry.pop("schema_sha256_by_platform",None);entry["schema_sha256"]=row["schema_sha256"]
            entries[row["backend"]]=entry
            profiles[entry["profile"]]=original["profiles"][entry["profile"]]
        policy={"schema_version":2,"reviewed_runtime_version":"1.76.0","providers":entries,"profiles":profiles}
        args={"now":self.now,"storj_bindings":self.bindings,"fixture_manifest_sha256":"f"*64}
        args.update(kwargs)
        return C.evaluate(catalog,policy,self.runtime,values,"e"*64,**args)

    def test_both_profiles_pass_without_promoting_application_vendor_or_lifecycle(self):
        report=self.evaluate([receipt()])
        self.assertEqual(report["errors"],[])
        self.assertFalse(report["all_complete"])
        for row in report["providers"]:
            self.assertEqual(row["evidence"]["local_protocol"]["status"],"passed")
            self.assertNotEqual(row["evidence"]["application"]["status"],"passed")
            self.assertNotEqual(row["evidence"]["vendor"]["status"],"passed")
            self.assertEqual(row["evidence"]["local_protocol"]["modes"][E.MODE]["status"],"passed")
            self.assertEqual(row["lifecycle_applicability"]["connection_session_reauthentication"],"review_required")
        self.assertEqual(C.gate_errors(report,require_fixtures=["storj","tardigrade"]),[])

    def test_absent_or_invalid_evidence_cannot_satisfy_either_gate(self):
        invalid=receipt();invalid["native_evidence"]["probe"]["native_checks"][30]["exit"]=1
        for values,kwargs in (([],{}),([invalid],{}),([receipt()],{"storj_bindings":None})):
            report=self.evaluate(values,**kwargs)
            self.assertIn("required_fixture_not_verified",C.gate_errors(report,require_fixtures=["storj","tardigrade"]))
            for row in report["providers"]:
                self.assertEqual(row["evidence"]["local_protocol"]["status"],"not_verified")

    def test_runtime_platform_mismatch_rejected(self):
        with self.assertRaisesRegex(C.CoverageError,"runtime_mismatch"):
            C.validate_receipt(receipt(),{**self.runtime,"platform":"windows"},"e"*64,self.now,
                               storj_bindings=self.bindings)



class StorjIsolationTests(unittest.TestCase):
    def fixture(self):
        return {"Image":"sha256:owned","Config":{"Labels":{"org.triage.storj-native":"owned"},"User":"999:999"},
                "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":True,"CapDrop":["ALL"],
                              "SecurityOpt":["no-new-privileges"],"NanoCpus":1500000000,
                              "Memory":1610612736,"MemorySwap":1610612736,"PidsLimit":384,
                              "CgroupnsMode":"private","IpcMode":"private","Init":True,
                              "Binds":None,"PortBindings":{},
                              "Tmpfs":{"/work":"rw,nosuid,nodev,noexec,size=512m,mode=0700,uid=999,gid=999",
                                       "/var/lib/postgresql":"rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=999,gid=999"}},
                "Mounts":[]}

    def test_every_isolation_boundary_is_enforced(self):
        R.verify_isolation(self.fixture(),"sha256:owned","owned")
        for path,replacement in [
            (("Image",),"sha256:other"),
            (("Config","Labels","org.triage.storj-native"),"other"),
            (("Config","User"),"0"),
            (("HostConfig","NetworkMode"),"host"),
            (("HostConfig","ReadonlyRootfs"),False),
            (("HostConfig","CapDrop"),[]),
            (("HostConfig","SecurityOpt"),[]),
            (("HostConfig","NanoCpus"),0),
            (("HostConfig","Memory"),0),
            (("HostConfig","MemorySwap"),-1),
            (("HostConfig","PidsLimit"),-1),
            (("HostConfig","CgroupnsMode"),"host"),
            (("HostConfig","IpcMode"),"host"),
            (("HostConfig","Init"),False),
            (("HostConfig","Binds"),["/:/host"]),
            (("HostConfig","PortBindings"),{"5432/tcp":[{"HostPort":"5432"}]}),
            (("HostConfig","Tmpfs","/work"),"rw,size=512m"),
            (("Mounts",),[{"Type":"volume","Destination":"/var/lib/postgresql"}]),
        ]:
            value=self.fixture();assign(value,path,replacement)
            with self.subTest(path=path),self.assertRaises(ValueError):
                R.verify_isolation(value,"sha256:owned","owned")

    def test_reusable_workflow_uses_exact_source_and_sanitized_artifact(self):
        self.assertIn("/scripts/provider-lab/storj-native/planet_test.go text eol=lf",(ROOT/".gitattributes").read_text())
        text=(ROOT/".github/workflows/storj-native.yml").read_text()
        self.assertIn("ref: b2fe6e00c07c42711217c1c60c283d5e000b18ba",text)
        self.assertIn("build_fixture.py",text)
        self.assertIn("run_container.py",text)
        self.assertNotIn("continue-on-error",text)
        upload=text.split("      - name: Retain sanitized native protocol evidence",1)[1]
        self.assertIn("path: $"+'{{ runner.temp }}/storj-native-protocol.json',upload)
        for forbidden in ("*.json","build.log","storj-native-build/","native.log"):
            self.assertNotIn(forbidden,upload)
        for name in ("ci.yml","provider-smoke.yml"):
            workflow=(ROOT/".github/workflows"/name).read_text()
            self.assertIn("uses: ./.github/workflows/storj-native.yml",workflow)
            self.assertIn("storj,tardigrade",workflow)
            self.assertIn('provider-storj/storj-native-protocol.json',workflow)

if __name__=="__main__":
    unittest.main()
