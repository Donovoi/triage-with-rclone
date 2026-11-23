import copy
import importlib.util
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("native_readfix_controller",HERE/"run.py")
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
RUNTIME={"runtime_version":"v1.76.0-triage-readfix.2","sha256":"a"*64,"source_commit":"b"*40}


def report(provider):
    cleanup={k:True for k in ("children_stopped","listeners_closed","temporary_removed")}
    value={"success":True,"scope":"experimental_patched_runtime_native_"+provider+"_reads","ledger_eligible":False,
           "backend":provider,"errors":[],"native_commands":C.PROVIDERS[provider],"runtime":dict(RUNTIME),
           "capabilities":dict.fromkeys(C.CAPABILITIES,"passed"),"cleanup":cleanup,
           "observations":{"requests":100,"unexpected":0,"denied":1,"read_denied":2,"rejected_mutations":1,"missing":1}}
    if C.AUTHORITIES[provider]:
        cleanup["certificates_removed"]=True
        snapshot=dict.fromkeys(("admission_denied","handshake_failures","request_timeouts","handler_failures",
                                "aborted_connections","active_connections","active_workers","active_timers"),0)
        snapshot.update(failure_codes=[],cleanup_complete=True,stopping=True,handshake_successes=10,
                        accepted_connections=10,closed_connections=10)
        value["tls"]=[copy.deepcopy(snapshot),copy.deepcopy(snapshot)]
    if provider=="filen":value["tampered_ciphertext_rejected"]=True
    if provider=="protondrive":value["tampered_reads_rejected"]={"tampered_ciphertext":2,"wrong_block_hash":2,"wrong_block_signature":2}
    return value


class ReportGateTests(unittest.TestCase):
    def rejected(self,value,provider):
        with self.assertRaises(C.ExperimentError):C.validate_report(value,provider,RUNTIME)
    def test_all_four_complete_scoped_reports_pass(self):
        for provider in C.PROVIDERS:
            C.validate_report(report(provider),provider,RUNTIME)
    def test_other_runtime_or_acceptance_claim_is_rejected(self):
        for provider in C.PROVIDERS:
            for key,value in (("scope","provider_acceptance"),("ledger_eligible",True),("backend","other")):
                sample=report(provider);sample[key]=value;self.rejected(sample,provider)
            sample=report(provider);sample["runtime"]["sha256"]="c"*64;self.rejected(sample,provider)
    def test_missing_native_command_or_skipped_capability_fails(self):
        for provider in C.PROVIDERS:
            sample=report(provider);sample["native_commands"]-=1;self.rejected(sample,provider)
            for capability in C.CAPABILITIES:
                sample=report(provider);sample["capabilities"][capability]="skipped";self.rejected(sample,provider)
    def test_cleanup_failure_cannot_pass(self):
        for provider in C.PROVIDERS:
            for key in report(provider)["cleanup"]:
                sample=report(provider);sample["cleanup"][key]=False;self.rejected(sample,provider)
                sample=report(provider);sample["cleanup"][key]=1;self.rejected(sample,provider)
    def test_denial_without_server_witness_fails(self):
        for provider in C.PROVIDERS:
            for key,value in (("denied",0),("read_denied",0),("unexpected",1),("rejected_mutations",0),("requests",513)):
                sample=report(provider);sample["observations"][key]=value;self.rejected(sample,provider)
    def test_tls_errors_or_live_workers_fail(self):
        for provider in ("imagekit","filen","protondrive"):
            for key,value in (("failure_codes",["tls_error"]),("handshake_successes",0),("active_workers",1),
                              ("active_connections",1),("active_timers",1),("cleanup_complete",False),("handshake_successes",11)):
                sample=report(provider);sample["tls"][0][key]=value;self.rejected(sample,provider)
    def test_tamper_checks_must_reach_both_native_read_paths(self):
        sample=report("filen");sample["tampered_ciphertext_rejected"]=False;self.rejected(sample,"filen")
        for key in report("protondrive")["tampered_reads_rejected"]:
            sample=report("protondrive");sample["tampered_reads_rejected"][key]=1;self.rejected(sample,"protondrive")
    def test_failed_report_or_error_is_rejected(self):
        for provider in C.PROVIDERS:
            sample=report(provider);sample["errors"]=["diagnostic"];self.rejected(sample,provider)
            sample=report(provider);sample["success"]=False;self.rejected(sample,provider)


if __name__=="__main__":unittest.main()
