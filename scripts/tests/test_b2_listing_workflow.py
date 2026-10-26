"""Pure B2 workflow contract; never executes workflow scripts."""
from pathlib import Path
import re
import shlex
import unittest
from test_gcs_oauth_workflow_contract import jobs, require, scalar
from test_azureblob_application_workflow import steps, action_refs, after_either_outcome

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"

def bound_command(step):
    require(scalar(step, "shell", 8) == "pwsh", "powershell_required")
    script = step.split("        run: |\n", 1)[1]
    guards = re.findall(r"if \((.*)\) \{ throw '[^']+' \}", script)
    # Inspect the trust boundaries, not the complete PowerShell implementation.
    for terms in (("$env:GITHUB_ACTIONS -cne 'true'", "$env:RUNNER_ENVIRONMENT -cne 'github-hosted'", " -or "),
                  ("$LASTEXITCODE -ne 0", "$buildCommit -cnotmatch '^[0-9a-f]{40}$'", "$env:GITHUB_SHA -cne $buildCommit", " -or "),
                  ('Get-FileHash -LiteralPath "$env:RUNNER_TEMP/b2-build/rclone-version.env"', "-Algorithm SHA256", ".Hash -cne $expectedPins")):
        require(any(all(term in guard for term in terms) for guard in guards), "independent_binding_guard")
    for binding in ("$ErrorActionPreference = 'Stop'", "$buildCommit = (& git rev-parse --verify HEAD)",
                    '$application = (Resolve-Path "$env:RUNNER_TEMP/b2-build/rclone-triage/target/release/rclone-triage.exe")',
                    "$expectedPins = (Get-FileHash -LiteralPath rclone-version.env -Algorithm SHA256)"):
        require(binding in script, "bound_inputs")
    joined = script.replace("`\n", "")
    commands = list(re.finditer(r"(?m)^\s*python -B ([^\n]+)", joined))
    require(len(commands) == 1, "one_python_invocation")
    require(re.search(r"if \(\$LASTEXITCODE -ne 0\) \{ throw '[^']+' \}", joined[commands[0].end():]), "native_exit_required")
    args = shlex.split(commands[0][1])
    require(args.count("--application") == args.count("--build-commit") == 1 and
        args[args.index("--application") + 1] == "$application" and
        args[args.index("--build-commit") + 1] == "$buildCommit", "same_build_arguments")
    return script, args

def validate(text):
    definitions=jobs(text);job=definitions["windows-b2"];chain=steps(job)
    require(scalar(job,"needs",4)=="test" and scalar(job,"runs-on",4)=="windows-latest","checked_hosted_build")
    require(scalar(job,"timeout-minutes",4)=="20" and "continue-on-error" not in job and "secrets." not in job and
            not re.search(r"^    (?:if|services|permissions):",job,re.MULTILINE),"mandatory_bounded_unprivileged")
    require("persist-credentials: false" in chain[0],"no_persisted_credentials")
    refs=action_refs(job);swift=action_refs(definitions["windows-swift"])
    require(len(refs)==5 and refs==swift+[swift[-1]],"shared_exact_actions")
    downloads=[p for p in chain if "uses: actions/download-artifact@" in p]
    require(len(downloads)==1 and re.findall(r"^          ([a-z-]+):",downloads[0],re.MULTILINE)==["name","path"] and
            scalar(downloads[0],"name",10)=="rclone-triage-windows" and
            scalar(downloads[0],"path",10)=="${{ runner.temp }}/b2-build","single_same_run_build")
    runs=[p for p in chain if "        run:" in p];uploads=[p for p in chain if "uses: actions/upload-artifact@" in p]
    ids=["b2_cases","b2_validation","b2_listing_cases","b2_listing_validation"]
    require(len(runs)==4 and [scalar(p,"id",8) for p in runs]==ids and len(uploads)==2,"distinct_ordered_modes")
    for index,stem in enumerate(("b2","b2-listing")):
        first,second=runs[2*index:2*index+2];upload=uploads[index]
        require(not re.search(r"^        if:",first,re.MULTILINE),"producer_not_optional")
        script,p=bound_command(first);_,v=bound_command(second)
        require(p[0]==("scripts/application-lab/run_windows_b2_listing.py" if index else "scripts/application-lab/run_windows_b2.py") and
                v[0]==("scripts/b2_listing_application_evidence.py" if index else "scripts/b2_application_evidence.py"),"separate_producer_validator")
        require("Get-FileHash -LiteralPath $application -Algorithm SHA256" in script and
                p.count("--application-sha256")==1 and p[p.index("--application-sha256")+1]=="$applicationHash","application_hash")
        require("--fixture-mode" not in p and "--fixture-mode" not in v,"single_closed_modes")
        require(p[p.index("--report")+1]==v[v.index("--receipt")+1]=="$env:RUNNER_TEMP/"+stem+".private.json" and
                v[v.index("--report")+1]=="$env:RUNNER_TEMP/"+stem+"-validation.json","private_input_normalized_output")
        after_either_outcome(second,ids[2*index]);after_either_outcome(upload,ids[2*index+1])
        require(chain.index(first)<chain.index(second)<chain.index(upload) and
                (index==0 or chain.index(uploads[index-1])<chain.index(first)),"retain_before_next_mode")
        require(scalar(upload,"name",10)==stem+"-experiment-Windows" and
                scalar(upload,"path",10)=="${{ runner.temp }}/"+stem+"-validation.json" and
                scalar(upload,"if-no-files-found",10)=="error","normalized_only")
        require(scalar(first,"timeout-minutes",8)=="8" and scalar(second,"timeout-minutes",8)=="3","bounded_steps")
    require(scalar(definitions["release"],"needs",4).strip("[]").split(", ").count("windows-b2")==1,"required_release_gate")


class WorkflowTests(unittest.TestCase):
    def test_contract(self):validate(WORKFLOW.read_text())

    def test_changed_common_action_pins_still_match(self):
        text=WORKFLOW.read_text()
        for ref in action_refs(jobs(text)["windows-b2"]):text=text.replace(ref,ref.split("@")[0]+"@"+"1"*40)
        validate(text)

    def test_admission_and_artifact_mutations_rejected(self):
        text=WORKFLOW.read_text();job=jobs(text)["windows-b2"]
        mutations=[("needs: test","needs: other"),("windows-latest","self-hosted"),("persist-credentials: false","persist-credentials: true"),
            ("timeout-minutes: 20","timeout-minutes: 60"),("path: ${{ runner.temp }}/b2-build","path: ${{ runner.temp }}/b2-build\n          run-id: 123"),
            ("name: rclone-triage-windows","pattern: rclone-triage-*"),("name: b2-listing-experiment-Windows","name: b2-experiment-Windows"),
            ("path: ${{ runner.temp }}/b2-listing-validation.json","path: ${{ runner.temp }}/b2-listing.private.json"),
            ("steps.b2_listing_cases.outcome == 'failure'","steps.b2_listing_cases.outcome == 'skipped'"),
            ("steps.b2_listing_validation.outcome == 'failure'","steps.b2_listing_validation.outcome == 'skipped'"),
            ("scripts/b2_listing_application_evidence.py","scripts/application-lab/run_windows_b2_listing.py")]
        for old,new in mutations:
            with self.subTest(old=old),self.assertRaises((ValueError,KeyError,IndexError)):validate(text.replace(job,job.replace(old,new,1),1))

    def test_each_execution_step_independently_binds_build_runtime_exit(self):
        text=WORKFLOW.read_text()
        for step in [p for p in steps(jobs(text)["windows-b2"]) if "        run:" in p]:
            for old,new in (("$env:RUNNER_ENVIRONMENT -cne 'github-hosted'","$false"),("$env:GITHUB_SHA -cne $buildCommit","$false"),
                            (".Hash -cne $expectedPins",".Hash -eq $expectedPins"),("git rev-parse --verify HEAD","git rev-parse --verify other")):
                with self.subTest(old=old),self.assertRaises((ValueError,KeyError,IndexError)):validate(text.replace(step,step.replace(old,new,1),1))
            guard=re.findall(r"if \(\$LASTEXITCODE -ne 0\) \{ throw '[^']+' \}",step)[-1]
            with self.assertRaises((ValueError,KeyError,IndexError)):validate(text.replace(step,step.replace(guard,"Write-Output 'ignored'"),1))
