#!/usr/bin/env python3
"""Hosted-only download-script tests with synthetic ZIPs and no network transport.

The downloaded text payload is never executed. Real bootstrap scripts run only
in hosted CI, with curl / Invoke-WebRequest replaced by an owned finite fake.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.0.0"
GOOD = b"synthetic runtime bytes; never executable\n"
OLD = b"existing asset must survive a failed download\n"
SCENARIOS = ("primary", "fallback", "primary_bad_archive", "fallback_bad_archive",
             "primary_bad_binary", "fallback_bad_binary", "both_fail")
PLATFORMS = {
    "linux-amd64": ("RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256", "rclone"),
    "windows-amd64": ("RCLONE_WINDOWS_ZIP_SHA256", "RCLONE_EXE_SHA256", "rclone.exe"),
    "windows-386": ("RCLONE_WINDOWS_X86_ZIP_SHA256", "RCLONE_WINDOWS_X86_EXE_SHA256", "rclone.exe"),
    "windows-arm64": ("RCLONE_WINDOWS_ARM64_ZIP_SHA256", "RCLONE_WINDOWS_ARM64_EXE_SHA256", "rclone.exe"),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fake_transport():
    """Invoked by the owned command shim. This function has no network API."""
    case = json.loads(Path(os.environ["DOWNLOAD_TEST_CASE"]).read_text())
    args = sys.argv[2:]
    if sys.argv[1] == "--fake-curl":
        assert len(args) == 13 and args[:10] == [
            "--proto", "=https", "--tlsv1.2", "-fSL", "--retry", "3",
            "--connect-timeout", "15", "--max-time", "120"] and args[11] == "-o"
        url, output = args[10], Path(args[12])
    else:
        assert sys.argv[1] == "--fake-powershell" and len(args) == 3 and args[2] == "120"
        url, output = args[0], Path(args[1])
    log = Path(case["log"])
    calls = log.read_text().splitlines() if log.exists() else []
    assert len(calls) < 2
    assert url == case["urls"][len(calls)]
    # The bootstrap must discard a partial first download before failover.
    assert not output.exists()
    assert output.name == "runtime.zip"
    assert Path(case["scratch"]).resolve() in output.resolve().parents
    with log.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"url": url}) + "\n")
    first = len(calls) == 0
    scenario = case["scenario"]
    if (first and scenario.startswith("fallback")) or scenario == "both_fail":
        output.write_bytes(b"partial failed acquisition")
        return 22
    raw = Path(case["archive"]).read_bytes()
    output.write_bytes(b"corrupt acquired archive" if scenario.endswith("bad_archive") else raw)
    return 0


POWERSHELL_WRAPPER = r'''$ErrorActionPreference = 'Stop'
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [int]$TimeoutSec)
    & $env:DOWNLOAD_TEST_PYTHON -I -S -B $env:DOWNLOAD_TEST_PROBE --fake-powershell $Uri $OutFile $TimeoutSec
    if ($LASTEXITCODE -ne 0) { throw 'synthetic_download_failure' }
}
if ($env:DOWNLOAD_TEST_ARCH -ceq 'default') { & $env:DOWNLOAD_TEST_SCRIPT }
else { & $env:DOWNLOAD_TEST_SCRIPT -Architecture $env:DOWNLOAD_TEST_ARCH }
'''


def exercise(parent, mode, platform, architecture, scenario, shell):
    case_root = parent / (mode + "-" + architecture + "-" + scenario)
    case_root.mkdir()
    repo = case_root / "repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    scratch = case_root / "scratch"
    scratch.mkdir()
    extension = "sh" if mode == "bash" else "ps1"
    original = ROOT / "scripts" / ("download-rclone." + extension)
    script = scripts / original.name
    shutil.copyfile(original, script)
    assert script.read_bytes() == original.read_bytes()
    archive = case_root / "payload.zip"
    name = f"rclone-v{VERSION}-{platform}"
    archive_key, binary_key, binary_name = PLATFORMS[platform]
    payload = b"wrong inner bytes\n" if scenario.endswith("bad_binary") else GOOD
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr(name + "/" + binary_name, payload)
    pins = {"RCLONE_VERSION": VERSION}
    for zip_key, exe_key, _ in PLATFORMS.values():
        pins[zip_key] = "0" * 64
        pins[exe_key] = "0" * 64
    pins[archive_key] = sha(archive.read_bytes())
    pins[binary_key] = sha(GOOD)
    (repo / "rclone-version.env").write_text("".join(k + "=" + v + "\n" for k, v in pins.items()))
    target = repo / "rclone-triage/assets/rclone.exe"
    if platform == "linux-amd64":
        target = repo / "linux-output"
    target.parent.mkdir(parents=True, exist_ok=True)
    previous = GOOD if scenario == "existing_valid" else OLD
    target.write_bytes(previous)
    log = case_root / "calls.jsonl"
    urls = [f"https://github.com/rclone/rclone/releases/download/v{VERSION}/{name}.zip",
            f"https://downloads.rclone.org/v{VERSION}/{name}.zip"]
    config = case_root / "case.json"
    config.write_text(json.dumps(dict(log=str(log), scratch=str(scratch), archive=str(archive),
                                     scenario=scenario, urls=urls)))
    env = os.environ.copy()
    env.update(DOWNLOAD_TEST_CASE=str(config), DOWNLOAD_TEST_PROBE=str(Path(__file__).resolve()),
               DOWNLOAD_TEST_PYTHON=sys.executable, DOWNLOAD_TEST_SCRIPT=str(script),
               DOWNLOAD_TEST_ARCH=architecture, TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch))
    if mode == "bash":
        shim = case_root / "bin"
        shim.mkdir()
        curl = shim / "curl"
        # POSIX argv forwarding preserves spaces in the controlled paths.
        curl.write_text('#!/bin/sh\nexec "$DOWNLOAD_TEST_PYTHON" -I -S -B "$DOWNLOAD_TEST_PROBE" --fake-curl "$@"\n')
        curl.chmod(0o700)
        env["PATH"] = str(shim) + os.pathsep + env["PATH"]
        command = [shell, str(script)]
        if platform == "linux-amd64":
            command += ["--linux", str(target)]
        elif architecture != "default":
            command += ["--architecture", architecture]
    else:
        wrapper = case_root / "invoke.ps1"
        wrapper.write_text(POWERSHELL_WRAPPER)
        command = [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(wrapper)]
    # Only our synthetic bootstrap runs; neither payload nor a provider runs.
    result = subprocess.run(command, cwd=repo, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30)
    assert len(result.stdout) + len(result.stderr) < 65536
    success = scenario in {"primary", "fallback", "existing_valid"}
    if (result.returncode == 0) != success:
        raise AssertionError(f"{mode}/{architecture}/{scenario}: unexpected exit {result.returncode}; "
                             + (result.stdout + result.stderr).decode(errors="replace")[-2000:])
    assert target.read_bytes() == (GOOD if success else previous)
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    expected_calls = 0 if scenario == "existing_valid" else 2 if scenario.startswith("fallback") or scenario == "both_fail" else 1
    assert calls == [{"url": url} for url in urls[:expected_calls]]
    assert not any(scratch.iterdir()), "bootstrap scratch must be removed"
    return dict(architecture=architecture, scenario=scenario, calls=len(calls), passed=True)


def main():
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert len(sys.argv) == 2 and sys.argv[1] in {"bash", "powershell"}
    mode = sys.argv[1]
    assert os.environ.get("RUNNER_OS") == ("Linux" if mode == "bash" else "Windows")
    shell = shutil.which("bash" if mode == "bash" else "pwsh")
    assert shell
    choices = [("windows-amd64", "default"), ("windows-amd64", "x64"),
               ("windows-386", "x86"), ("windows-arm64", "arm64")]
    if mode == "bash":
        choices.append(("linux-amd64", "linux"))
    results = []
    with tempfile.TemporaryDirectory(prefix="runtime-bootstrap-contract-") as folder:
        parent = Path(folder).resolve()
        for platform, architecture in choices:
            scenarios = SCENARIOS + (("existing_valid",) if platform.startswith("windows") else ())
            for scenario in scenarios:
                results.append(exercise(parent, mode, platform, architecture, scenario, shell))
    print(json.dumps(dict(schema=1, mode=mode, passed=len(results), failed=0,
                          network_calls=0, payload_executed=False, results=results), separators=(",", ":")))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in {"--fake-curl", "--fake-powershell"}:
        raise SystemExit(fake_transport())
    main()
