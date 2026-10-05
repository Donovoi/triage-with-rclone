"""Package same-run checked Windows artifacts; never execute their contents."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile


TARGETS = {
    "x64": ("", 0x8664),
    "x86": ("i686-pc-windows-msvc/", 0x014C),
    "arm64": ("aarch64-pc-windows-msvc/", 0xAA64),
}


def read_file(path, limit):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("Missing or invalid release input")
    return path.read_bytes()


def machine(binary):
    if len(binary) < 64 or binary[:2] != b"MZ":
        raise ValueError("Invalid Windows executable")
    offset = struct.unpack_from("<I", binary, 60)[0]
    if offset < 64 or offset + 6 > len(binary) or binary[offset:offset + 4] != b"PE\0\0":
        raise ValueError("Invalid Windows executable")
    return struct.unpack_from("<H", binary, offset + 4)[0]


def package(artifact_root, output, commit, run_id, run_attempt, runtime_manifest):
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Invalid source commit")
    if any(not re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run_id, run_attempt)):
        raise ValueError("Invalid workflow run binding")
    prepared = {}
    manifest = read_file(runtime_manifest, 16 * 1024)
    for arch, (target, expected_machine) in TARGETS.items():
        root = artifact_root / arch
        build = root / "rclone-triage" / "target" / target / "release"
        binary = read_file(build / "rclone-triage.exe", 512 * 1024 * 1024)
        if machine(binary) != expected_machine:
            raise ValueError("Release executable has the wrong architecture")
        inventory = read_file(build / "dependencies.json", 16 * 1024 * 1024)
        current_manifest = read_file(root / "rclone-version.env", 16 * 1024)
        if manifest != current_manifest:
            raise ValueError("Release runtime manifests disagree")
        files = {
            "rclone-triage.exe": binary,
            "dependencies.json": inventory,
            "rclone-version.env": manifest,
            "BUILD.json": (json.dumps({
                "commit": commit, "architecture": arch,
                "run_id": run_id, "run_attempt": run_attempt,
                "channel": "nightly", "provider_acceptance_complete": False,
            }, indent=2) + "\n").encode("ascii"),
        }
        files["SHA256SUMS"] = "".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}\n"
            for name, data in sorted(files.items())
        ).encode("ascii")
        prepared[arch] = files

    # Validate the entire set before creating any publication outputs.
    output.mkdir(exist_ok=False)
    checksums = []
    for arch, files in prepared.items():
        name = f"rclone-triage-windows-{arch}.zip"
        archive = output / name
        with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as target:
            for filename, data in sorted(files.items()):
                target.writestr(filename, data)
        checksums.append(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {name}\n")
    (output / "SHA256SUMS").write_text("".join(checksums), encoding="ascii", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    args = parser.parse_args()
    package(args.artifact_root, args.output, args.commit, args.run_id, args.run_attempt,
            args.runtime_manifest)
