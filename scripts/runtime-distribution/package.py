#!/usr/bin/env python3
"""Create deterministic, unactivated runtime archives from verified build receipts."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import stat
import zipfile

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
RECIPE = HERE.parent / "runtime-readfix"
NATIVE = HERE.parent / "provider-lab/readfix-experimental"
STAMP = (1980, 1, 1, 0, 0, 0)


class PackageError(Exception):
    pass


def require(value, reason):
    if not value:
        raise PackageError(reason)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def compact(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def plain_file(path):
    require(path.is_file() and not path.is_symlink(), "plain_input_file_required")
    return path


def archive(destination, prefix, entries):
    """Stored ZIP entries avoid host zlib versions changing archive hashes."""
    require(not destination.exists(), "archive_already_exists")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+", prefix) and prefix not in (".", ".."), "invalid_archive_prefix")
    require(len({name for name, _, _ in entries}) == len(entries), "duplicate_archive_member")
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_STORED, allowZip64=False) as output:
        for name, source, executable in sorted(entries):
            require(re.fullmatch(r"[A-Za-z0-9_.@/-]+", name)
                    and not name.startswith("/") and all(p not in ("", ".", "..") for p in name.split("/")),
                    "invalid_archive_member")
            info = zipfile.ZipInfo(prefix + "/" + name, STAMP)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = ((stat.S_IFREG | (0o755 if executable else 0o644)) << 16)
            info.extra = b""
            info.comment = b""
            if isinstance(source, Path):
                plain_file(source)
                info.file_size = source.stat().st_size
                with source.open("rb") as incoming, output.open(info, "w") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            else:
                output.writestr(info, source)
    with zipfile.ZipFile(destination) as check:
        require(check.testzip() is None, "archive_crc_failed")
        require(check.namelist() == [prefix + "/" + name for name, _, _ in sorted(entries)], "archive_inventory_mismatch")
        for name, source, executable in entries:
            expected = digest(source) if isinstance(source, Path) else hashlib.sha256(source).hexdigest()
            with check.open(prefix + "/" + name) as stream:
                require(hashlib.file_digest(stream, "sha256").hexdigest() == expected, "archive_member_hash_mismatch")


def verify_inputs(work, native_report, recipe, native_gate, lock):
    recipe.verify_source(work / "rclone", lock, True)
    recipe.verify_prepared(work, lock)
    identity = recipe.recipe_identity()
    checks = json.loads(plain_file(work / "checks.json").read_text())
    require(checks.get("success") is True and checks.get("recipe") == identity
            and checks.get("scope") == lock["scope"] and checks.get("ledger_eligible") is False,
            "current_regressions_required")
    for field, outcome in (("baseline", "fail"), ("fixed", "pass"), ("race", "pass")):
        expected = [{"package": p, "test": t, "outcome": outcome} for p, t in sorted(recipe.EXPECTED_TESTS)]
        require(checks.get(field) == expected, "complete_regressions_required")
    prepared = json.loads((work / "prepared.json").read_text())
    builds = {}
    for platform in lock["platforms"]:
        directory = work / "artifacts" / platform
        binary = plain_file(directory / ("rclone.exe" if platform.startswith("windows-") else "rclone"))
        build = json.loads(plain_file(directory / "build.json").read_text())
        require(build.get("success") is True and build.get("recipe") == identity
                and build.get("different_root_rebuild_matched") is True
                and build.get("runtime_version") == lock["runtime_version"]
                and build.get("scope") == lock["scope"] and build.get("toolchain") == lock["toolchain"]
                and build.get("source_commit") == lock["rclone_commit"]
                and build.get("source_tree_sha256") == prepared["source_tree_sha256"]
                and build.get("platform") == platform and build.get("sha256") == digest(binary)
                and build.get("bytes") == binary.stat().st_size and build.get("ledger_eligible") is False,
                "verified_build_required")
        require(build.get("execution_verified") is (platform == "linux-amd64"), "execution_scope_mismatch")
        recipe.verify_binary(binary, platform)
        builds[platform] = build
    native = json.loads(plain_file(native_report).read_text())
    require(native.get("success") is True and native.get("errors") == []
            and native.get("ledger_eligible") is False
            and native.get("scope") == "experimental_native_reads_not_provider_acceptance"
            and set(native.get("providers", {})) == set(native_gate.PROVIDERS), "complete_native_report_required")
    runtime = {key: builds["linux-amd64"][key] for key in ("runtime_version", "sha256", "source_commit")}
    require(native.get("runtime") == runtime, "native_runtime_mismatch")
    for provider, record in native["providers"].items():
        require(record.get("success") is True and record.get("container_removed") is True, "native_cleanup_required")
        native_gate.validate_report(record["native"], provider, runtime)
    lab = NATIVE.parent
    sources = {p.relative_to(lab).as_posix() for p in NATIVE.iterdir() if p.suffix in (".py", ".go")}
    sources |= {p.relative_to(lab).as_posix() for p in lab.glob("*.py")}
    sources |= {"readfix-experimental/Dockerfile", "requirements-fixture.txt"}
    require(set(native.get("source_sha256", {})) == sources, "native_source_inventory_mismatch")
    for name, expected in native["source_sha256"].items():
        require(digest(plain_file(lab / name)) == expected, "native_source_changed")
    return builds


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--native-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    work, output = args.work_root.resolve(), args.output.resolve()
    require(not output.exists() and not output.is_relative_to(REPOSITORY), "fresh_external_output_required")
    recipe = module("package_recipe", RECIPE / "build.py")
    native_gate = module("package_native_gate", NATIVE / "run.py")
    lock = json.loads((RECIPE / "build-lock.json").read_text())
    version = lock["runtime_version"]
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+-triage-readfix\.[1-9][0-9]*", version),
            "distinct_patched_runtime_version_required")
    builds = verify_inputs(work, args.native_report, recipe, native_gate, lock)
    output.mkdir(mode=0o700)
    repeat = output / "repeat"
    repeat.mkdir(mode=0o700)
    # Archive contents describe only runtime inputs. CI verification receipts
    # remain separate so container image IDs and execution dates are not baked in.
    common = [("COPYING", work / "rclone/COPYING", False),
              ("licenses/filen-LICENSE", work / "rclone/readfix-deps/filen/LICENSE", False),
              ("licenses/proton-LICENSE", work / "rclone/readfix-deps/proton/LICENSE", False),
              ("licenses/proton-COPYING_NOTES.md", work / "rclone/readfix-deps/proton/COPYING_NOTES.md", False),
              ("source/build-lock.json", RECIPE / "build-lock.json", False)]
    for patch in lock["patches"]:
        common.append(("source/" + patch["name"], RECIPE / patch["name"], False))
    distributions = {}
    for platform, build in sorted(builds.items()):
        binary_name = "rclone.exe" if platform.startswith("windows-") else "rclone"
        binary = work / "artifacts" / platform / binary_name
        prefix = "rclone-" + version + "-" + platform
        filename = prefix + ".zip"
        provenance = {"scope": "patched_rclone_runtime_not_upstream_release", "runtime_version": version,
                      "source_commit": lock["rclone_commit"], "source_repository": lock["rclone_repository"],
                      "source_tree_sha256": build["source_tree_sha256"], "toolchain": build["toolchain"],
                      "platform": platform, "binary_sha256": build["sha256"], "binary_bytes": build["bytes"],
                      "patches": lock["patches"], "modules": lock["modules"]}
        entries = [(binary_name, binary, True), ("RUNTIME-SOURCE.json", compact(provenance), False), *common]
        for destination in (output / filename, repeat / filename):
            archive(destination, prefix, entries)
        require(digest(output / filename) == digest(repeat / filename), "archive_rebuild_mismatch")
        distributions[platform] = {"filename": filename, "sha256": digest(output / filename),
            "bytes": (output / filename).stat().st_size, "binary_sha256": build["sha256"],
            "binary_bytes": build["bytes"], "binary_member": prefix + "/" + binary_name}
    sums = "".join(item["sha256"] + "  " + item["filename"] + "\n"
                   for item in sorted(distributions.values(), key=lambda value: value["filename"]))
    (output / "SHA256SUMS").write_text(sums)
    manifest = {"schema_version": 1, "runtime_version": version,
                "scope": "unactivated_patched_runtime_distribution", "application_default_changed": False,
                "upstream_release": False, "success": True, "archive_format": "stored_zip_fixed_metadata_v1",
                "archives": distributions, "source_commit": lock["rclone_commit"]}
    (output / "distribution.json").write_bytes(compact(manifest))
    print(json.dumps(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
