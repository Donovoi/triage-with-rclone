#!/usr/bin/env python3
"""Build a sanitized, current-runtime provider evidence ledger.

Only `version` and `config providers` are executed, against a verified explicit
native rclone and empty private configuration. Fixture receipts are reports from
the current harness, not cryptographic attestations or hosted-account evidence.
"""

import argparse
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform as platform_module
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
WRAPPERS = {"alias", "cache", "chunker", "combine", "compress", "crypt", "hasher", "union"}
TIERS = ("local_protocol", "application", "vendor")
PLATFORMS = frozenset(("windows", "linux"))
AUTH_APPLICABILITY = frozenset(("none", "credentials", "oauth", "provider_specific"))
LIFECYCLE_APPLICABILITY = frozenset(("required", "not_applicable", "review_required"))
LIFECYCLE_DIMENSIONS = {
    "refresh": ("refresh_applicability", "credential_renewal_requirement", "credential_renewal"),
    "reauthentication": ("reauthentication_applicability", "connection_session_reauthentication_requirement",
                         "connection_session_reauthentication"),
}
ARCHIVE_CAPABILITIES = {
    "archive_crc32", "directory_as_file_rejection", "corrupt_member_rejection",
    "truncated_archive_rejection", "config_preservation",
}
ARCHIVE_ONLY_CAPABILITIES = ARCHIVE_CAPABILITIES - {"config_preservation"}
ARCHIVE_REQUIRED_CAPABILITIES = ARCHIVE_CAPABILITIES | {
    "listing", "download_hash", "missing_object_rejection", "source_preservation",
    "cleanup", "authentication_rejection", "fixture_write_rejection",
}
SWIFT_ONLY_CAPABILITIES = {"service_token_reacquisition"}
SWIFT_REQUIRED_CAPABILITIES = SWIFT_ONLY_CAPABILITIES | {
    "listing", "download_hash", "missing_object_rejection", "authentication_rejection",
    "source_preservation", "config_preservation", "cleanup", "fixture_write_rejection", "renewal_denial",
}
B2_ONLY_CAPABILITIES = {"account_token_reacquisition"}
B2_REQUIRED_CAPABILITIES = B2_ONLY_CAPABILITIES | {
    "listing", "download_hash", "missing_object_rejection", "authentication_rejection",
    "source_preservation", "config_preservation", "cleanup", "fixture_write_rejection", "renewal_denial",
}
AZUREBLOB_REQUIRED_CAPABILITIES = {
    "listing", "download_hash", "missing_object_rejection", "authentication_rejection",
    "source_preservation", "config_preservation", "cleanup", "fixture_write_rejection",
}
AZUREFILES_REQUIRED_CAPABILITIES = frozenset(AZUREBLOB_REQUIRED_CAPABILITIES)
SEAFILE_REQUIRED_CAPABILITIES = frozenset({
    "listing", "download_hash", "missing_object_rejection", "authentication_rejection",
    "source_preservation", "config_preservation", "cleanup", "fixture_write_rejection",
})
KOOFR_REQUIRED_CAPABILITIES = frozenset({
    "listing", "download_hash", "missing_object_rejection", "authentication_rejection",
    "source_preservation", "config_preservation", "cleanup", "fixture_write_rejection",
})
PIXELDRAIN_REQUIRED_CAPABILITIES = frozenset({
    "listing", "download_hash", "missing_object_rejection", "authentication_rejection",
    "source_preservation", "config_preservation", "cleanup", "fixture_write_rejection",
})
# Anonymous reads and LOW header rejection have separate closed contracts.
# Neither supplies application/vendor login or any credential lifecycle evidence.
INTERNETARCHIVE_ONLY_CAPABILITIES = frozenset({"anonymous_read"})
INTERNETARCHIVE_REQUIRED_CAPABILITIES = INTERNETARCHIVE_ONLY_CAPABILITIES | {
    "listing", "download_hash", "missing_object_rejection", "read_denial", "source_preservation",
    "config_preservation", "fixture_write_rejection", "cleanup",
}
INTERNETARCHIVE_ANONYMOUS_MODE = "internetarchive_anonymous_read_v1"
INTERNETARCHIVE_LOW_MODE = "internetarchive_low_read_auth_v1"
INTERNETARCHIVE_LOW_REQUIRED_CAPABILITIES = frozenset({
    "authentication_rejection", "source_preservation", "config_preservation", "cleanup",
})
INTERNETARCHIVE_MODE_CONTRACTS = {
    INTERNETARCHIVE_ANONYMOUS_MODE: INTERNETARCHIVE_REQUIRED_CAPABILITIES,
    INTERNETARCHIVE_LOW_MODE: INTERNETARCHIVE_LOW_REQUIRED_CAPABILITIES,
}
# Saved synthetic-token reads/rejections do not establish fresh OAuth consent,
# refresh, revocation or hosted-account acceptance.
PCLOUD_ONLY_CAPABILITIES = frozenset({"saved_token_read", "saved_token_rejection"})
PCLOUD_REQUIRED_CAPABILITIES = PCLOUD_ONLY_CAPABILITIES | {
    "listing", "download_hash", "missing_object_rejection", "read_denial",
    "source_preservation", "config_preservation", "fixture_write_rejection", "cleanup",
}
PCLOUD_SAVED_TOKEN_MODE = "pcloud_saved_token_read_v1"
PCLOUD_AUTHENTICATION_MODE = "pcloud_oauth_authentication_v1"
NETSTORAGE_REQUIRED_CAPABILITIES = frozenset({
    "listing", "download_hash", "missing_object_rejection", "authentication_rejection",
    "source_preservation", "config_preservation", "fixture_write_rejection", "cleanup",
})
FILEFABRIC_REQUIRED_CAPABILITIES = frozenset(PIXELDRAIN_REQUIRED_CAPABILITIES)
FILEFABRIC_CACHED_MODE = "filefabric_cached_session_v1"
FILEFABRIC_RENEWAL_MODE = "filefabric_later_call_renewal_v1"
FILEFABRIC_ONLY_CAPABILITIES = frozenset({
    "session_token_reacquisition", "config_scope_preservation", "saved_token_reuse",
})
FILEFABRIC_ADDITIONAL_CAPABILITIES = FILEFABRIC_ONLY_CAPABILITIES | {"renewal_denial"}
FILEFABRIC_RENEWAL_REQUIRED_CAPABILITIES = FILEFABRIC_ADDITIONAL_CAPABILITIES | {
    "source_preservation", "cleanup",
}
FILEFABRIC_MODE_CONTRACTS = {
    FILEFABRIC_CACHED_MODE: FILEFABRIC_REQUIRED_CAPABILITIES,
    FILEFABRIC_RENEWAL_MODE: FILEFABRIC_RENEWAL_REQUIRED_CAPABILITIES,
}
MEMORY_REQUIRED_CAPABILITIES = frozenset({
    "listing", "download_hash", "missing_object_rejection", "authentication_rejection",
    "source_preservation", "config_preservation", "cleanup",
})
SMB_MODE = "smb_samba_ntlm_read_v1"
SMB_REQUIRED_CAPABILITIES = frozenset({
    "listing", "download_hash", "missing_object_rejection", "authentication_rejection",
    "source_preservation", "config_preservation", "cleanup",
})
READ_FIXTURE_CONTRACTS = {
    "azureblob": AZUREBLOB_REQUIRED_CAPABILITIES,
    "azurefiles": AZUREFILES_REQUIRED_CAPABILITIES,
    "seafile": SEAFILE_REQUIRED_CAPABILITIES,
    "koofr": KOOFR_REQUIRED_CAPABILITIES,
    "pixeldrain": PIXELDRAIN_REQUIRED_CAPABILITIES,
    "filefabric": FILEFABRIC_REQUIRED_CAPABILITIES,
    "internetarchive": INTERNETARCHIVE_REQUIRED_CAPABILITIES,
    "netstorage": NETSTORAGE_REQUIRED_CAPABILITIES,
    "pcloud": PCLOUD_REQUIRED_CAPABILITIES,
}
CAPABILITIES = {
    "authentication", "listing", "download_hash", "manifest_integrity",
    "source_preservation", "cleanup", "refresh", "reauthentication", "cancellation", "denial",
    "revocation", "missing_object_rejection", "authentication_rejection", "read_denial",
    "truncated_download_rejection", "cancellation_cleanup", "fixture_write_rejection", "host_key_rejection", "renewal_denial",
} | ARCHIVE_CAPABILITIES | SWIFT_ONLY_CAPABILITIES | B2_ONLY_CAPABILITIES | FILEFABRIC_ONLY_CAPABILITIES | INTERNETARCHIVE_ONLY_CAPABILITIES | PCLOUD_ONLY_CAPABILITIES
FIXTURE_KINDS = {
    "http": "independent_loopback", "webdav": "independent_loopback",
    "ftp": "independent_loopback", "sftp": "rclone_loopback",
    "s3": "rclone_loopback", "local": "local", "archive": "local", "memory": "local",
    "swift": "independent_loopback", "b2": "independent_loopback", "azureblob": "independent_loopback",
    "azurefiles": "independent_loopback", "seafile": "independent_loopback", "koofr": "independent_loopback",
    "pixeldrain": "independent_loopback", "filefabric": "independent_loopback",
    "internetarchive": "independent_loopback",
    "netstorage": "independent_loopback",
    "pcloud": "independent_loopback",
}
FIXTURE_CAPABILITIES = {
    "listing", "download_hash", "missing_object_rejection", "source_preservation",
    "authentication_rejection", "cleanup", "truncated_download_rejection", "read_denial",
    "cancellation_cleanup", "fixture_write_rejection", "host_key_rejection", "renewal_denial",
} | ARCHIVE_CAPABILITIES | SWIFT_ONLY_CAPABILITIES | B2_ONLY_CAPABILITIES | FILEFABRIC_ONLY_CAPABILITIES | INTERNETARCHIVE_ONLY_CAPABILITIES | PCLOUD_ONLY_CAPABILITIES
HARNESSES = ("fixture_servers.py", "run_lab.py", "fixture_tls.py", "fixture_pcloud.py", "requirements-fixture.txt")
HASH_PATTERN = re.compile(r"[a-f0-9]{64}")
ID_PATTERN = re.compile(r"[a-z0-9_]{1,80}")
MAX_JSON = 32 * 1024 * 1024
MAX_RECEIPT = 1024 * 1024
MAX_AGE_HOURS = 24
MAX_RUN_MINUTES = 30


class CoverageError(Exception):
    """Static, non-secret diagnostic code only."""


METADATA_STAGES = frozenset({
    "runtime_preflight", "runtime_verification", "temporary_create",
    "temporary_permissions", "runtime_copy", "runtime_permissions", "runtime_rehash",
    "config_create", "version_probe", "providers_probe", "catalog_parse",
    "temporary_cleanup", "initial_catalog_summary",
})
METADATA_CATEGORIES = frozenset({
    "access_denied", "sharing_violation", "not_found", "os_error", "timeout",
    "subprocess_error", "value_error", "type_error", "key_error", "runtime_error",
})
METADATA_EXCEPTIONS = (OSError, ValueError, TypeError, KeyError,
                       subprocess.SubprocessError, RuntimeError)


class MetadataDiagnosticError(CoverageError):
    """Only static codes survive cleanup; never retain the original exception."""

    def __init__(self, primary_code, diagnostics):
        allowed = {f"metadata_{stage}_{category}"
                   for stage in METADATA_STAGES for category in METADATA_CATEGORIES}
        if (not diagnostics or any(code not in allowed for code in diagnostics)
                or (primary_code is not None and
                    (not isinstance(primary_code, str)
                     or re.fullmatch(r"[a-z][a-z0-9_]{0,100}", primary_code) is None))):
            raise ValueError("invalid_metadata_diagnostic")
        # primary_code comes only from an existing CoverageError, whose contract
        # already requires a static code. New boundary codes use the closed set.
        self.codes = ((primary_code,) if primary_code is not None else ()) + tuple(diagnostics)
        super().__init__(self.codes[0])


def metadata_diagnostic(stage, error):
    if stage not in METADATA_STAGES:
        raise ValueError("invalid_metadata_stage")
    if isinstance(error, subprocess.TimeoutExpired):
        category = "timeout"
    elif isinstance(error, subprocess.SubprocessError):
        category = "subprocess_error"
    elif isinstance(error, OSError):
        if getattr(error, "winerror", None) in (32, 33):
            category = "sharing_violation"
        elif isinstance(error, PermissionError) or error.errno in (errno.EACCES, errno.EPERM):
            category = "access_denied"
        elif isinstance(error, FileNotFoundError) or error.errno == errno.ENOENT:
            category = "not_found"
        else:
            category = "os_error"
    elif isinstance(error, ValueError):
        category = "value_error"
    elif isinstance(error, TypeError):
        category = "type_error"
    elif isinstance(error, KeyError):
        category = "key_error"
    elif isinstance(error, RuntimeError):
        category = "runtime_error"
    else:
        raise ValueError("invalid_metadata_exception")
    return f"metadata_{stage}_{category}"


def fail(code):
    raise CoverageError(code)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def compact_json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate_json_key")
        result[key] = value
    return result


def read_json(path, limit=MAX_JSON):
    try:
        path = plain_path(path)
        with path.open("rb") as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            fail("json_size_limit")
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except CoverageError:
        raise
    except (OSError, ValueError, UnicodeError):
        fail("invalid_json_input")


def plain_path(path, allow_missing_leaf=False):
    path = Path(path)
    if not path.is_absolute():
        fail("absolute_path_required")
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if part == path and allow_missing_leaf:
                continue
            fail("input_unavailable")
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            fail("reparse_path_rejected")
    return path


def valid_hash(value):
    return isinstance(value, str) and HASH_PATTERN.fullmatch(value) is not None


def _text(value, maximum=200):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value):
        fail("invalid_catalog")
    return value


def canonical_schema(provider):
    """Stable contract only: help/default/example and machine paths are omitted."""
    if not isinstance(provider, dict):
        fail("invalid_catalog")
    name = _text(provider.get("Name")).strip()
    prefix = _text(provider.get("Prefix", "")).strip().lower()
    if not name or not re.fullmatch(r"[A-Za-z0-9_. -]{1,80}", name):
        fail("invalid_catalog")
    if prefix and not ID_PATTERN.fullmatch(prefix):
        fail("invalid_catalog")
    options = provider.get("Options", [])
    if options is None:
        options = []
    if not isinstance(options, list) or len(options) > 2048:
        fail("invalid_catalog")
    normalized, seen = [], set()
    for option in options:
        if not isinstance(option, dict):
            fail("invalid_catalog")
        option_name = _text(option.get("Name"))
        option_type = _text(option.get("Type"))
        selector = _text(option.get("Provider", ""), 1024)
        identity = (option_name, selector)
        if not re.fullmatch(r"[A-Za-z0-9_]{1,100}", option_name) or identity in seen:
            fail("invalid_catalog")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\|[A-Za-z][A-Za-z0-9_]*)*", option_type):
            fail("invalid_catalog")
        seen.add(identity)
        entry = {"Name": option_name, "Type": option_type, "Provider": selector}
        for key in ("Required", "IsPassword", "Advanced", "Exclusive"):
            value = option.get(key, False)
            if type(value) is not bool:
                fail("invalid_catalog")
            entry[key] = value
        normalized.append(entry)
    return {"Name": name, "Prefix": prefix, "Options": sorted(normalized, key=lambda v: (v["Name"], v["Provider"]))}


def schema_digest(provider):
    return sha256_bytes(compact_json(canonical_schema(provider)))


def catalog_from_schemas(schemas):
    if not isinstance(schemas, list) or not schemas or len(schemas) > 2048:
        fail("invalid_catalog")
    result, seen = [], set()
    for provider in schemas:
        canonical = canonical_schema(provider)
        backend = canonical["Prefix"] or canonical["Name"].lower()
        if not ID_PATTERN.fullmatch(backend) or backend in seen:
            fail("invalid_catalog")
        seen.add(backend)
        if backend in WRAPPERS or canonical["Name"].lower() in WRAPPERS:
            continue
        result.append({"backend": backend, "canonical_name": canonical["Name"],
                       "schema_sha256": sha256_bytes(compact_json(canonical))})
    if not result:
        fail("empty_catalog")
    return sorted(result, key=lambda value: value["backend"])


def compute_harness_sha256(root):
    """Same fixed file framing as the producer, with no receipt-supplied paths."""
    digest = hashlib.sha256()
    for filename in sorted(HARNESSES):
        path = plain_path(Path(root).absolute() / filename)
        data = path.read_bytes()
        if len(data) > MAX_RECEIPT:
            fail("harness_size_limit")
        digest.update(filename.encode("utf-8") + b"\0" + data + b"\0")
    return digest.hexdigest()


def smb_evidence_module():
    """Load only the repository-owned, pure SMB receipt helper on demand."""
    path = plain_path(ROOT / "scripts" / "provider-lab" / "smb" / "protocol_evidence.py")
    try:
        spec = importlib.util.spec_from_file_location("coverage_smb_evidence", path)
        module = importlib.util.module_from_spec(spec)
        source = path.read_bytes()
        if len(source) > MAX_RECEIPT:
            fail("smb_evidence_helper_size_limit")
        exec(compile(source, str(path), "exec"), module.__dict__)
        return module
    except (ImportError, OSError, SyntaxError, AttributeError, TypeError):
        fail("smb_evidence_helper_unavailable")


def compute_smb_bindings(root):
    """Current fixed SMB sources, never paths or expectations from a receipt."""
    try:
        return smb_evidence_module().compute_bindings(plain_path(Path(root).absolute()))
    except (OSError, ValueError, TypeError, KeyError):
        fail("smb_evidence_bindings_invalid")


def pcloud_evidence_module():
    """Import definitions only from the current owned stdlib supervisor."""
    path = plain_path(ROOT / "scripts" / "provider-lab" / "pcloud-oauth" / "run_container.py")
    try:
        source = path.read_bytes()
        if len(source) > MAX_RECEIPT:
            fail("pcloud_evidence_helper_size_limit")
        spec = importlib.util.spec_from_file_location("coverage_pcloud_evidence", path)
        module = importlib.util.module_from_spec(spec)
        exec(compile(source, str(path), "exec"), module.__dict__)
        return module
    except (ImportError, OSError, SyntaxError, AttributeError, TypeError):
        fail("pcloud_evidence_helper_unavailable")


def compute_pcloud_bindings(root):
    try:
        return pcloud_evidence_module().compute_bindings(plain_path(Path(root).absolute()))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        fail("pcloud_evidence_bindings_invalid")


def validate_pcloud_receipt(receipt, runtime, bindings, now, max_age_hours, fixture_manifest_sha256):
    if bindings is None:
        fail("unknown_receipt_schema")
    if (not isinstance(bindings, dict) or not valid_hash(fixture_manifest_sha256)
            or bindings.get("fixture_manifest_sha256") != fixture_manifest_sha256):
        fail("pcloud_evidence_bindings_invalid")
    try:
        pcloud_evidence_module().validate_authentication_evidence(receipt, runtime, bindings, now, max_age_hours)
    except (ValueError, RuntimeError) as error:
        code = str(error)
        fail(code if re.fullmatch(r"[a-z][a-z0-9_]{0,80}", code) else "invalid_pcloud_evidence")
    except (TypeError, KeyError, AttributeError, OverflowError):
        fail("invalid_pcloud_evidence")
    return receipt


def validate_smb_receipt(receipt, runtime, bindings, now, max_age_hours, fixture_manifest_sha256):
    if bindings is None:
        # Existing callers have not opted into the separately bound format.
        fail("unknown_receipt_schema")
    if runtime.get("platform") != "linux":
        fail("receipt_runtime_mismatch")
    if (not isinstance(bindings, dict) or set(bindings) != {
            "harness_sha256", "fixture_manifest_sha256", "source_sha256", "base_image", "samba_version"}
            or not valid_hash(fixture_manifest_sha256)
            or bindings["fixture_manifest_sha256"] != fixture_manifest_sha256):
        fail("smb_evidence_bindings_invalid")
    try:
        smb_evidence_module().validate_evidence(
            receipt, runtime, bindings["harness_sha256"], fixture_manifest_sha256,
            bindings["source_sha256"], now, max_age_hours,
            expected_base_image=bindings["base_image"], expected_samba_version=bindings["samba_version"])
    except ValueError as error:
        code = str(error)
        fail(code if re.fullmatch(r"[a-z][a-z0-9_]{0,80}", code) else "invalid_smb_evidence")
    except (TypeError, KeyError, AttributeError, OverflowError):
        fail("invalid_smb_evidence")
    return receipt


def compute_fixture_manifest_sha256(root):
    """Read the current repository fixture definition, never a receipt path.

    Importing this reviewed module defines fixture classes only; it starts no
    listeners or subprocesses. Recompute the producer's framing independently.
    """
    path = plain_path(Path(root).absolute() / "fixture_servers.py")
    try:
        spec = importlib.util.spec_from_file_location("coverage_fixture_definitions", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        files = module.FILES
    except (ImportError, OSError, SyntaxError, AttributeError, TypeError):
        fail("invalid_fixture_definition")
    if not isinstance(files, dict) or not files or len(files) > 100:
        fail("invalid_fixture_definition")
    manifest = []
    for name, content in sorted(files.items()):
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_. /-]{1,200}", name)
                or name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/"))
                or not isinstance(content, bytes) or len(content) > MAX_RECEIPT):
            fail("invalid_fixture_definition")
        manifest.append({"path": name, "size": len(content), "sha256": sha256_bytes(content)})
    return sha256_bytes(json.dumps(manifest, separators=(",", ":")).encode("utf-8"))


def _policy_text(value, maximum=4096):
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(character) < 32 for character in value)):
        fail("invalid_policy")
    return value


def validate_plan_metadata(entry, profile):
    auth = entry.get("auth_applicability")
    if not isinstance(auth, str) or auth not in AUTH_APPLICABILITY:
        fail("invalid_policy")
    for entry_field, _, _ in LIFECYCLE_DIMENSIONS.values():
        value = entry.get(entry_field)
        if not isinstance(value, str) or value not in LIFECYCLE_APPLICABILITY:
            fail("invalid_policy")
    sources = entry.get("source_links")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 20:
        fail("invalid_policy")
    for source in sources:
        _policy_text(source)
        try:
            url = urlsplit(source)
            if (url.scheme != "https" or not url.hostname or url.username is not None
                    or url.password is not None or "\\" in source or any(c.isspace() for c in source)):
                fail("invalid_policy")
            # Parsing .port also rejects malformed or out-of-range ports.
            _ = url.port
        except ValueError:
            fail("invalid_policy")
    modes = entry.get("renewal_modes")
    if not isinstance(modes, list) or not 1 <= len(modes) <= 32:
        fail("invalid_policy")
    fields = {"auth_mode", "credential_renewal_requirement", "connection_session_reauthentication_requirement", "renewal_kind",
              "source_supported_behavior", "required_lifecycle_scenarios"}
    seen = set()
    requirements = {capability: set() for capability in LIFECYCLE_DIMENSIONS}
    for mode in modes:
        if not isinstance(mode, dict) or set(mode) != fields:
            fail("invalid_policy")
        identity = _policy_text(mode["auth_mode"], 256).strip().casefold()
        if identity in seen:
            fail("invalid_policy")
        seen.add(identity)
        renewal_kind = _policy_text(mode["renewal_kind"], 80)
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", renewal_kind):
            fail("invalid_policy")
        _policy_text(mode["source_supported_behavior"])
        scenarios = mode["required_lifecycle_scenarios"]
        if not isinstance(scenarios, list) or not 1 <= len(scenarios) <= 20:
            fail("invalid_policy")
        for scenario in scenarios:
            _policy_text(scenario, 512)
        for capability, (_, mode_field, _) in LIFECYCLE_DIMENSIONS.items():
            requirement = mode[mode_field]
            if not isinstance(requirement, str) or requirement not in LIFECYCLE_APPLICABILITY:
                fail("invalid_policy")
            requirements[capability].add(requirement)
    for capability, (entry_field, _, _) in LIFECYCLE_DIMENSIONS.items():
        decisions = requirements[capability]
        aggregate = ("review_required" if "review_required" in decisions else
                     "required" if "required" in decisions else "not_applicable")
        if (entry[entry_field] != aggregate
                or ((capability in profile.get("unresolved_applicability", [])) != (aggregate == "review_required"))):
            fail("invalid_policy")
    for tier in ("application", "vendor"):
        capabilities = profile["required"].get(tier)
        if capabilities is None:
            continue
        if auth != "none" and "authentication" not in capabilities:
            fail("invalid_policy")
        for capability, (entry_field, _, _) in LIFECYCLE_DIMENSIONS.items():
            if "required" in requirements[capability] and capability not in capabilities:
                fail("invalid_policy")
            if entry[entry_field] == "not_applicable" and capability in capabilities:
                fail("invalid_policy")


def validate_policy(policy):
    if not isinstance(policy, dict) or type(policy.get("schema_version")) is not int or policy["schema_version"] != 2:
        fail("invalid_policy")
    reviewed_version = policy.get("reviewed_runtime_version")
    if not isinstance(reviewed_version, str) or not re.fullmatch(
            r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", reviewed_version):
        fail("invalid_policy")
    profiles, providers = policy.get("profiles"), policy.get("providers")
    if not isinstance(profiles, dict) or not profiles or not isinstance(providers, dict):
        fail("invalid_policy")
    for key, profile in profiles.items():
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", key) or not isinstance(profile, dict):
            fail("invalid_policy")
        required = profile.get("required")
        if not isinstance(required, dict) or "application" not in required or set(required) - set(TIERS):
            fail("invalid_policy")
        if type(profile.get("review_required", False)) is not bool:
            fail("invalid_policy")
        unresolved = profile.get("unresolved_applicability", [])
        if not isinstance(unresolved, list) or any(not isinstance(value, str) or value not in CAPABILITIES for value in unresolved) or len(unresolved) != len(set(unresolved)):
            fail("invalid_policy")
        for capabilities in required.values():
            if not isinstance(capabilities, list) or not capabilities or any(
                not isinstance(capability, str) or capability not in CAPABILITIES for capability in capabilities
            ) or len(capabilities) != len(set(capabilities)):
                fail("invalid_policy")
    for backend, entry in providers.items():
        if not ID_PATTERN.fullmatch(backend) or not isinstance(entry, dict):
            fail("invalid_policy")
        if not isinstance(entry.get("canonical_name"), str):
            fail("invalid_policy")
        # A platform variant is a separately reviewed full contract. Never
        # accept either platform's digest as a fallback for the other one.
        if ("schema_sha256" in entry) == ("schema_sha256_by_platform" in entry):
            fail("invalid_policy")
        if "schema_sha256" in entry:
            if not valid_hash(entry["schema_sha256"]):
                fail("invalid_policy")
        else:
            variants = entry["schema_sha256_by_platform"]
            if (not isinstance(variants, dict) or not variants or set(variants) - PLATFORMS
                    or any(not valid_hash(value) for value in variants.values())):
                fail("invalid_policy")
        if entry.get("profile") not in profiles:
            fail("invalid_policy")
        validate_plan_metadata(entry, profiles[entry["profile"]])
        if "notes" in entry:
            values = entry["notes"] if isinstance(entry["notes"], list) else [entry["notes"]]
            if len(values) > 20 or any(not isinstance(value, str) or len(value) > 4096 for value in values):
                fail("invalid_policy")
    return policy


def utc_text(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_utc(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", value):
        fail("invalid_receipt_time")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail("invalid_receipt_time")


def validate_receipt(receipt, runtime, harness_sha256, now, max_age_hours=MAX_AGE_HOURS,
                     fixture_manifest_sha256=None, smb_bindings=None, pcloud_bindings=None):
    if isinstance(receipt, dict) and type(receipt.get("schema_version")) is int and receipt["schema_version"] == 3:
        return validate_smb_receipt(receipt, runtime, smb_bindings, now, max_age_hours, fixture_manifest_sha256)
    if isinstance(receipt, dict) and type(receipt.get("schema_version")) is int and receipt["schema_version"] == 5:
        return validate_pcloud_receipt(receipt, runtime, pcloud_bindings, now, max_age_hours, fixture_manifest_sha256)
    if (not isinstance(receipt, dict) or type(receipt.get("schema_version")) is not int
            or receipt["schema_version"] not in (1, 2, 4) or receipt.get("scope") != "rclone_backend_protocol_fixture"):
        fail("unknown_receipt_schema")
    renewal_receipt = receipt["schema_version"] == 2
    low_receipt = receipt["schema_version"] == 4
    # Schemas 2 and 4 are separately invoked, closed experiments, never
    # generic mode overrides for the predefined schema-1 backend contracts.
    if renewal_receipt or low_receipt:
        if set(receipt) != {"schema_version", "scope", "runtime", "platform", "harness_sha256",
                            "fixture_manifest_sha256", "started_utc", "finished_utc", "success",
                            "cleanup_passed", "backends", "errors"}:
            fail("invalid_fixture_mode")
    elif set(receipt) & {"fixture_mode", "modes", "subscenarios"}:
        fail("invalid_fixture_mode")
    if not isinstance(receipt.get("runtime"), dict) or any(
        receipt["runtime"].get(key) != runtime[key] for key in ("version", "sha256")
    ) or receipt.get("platform") != runtime["platform"]:
        fail("receipt_runtime_mismatch")
    if low_receipt and set(receipt["runtime"]) != {"version", "sha256"}:
        fail("receipt_runtime_mismatch")
    if not valid_hash(harness_sha256) or receipt.get("harness_sha256") != harness_sha256:
        fail("receipt_harness_mismatch")
    if not valid_hash(fixture_manifest_sha256) or receipt.get("fixture_manifest_sha256") != fixture_manifest_sha256:
        fail("receipt_fixture_manifest_mismatch")
    start, finish = parse_utc(receipt.get("started_utc")), parse_utc(receipt.get("finished_utc"))
    if finish < start or finish - start > timedelta(minutes=MAX_RUN_MINUTES):
        fail("invalid_receipt_duration")
    if start > now or finish > now:
        fail("future_receipt")
    if now - finish > timedelta(hours=max_age_hours):
        fail("expired_receipt")
    if type(receipt.get("success")) is not bool or type(receipt.get("cleanup_passed")) is not bool:
        fail("invalid_receipt_outcome")
    errors = receipt.get("errors")
    if not isinstance(errors, list) or len(errors) > 32 or any(
        not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,80}", code) for code in errors
    ):
        fail("invalid_fixture_errors")
    if receipt["success"] and errors:
        fail("inconsistent_fixture_success")
    backends = receipt.get("backends")
    if not isinstance(backends, list) or not backends or len(backends) > len(FIXTURE_KINDS):
        fail("invalid_receipt_backends")
    if (renewal_receipt or low_receipt) and len(backends) != 1:
        fail("invalid_fixture_mode")
    seen = set()
    for row in backends:
        if not isinstance(row, dict):
            fail("invalid_receipt_backends")
        backend = row.get("backend")
        if not isinstance(backend, str) or backend not in FIXTURE_KINDS or backend in seen or row.get("fixture_kind") != FIXTURE_KINDS[backend]:
            fail("unknown_fixture_backend")
        if renewal_receipt:
            if (backend != "filefabric" or row.get("fixture_mode") != FILEFABRIC_RENEWAL_MODE
                    or set(row) != {"backend", "fixture_kind", "fixture_mode", "capabilities", "errors"}):
                fail("invalid_fixture_mode")
        elif low_receipt:
            if (backend != "internetarchive" or row.get("fixture_mode") != INTERNETARCHIVE_LOW_MODE
                    or set(row) != {"backend", "fixture_kind", "fixture_mode", "capabilities", "errors"}):
                fail("invalid_fixture_mode")
        elif set(row) & {"fixture_mode", "modes", "subscenarios"}:
            fail("invalid_fixture_mode")
        if not low_receipt and backend in ("internetarchive", "netstorage", "pcloud") and (
                set(row) != {"backend", "fixture_kind", "capabilities", "errors"}
                or set(receipt) != {"schema_version", "scope", "runtime", "platform", "harness_sha256",
                                    "fixture_manifest_sha256", "started_utc", "finished_utc", "success",
                                    "cleanup_passed", "backends", "errors"}):
            # Unknown scope/auth fields cannot redefine these fixed schema-1
            # contracts; another profile needs independent source review.
            fail("invalid_fixture_mode")
        seen.add(backend)
        capabilities = row.get("capabilities")
        if not isinstance(capabilities, dict) or not capabilities or set(capabilities) - FIXTURE_CAPABILITIES:
            fail("invalid_fixture_capability")
        if (backend not in ("http", "webdav") and set(capabilities) & {"truncated_download_rejection", "cancellation_cleanup"}
                or backend not in ("http", "webdav", "ftp", "archive", "swift", "b2", "azureblob", "azurefiles", "seafile", "koofr", "pixeldrain", "filefabric", "internetarchive", "netstorage", "pcloud") and "fixture_write_rejection" in capabilities
                or backend != "sftp" and "host_key_rejection" in capabilities
                or backend != "archive" and set(capabilities) & ARCHIVE_ONLY_CAPABILITIES
                or backend not in ("archive", "memory", "swift", "b2", "azureblob", "azurefiles", "seafile", "koofr", "pixeldrain", "filefabric", "internetarchive", "netstorage", "pcloud") and "config_preservation" in capabilities
                or backend != "swift" and set(capabilities) & SWIFT_ONLY_CAPABILITIES
                or backend != "b2" and set(capabilities) & B2_ONLY_CAPABILITIES
                or backend != "internetarchive" and set(capabilities) & INTERNETARCHIVE_ONLY_CAPABILITIES
                or backend not in ("internetarchive", "pcloud") and "read_denial" in capabilities
                or backend != "pcloud" and set(capabilities) & PCLOUD_ONLY_CAPABILITIES
                or not renewal_receipt and set(capabilities) & FILEFABRIC_ONLY_CAPABILITIES
                or backend not in ("swift", "b2") and not renewal_receipt and "renewal_denial" in capabilities):
            fail("invalid_fixture_capability")
        if any(value not in ("passed", "failed", "not_run", "not_applicable") for value in capabilities.values()):
            fail("invalid_fixture_outcome")
        # Only the reviewed local filesystem/archive/memory fixtures have no auth.
        if any(value == "not_applicable" and (backend not in ("local", "archive", "memory") or key != "authentication_rejection") for key, value in capabilities.items()):
            fail("invalid_fixture_not_applicable")
        if backend == "archive" and (set(capabilities) != ARCHIVE_REQUIRED_CAPABILITIES
                                     or capabilities["authentication_rejection"] != "not_applicable"):
            fail("invalid_fixture_capability")
        # Memory evidence covers one finite in-process batch, without network
        # authentication, write rejection, persistence or lifecycle claims.
        if backend == "memory" and (set(capabilities) != MEMORY_REQUIRED_CAPABILITIES
                                    or capabilities["authentication_rejection"] != "not_applicable"):
            fail("invalid_fixture_capability")
        # This exact contract attests only the reviewed Swift v1 forced-401
        # fixture. It is neither OAuth refresh nor general reauthentication.
        if backend == "swift" and set(capabilities) != SWIFT_REQUIRED_CAPABILITIES:
            fail("invalid_fixture_capability")
        # B2 account-token replacement has a separate, exact native-API
        # contract. Never alias it to Swift, OAuth or session evidence.
        if backend == "b2" and set(capabilities) != B2_REQUIRED_CAPABILITIES:
            fail("invalid_fixture_capability")
        # These independent fixtures share capability names, not protocol or
        # auth semantics. No result proves another service, mode or lifecycle.
        if renewal_receipt and set(capabilities) != FILEFABRIC_RENEWAL_REQUIRED_CAPABILITIES:
            fail("invalid_fixture_capability")
        if low_receipt and set(capabilities) != INTERNETARCHIVE_LOW_REQUIRED_CAPABILITIES:
            fail("invalid_fixture_capability")
        if not (renewal_receipt or low_receipt) and backend in READ_FIXTURE_CONTRACTS and set(capabilities) != READ_FIXTURE_CONTRACTS[backend]:
            fail("invalid_fixture_capability")
        errors = row.get("errors")
        if not isinstance(errors, list) or len(errors) > 32 or any(not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,80}", code) for code in errors):
            fail("invalid_fixture_errors")
        if receipt["success"] and (errors or any(value in ("failed", "not_run") for value in capabilities.values())
                                   or capabilities.get("cleanup") != "passed"):
            fail("inconsistent_fixture_success")
    if receipt["success"] and not receipt["cleanup_passed"]:
        fail("inconsistent_fixture_success")
    return receipt


def merge_fixture_observation(observed, capabilities, failed, run):
    """A later successful run cannot erase an observed failure."""
    observed["failed"] |= failed
    observed["runs"].append(run)
    for capability, status in capabilities.items():
        prior = observed["capabilities"].get(capability)
        if status == "failed" or prior == "failed":
            observed["capabilities"][capability] = "failed"
        elif status == "passed" or prior != "passed":
            observed["capabilities"][capability] = status


def evaluate(catalog, policy, runtime, receipts, harness_sha256, now=None, max_age_hours=MAX_AGE_HOURS,
             fixture_manifest_sha256=None, smb_bindings=None, pcloud_bindings=None):
    """Receipts are explicit batch inputs. Failed current evidence stays failed."""
    now = now or datetime.now(timezone.utc)
    validate_policy(policy)
    if not isinstance(runtime.get("platform"), str) or runtime["platform"] not in PLATFORMS:
        fail("unsupported_runtime_platform")
    if not 1 <= max_age_hours <= 168:
        fail("invalid_freshness_window")
    report = {
        "schema_version": 1, "generated_utc": utc_text(now), "runtime": dict(runtime),
        "catalog_sha256": sha256_bytes(compact_json(catalog)),
        "policy_sha256": sha256_bytes(compact_json(policy)),
        "policy_schema_version": policy["schema_version"],
        "harness_sha256": harness_sha256, "fixture_max_age_hours": max_age_hours,
        "fixture_manifest_sha256": fixture_manifest_sha256,
        "evidence_trust": "harness_report_not_cryptographic_attestation",
        "scope": "current_runtime_catalog_and_layered_evidence",
        "all_plans_current": False, "all_complete": False, "providers": [], "errors": [],
        "retired_policy_backends": sorted(set(policy["providers"]) - {entry["backend"] for entry in catalog}),
        "applicability_summary": {label: {state: 0 for state in (*sorted(LIFECYCLE_APPLICABILITY), "not_verified")}
                                  for _, _, label in LIFECYCLE_DIMENSIONS.values()},
    }
    observations = {}
    for receipt in receipts:
        try:
            validate_receipt(receipt, runtime, harness_sha256, now, max_age_hours, fixture_manifest_sha256,
                             smb_bindings=smb_bindings, pcloud_bindings=pcloud_bindings)
            for row in receipt["backends"]:
                if row["backend"] not in {entry["backend"] for entry in catalog}:
                    fail("fixture_backend_absent_from_catalog")
            for row in receipt["backends"]:
                observed = observations.setdefault(row["backend"], {"capabilities": {}, "failed": False, "runs": []})
                failed = not receipt["success"] or not receipt["cleanup_passed"] or bool(row["errors"])
                run = {
                    "receipt_sha256": sha256_bytes(compact_json(receipt)),
                    "finished_utc": receipt["finished_utc"],
                    "expires_utc": utc_text(parse_utc(receipt["finished_utc"]) + timedelta(hours=max_age_hours)),
                    "fixture_kind": row["fixture_kind"],
                    "fixture_manifest_sha256": receipt["fixture_manifest_sha256"],
                }
                contributed = row["capabilities"]
                if row["backend"] == "smb":
                    native = receipt["native_evidence"]
                    probe_runtime = (native.get("probe") or {}).get("runtime", {})
                    run.update(fixture_mode=SMB_MODE, platform="linux", architecture="amd64",
                               samba_version=probe_runtime.get("samba_version"), base_image=native["base_image"],
                               image_id=native["image_id"], source_sha256=dict(native["source_sha256"]),
                               harness_sha256=receipt["harness_sha256"])
                    mode_observed = observed.setdefault("modes", {}).setdefault(
                        SMB_MODE, {"capabilities": {}, "failed": False, "runs": []})
                    merge_fixture_observation(mode_observed, contributed, failed, run)
                if row["backend"] == "internetarchive":
                    mode = row.get("fixture_mode", INTERNETARCHIVE_ANONYMOUS_MODE)
                    run["fixture_mode"] = mode
                    mode_observed = observed.setdefault("modes", {}).setdefault(
                        mode, {"capabilities": {}, "failed": False, "runs": []})
                    merge_fixture_observation(mode_observed, contributed, failed, run)
                    # LOW tests header rejection; its bounded reads cannot
                    # substitute for the complete anonymous inventory contract.
                    if mode == INTERNETARCHIVE_LOW_MODE:
                        contributed = {key: value for key, value in contributed.items()
                                       if key in INTERNETARCHIVE_LOW_REQUIRED_CAPABILITIES}
                if row["backend"] == "pcloud":
                    mode = row.get("fixture_mode", PCLOUD_SAVED_TOKEN_MODE)
                    run["fixture_mode"] = mode
                    if mode == PCLOUD_AUTHENTICATION_MODE:
                        native = receipt["native_evidence"]
                        run.update(platform="linux", architecture="amd64", base_image=native["base_image"],
                                   image_id=native["image_id"], python_version=native["python_version"],
                                   dependency_lock_sha256=native["dependency_lock_sha256"],
                                   source_sha256=dict(native["source_sha256"]), harness_sha256=receipt["harness_sha256"])
                        contributed = {"authentication": contributed["authentication"]}
                    mode_observed = observed.setdefault("modes", {}).setdefault(
                        mode, {"capabilities": {}, "failed": False, "runs": []})
                    merge_fixture_observation(mode_observed, contributed, failed, run)
                if row["backend"] == "filefabric":
                    mode = row.get("fixture_mode", FILEFABRIC_CACHED_MODE)
                    run["fixture_mode"] = mode
                    mode_observed = observed.setdefault("modes", {}).setdefault(
                        mode, {"capabilities": {}, "failed": False, "runs": []})
                    merge_fixture_observation(mode_observed, contributed, failed, run)
                    # Renewal reads one member; it cannot replace the complete
                    # cached-read inventory or its byte-preserved config proof.
                    if mode == FILEFABRIC_RENEWAL_MODE:
                        contributed = {key: value for key, value in contributed.items()
                                       if key in FILEFABRIC_ADDITIONAL_CAPABILITIES}
                merge_fixture_observation(observed, contributed, failed, run)
        except CoverageError as error:
            report["errors"].append(str(error))
    for entry in catalog:
        backend = entry["backend"]
        planned = policy["providers"].get(backend)
        profile = None
        if planned is None:
            policy_status = "missing_plan"
        elif policy["reviewed_runtime_version"] != runtime.get("version"):
            # Matching option schemas cannot establish review of a new runtime.
            policy_status = "unreviewed_runtime"
        elif ("schema_sha256_by_platform" in planned
              and runtime["platform"] not in planned["schema_sha256_by_platform"]):
            policy_status = "unreviewed_platform"
        elif (planned["canonical_name"] != entry["canonical_name"]
              or planned.get("schema_sha256", planned.get("schema_sha256_by_platform", {}).get(runtime["platform"])) != entry["schema_sha256"]):
            policy_status = "stale_schema"
        else:
            profile = policy["profiles"][planned["profile"]]
            policy_status = "review_required" if profile.get("review_required", False) else "current"
        unresolved = sorted(profile.get("unresolved_applicability", [])) if profile else []
        row = dict(entry, catalog_status="discovered", policy_status=policy_status, evidence={}, complete=False,
                   capability_applicability_review_required=unresolved, lifecycle_applicability={})
        for entry_field, _, label in LIFECYCLE_DIMENSIONS.values():
            decision = planned[entry_field] if policy_status == "current" else "not_verified"
            row["lifecycle_applicability"][label] = decision
            report["applicability_summary"][label][decision] += 1
        observed = observations.get(backend)
        for tier in TIERS:
            if policy_status != "current":
                row["evidence"][tier] = {"status": "not_verified", "capabilities": {}}
                continue
            needed = profile["required"].get(tier)
            if needed is None:
                row["evidence"][tier] = {"status": "not_applicable", "capabilities": {}}
                continue
            capabilities = {capability: "not_verified" for capability in needed}
            evidence = {"status": "not_verified", "capabilities": capabilities}
            if tier == "local_protocol" and observed:
                for capability in needed:
                    value = observed["capabilities"].get(capability)
                    if value in ("passed", "failed"):
                        capabilities[capability] = value
                evidence["runs"] = observed["runs"]
                if backend in ("filefabric", "smb", "internetarchive", "pcloud"):
                    evidence["modes"] = {}
                    contracts = ({SMB_MODE: SMB_REQUIRED_CAPABILITIES} if backend == "smb"
                                 else {PCLOUD_SAVED_TOKEN_MODE: PCLOUD_REQUIRED_CAPABILITIES,
                                       PCLOUD_AUTHENTICATION_MODE: {"authentication"}} if backend == "pcloud"
                                 else INTERNETARCHIVE_MODE_CONTRACTS if backend == "internetarchive"
                                 else FILEFABRIC_MODE_CONTRACTS)
                    for mode, contract in contracts.items():
                        mode_observed = observed.get("modes", {}).get(mode, {})
                        mode_capabilities = {key: mode_observed.get("capabilities", {}).get(key, "not_verified")
                                             for key in sorted(contract)}
                        mode_status = ("failed" if mode_observed.get("failed")
                                       else "passed" if all(value == "passed" for value in mode_capabilities.values())
                                       else "not_verified")
                        evidence["modes"][mode] = {"status": mode_status, "capabilities": mode_capabilities,
                                                   "runs": mode_observed.get("runs", [])}
                if observed["failed"] or "failed" in capabilities.values():
                    evidence["status"] = "failed"
                elif all(value == "passed" for value in capabilities.values()):
                    evidence["status"] = "passed"
            row["evidence"][tier] = evidence
        row["complete"] = policy_status == "current" and not unresolved and all(
            evidence["status"] in ("passed", "not_applicable") for evidence in row["evidence"].values()
        )
        report["providers"].append(row)
    report["errors"] = sorted(set(report["errors"]))
    report["all_plans_current"] = bool(catalog) and not report["retired_policy_backends"] and all(row["policy_status"] == "current" for row in report["providers"])
    report["all_complete"] = report["all_plans_current"] and not report["errors"] and all(row["complete"] for row in report["providers"])
    return report


def gate_errors(report, require_plans=False, require_fixtures=(), require_complete=False):
    errors = list(report["errors"])
    if require_plans and not report["all_plans_current"]:
        errors.append("provider_plans_incomplete")
    rows = {row["backend"]: row for row in report["providers"]}
    for backend in require_fixtures:
        if backend not in rows or rows[backend]["evidence"]["local_protocol"]["status"] != "passed":
            errors.append("required_fixture_not_verified")
    if require_complete and not report["all_complete"]:
        errors.append("provider_coverage_incomplete")
    return sorted(set(errors))


def isolated_environment(root):
    # Allow only process-launch essentials, never inherited cloud/SSH/rclone/proxy settings.
    allowed = {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMP", "TEMP", "TMPDIR"):
        environment[key] = str(root)
    return environment


def run_metadata(binary, arguments, config, environment):
    """Bound time and pipe memory, keeping raw diagnostics entirely private."""
    command = [str(binary), "--config", str(config), *arguments]
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    try:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=environment, **options)
    except OSError:
        fail("metadata_start_failed")
    buffers = [bytearray(), bytearray()]
    exceeded = threading.Event()

    def collect(pipe, output, limit):
        try:
            while True:
                chunk = pipe.read(8192)
                if not chunk:
                    return
                if len(output) + len(chunk) > limit:
                    exceeded.set()
                    return
                output.extend(chunk)
        except OSError:
            exceeded.set()
        finally:
            pipe.close()

    workers = [threading.Thread(target=collect, args=(child.stdout, buffers[0], MAX_JSON), daemon=True),
               threading.Thread(target=collect, args=(child.stderr, buffers[1], MAX_RECEIPT), daemon=True)]
    for worker in workers:
        worker.start()
    timed_out = False
    deadline = time.monotonic() + 30
    try:
        while child.poll() is None:
            if exceeded.is_set() or time.monotonic() >= deadline:
                timed_out = not exceeded.is_set()
                child.kill()
                break
            time.sleep(0.02)
        child.wait(timeout=5)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        for worker in workers:
            worker.join(timeout=5)
    if timed_out or exceeded.is_set() or any(worker.is_alive() for worker in workers):
        fail("metadata_bound_exceeded")
    if child.returncode != 0:
        fail("metadata_command_failed")
    return bytes(buffers[0])


def query_runtime(binary, manifest_path):
    temporary = None
    primary_code, diagnostics = None, []
    stage = "runtime_preflight"
    try:
        binary = plain_path(binary)
        if not binary.is_file() or binary.stat().st_size > 512 * 1024 * 1024:
            fail("invalid_runtime_file")
        system = platform_module.system().lower()
        key = {"windows": "RCLONE_EXE_SHA256", "linux": "RCLONE_LINUX_EXE_SHA256"}.get(system)
        if key is None:
            fail("unsupported_runtime_platform")
        stage = "runtime_verification"
        try:
            manifest = {}
            for line in plain_path(manifest_path).read_text(encoding="utf-8").splitlines():
                if not line or line.startswith("#"):
                    continue
                name, separator, value = line.partition("=")
                if not separator or name in manifest:
                    fail("invalid_runtime_manifest")
                manifest[name] = value
            expected, version = manifest.get(key), manifest.get("RCLONE_VERSION")
            if not valid_hash(expected) or not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
                fail("invalid_runtime_manifest")
            with binary.open("rb") as source:
                actual = hashlib.file_digest(source, "sha256").hexdigest()
            if actual != expected:
                fail("runtime_hash_mismatch")
        except CoverageError:
            raise
        except (OSError, ValueError):
            fail("runtime_verification_failed")
        stage = "temporary_create"
        temporary = tempfile.TemporaryDirectory(prefix="triage-catalog-")
        root = Path(temporary.name)
        stage = "temporary_permissions"
        root.chmod(0o700)
        # Run an independently rehashed owned copy, preventing replacement of
        # the supplied executable between verification and the metadata calls.
        executable = root / ("rclone.exe" if system == "windows" else "rclone")
        stage = "runtime_copy"
        shutil.copyfile(binary, executable)
        stage = "runtime_permissions"
        executable.chmod(0o700)
        stage = "runtime_rehash"
        with executable.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != actual:
                fail("runtime_copy_hash_mismatch")
        stage = "config_create"
        config = root / "empty.conf"
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        environment = isolated_environment(root)
        stage = "version_probe"
        reported = run_metadata(executable, ["version"], config, environment)
        if reported.splitlines()[:1] != [f"rclone v{version}".encode("ascii")]:
            fail("runtime_version_mismatch")
        stage = "providers_probe"
        raw = run_metadata(executable, ["config", "providers"], config, environment)
        stage = "catalog_parse"
        try:
            catalog = catalog_from_schemas(json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object))
        except (ValueError, UnicodeError):
            fail("invalid_catalog")
    except CoverageError as error:
        # Do not keep an exception/traceback alive across owned cleanup.
        primary_code = str(error)
    except METADATA_EXCEPTIONS as error:
        diagnostics.append(metadata_diagnostic(stage, error))
    finally:
        if temporary is not None:
            try:
                temporary.cleanup()
            except METADATA_EXCEPTIONS as error:
                diagnostics.append(metadata_diagnostic("temporary_cleanup", error))
    if diagnostics:
        raise MetadataDiagnosticError(primary_code, diagnostics)
    if primary_code is not None:
        raise CoverageError(primary_code)
    return {"version": version, "sha256": actual, "platform": system}, catalog


def write_report(report, destination):
    destination = plain_path(destination, allow_missing_leaf=True)
    data = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        fail("report_already_exists")
    except OSError:
        fail("report_write_failed")


def parse_required(raw):
    if not raw:
        return []
    parts = raw.split(",")
    if any(not ID_PATTERN.fullmatch(part.strip()) for part in parts):
        fail("invalid_required_fixture")
    return sorted(set(part.strip() for part in parts))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rclone", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=ROOT / "rclone-version.env")
    parser.add_argument("--policy", type=Path, default=ROOT / "provider-coverage-policy.json")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--fixture-receipt", action="append", type=Path, default=[])
    parser.add_argument("--max-age-hours", type=int, default=MAX_AGE_HOURS)
    parser.add_argument("--require-plans", action="store_true")
    parser.add_argument("--require-fixtures", default="")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args(argv)
    report = {"schema_version": 1, "all_plans_current": False, "all_complete": False,
              "providers": [], "errors": []}
    try:
        required = parse_required(args.require_fixtures)
        runtime, catalog = query_runtime(args.rclone, args.manifest)
        # Even a malformed/missing policy must leave every discovered backend in
        # the failure receipt; a policy failure cannot erase the coverage gap.
        unreviewed = {"schema_version": 2, "reviewed_runtime_version": runtime["version"],
            "profiles": {"unreviewed": {
            "required": {"application": ["cleanup"]}, "review_required": True}}, "providers": {}}
        summary_diagnostic = None
        try:
            report = evaluate(catalog, unreviewed, runtime, [], None)
        except METADATA_EXCEPTIONS as error:
            summary_diagnostic = metadata_diagnostic("initial_catalog_summary", error)
        if summary_diagnostic is not None:
            raise MetadataDiagnosticError(None, [summary_diagnostic])
        policy = read_json(args.policy)
        harness_sha = compute_harness_sha256(ROOT / "scripts" / "provider-lab") if args.fixture_receipt else None
        fixture_sha = compute_fixture_manifest_sha256(ROOT / "scripts" / "provider-lab") if args.fixture_receipt else None
        receipts, receipt_errors = [], []
        for path in args.fixture_receipt:
            try:
                receipts.append(read_json(path, MAX_RECEIPT))
            except CoverageError as error:
                receipt_errors.append(str(error))
        smb_bindings = (compute_smb_bindings(ROOT / "scripts" / "provider-lab" / "smb")
                        if any(isinstance(receipt, dict) and type(receipt.get("schema_version")) is int
                               and receipt["schema_version"] == 3 for receipt in receipts) else None)
        pcloud_bindings = (compute_pcloud_bindings(ROOT / "scripts" / "provider-lab" / "pcloud-oauth")
                           if any(isinstance(receipt, dict) and type(receipt.get("schema_version")) is int
                                  and receipt["schema_version"] == 5 for receipt in receipts) else None)
        report = evaluate(catalog, policy, runtime, receipts, harness_sha, max_age_hours=args.max_age_hours,
                          fixture_manifest_sha256=fixture_sha, smb_bindings=smb_bindings, pcloud_bindings=pcloud_bindings)
        report["errors"] = sorted(set(report["errors"] + receipt_errors))
        report["all_complete"] = report["all_complete"] and not report["errors"]
        report["gate_errors"] = gate_errors(report, args.require_plans, required, args.require_complete)
    except MetadataDiagnosticError as error:
        report["errors"].extend(error.codes)
        report["gate_errors"] = list(report["errors"])
    except CoverageError as error:
        report["errors"].append(str(error))
        report["gate_errors"] = list(report["errors"])
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        report["errors"].append("coverage_input_failed")
        report["gate_errors"] = list(report["errors"])
    try:
        write_report(report, args.report)
    except (CoverageError, OSError):
        print("Provider coverage report could not be saved.", file=sys.stderr)
        return 2
    passed = not report.get("gate_errors")
    print("Provider coverage report saved; gates " + ("passed." if passed else "failed."))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
