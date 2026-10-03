#!/usr/bin/env python3
"""Propose a stable rclone pin after verifying official archives; never run it.

The default is a dry run. --write atomically updates only the manifest.
--refresh-current verifies an unchanged release and fills missing binary pins.
Transport is HTTPS to downloads.rclone.org with redirects/proxies disabled.
SHA256SUMS is trusted through that transport; its PGP signature is not verified.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile


ORIGIN = "https://downloads.rclone.org"
VERSION_RE = r"(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})"
HASH_RE = r"[a-f0-9]{64}"
KEYS = (
    "RCLONE_VERSION",
    "RCLONE_EXE_SHA256",
    "RCLONE_WINDOWS_ZIP_SHA256",
    "RCLONE_LINUX_ZIP_SHA256",
    "RCLONE_LINUX_EXE_SHA256",
)
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_BINARY = 512 * 1024 * 1024


class UpdateError(Exception):
    """A failed validation that must leave the existing manifest untouched."""


def version_tuple(value):
    if not re.fullmatch(VERSION_RE, value):
        raise UpdateError("Expected a stable numeric release version")
    return tuple(int(part) for part in value.split("."))


def parse_manifest(text):
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key not in KEYS or key in result:
            raise UpdateError("Manifest contains an unknown, malformed or duplicate key")
        if key == "RCLONE_VERSION":
            version_tuple(value)
        elif not re.fullmatch(HASH_RE, value):
            raise UpdateError("Manifest contains an invalid SHA256")
        result[key] = value
    if not set(KEYS[:-1]).issubset(result):
        raise UpdateError("Manifest is missing a required pin")
    return result


def render_manifest(values):
    return (
        f"# Verified against the official rclone v{values['RCLONE_VERSION']} SHA256SUMS release asset.\n"
        + "".join(f"{key}={values[key]}\n" for key in KEYS)
    )


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    allowed_path = rf"/(?:version\.txt|v(?P<version>{VERSION_RE})/(?:SHA256SUMS|rclone-v(?P=version)-(?:windows|linux)-amd64\.zip))"
    if (
        parsed.scheme != "https"
        or parsed.netloc != "downloads.rclone.org"
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(allowed_path, parsed.path)
    ):
        raise UpdateError("Download URL is outside the fixed official release endpoints")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UpdateError("Official release endpoint redirected; refusing a different URL")


def download(url, destination, limit):
    validate_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "triage-rclone-pin-updater/1"})
    deadline = time.monotonic() + 300
    with opener.open(request, timeout=30) as response, destination.open("xb") as output:
        if response.status != 200 or response.geturl() != url:
            raise UpdateError("Unexpected official download response")
        declared = response.headers.get("Content-Length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            raise UpdateError("Official response exceeds the size limit")
        size = 0
        # read(amt) can keep filling its buffer through a slow stream of bytes,
        # postponing our deadline indefinitely. read1 performs at most one
        # underlying read, so the deadline is checked between network reads.
        while chunk := response.read1(1024 * 1024):
            if time.monotonic() > deadline:
                raise UpdateError("Official download exceeded its five-minute deadline")
            size += len(chunk)
            if size > limit:
                raise UpdateError("Official response exceeds the size limit")
            output.write(chunk)
        if declared is not None and size != int(declared):
            raise UpdateError("Official download was truncated")
        if size == 0:
            raise UpdateError("Official download was empty")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_checksums(text, names):
    # Official SHA256SUMS is currently an OpenPGP clear-signed checksum file.
    # Read hashes only from its cleartext, never from signature/armor content.
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        body, separator, _signature = text.partition("-----BEGIN PGP SIGNATURE-----")
        if not separator:
            raise UpdateError("Incomplete clear-signed checksum document")
    else:
        body = text
    found = {}
    for line in body.splitlines():
        match = re.fullmatch(r"([a-fA-F0-9]{64}) [ *]([^\r\n]+)", line)
        if match and match[2] in names:
            if match[2] in found:
                raise UpdateError("Duplicate archive checksum")
            found[match[2]] = match[1].lower()
    if set(found) != set(names):
        raise UpdateError("Official checksums do not identify both exact platform archives")
    return found


def extract_binary_hash(archive, entry_name, destination, magic):
    with zipfile.ZipFile(archive) as source:
        entries = [item for item in source.infolist() if item.filename == entry_name]
        if len(entries) != 1:
            raise UpdateError("Archive must contain exactly one expected executable")
        entry = entries[0]
        mode = entry.external_attr >> 16
        if entry.is_dir() or stat.S_ISLNK(mode) or entry.flag_bits & 1:
            raise UpdateError("Archive executable is not a plain unencrypted file")
        if not 0 < entry.file_size <= MAX_BINARY:
            raise UpdateError("Archive executable has an invalid size")
        digest = hashlib.sha256()
        size = 0
        prefix = b""
        with source.open(entry) as payload, destination.open("xb") as output:
            for chunk in iter(lambda: payload.read(1024 * 1024), b""):
                if not prefix:
                    prefix = chunk[: len(magic)]
                size += len(chunk)
                if size > MAX_BINARY:
                    raise UpdateError("Extracted executable exceeds the size limit")
                digest.update(chunk)
                output.write(chunk)
        if size != entry.file_size or prefix != magic:
            raise UpdateError("Executable size or platform signature is invalid")
    expected = digest.hexdigest()
    if sha256_file(destination) != expected:
        raise UpdateError("Extracted executable read-back hash mismatch")
    return expected


def atomic_write(path, content, original):
    if path.is_symlink() or path.read_bytes() != original:
        raise UpdateError("Manifest changed while verifying the release")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".rclone-pin-", delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        except BaseException:
            output.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
        if path.is_symlink() or path.read_bytes() != original:
            raise UpdateError("Manifest changed before replacement")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def update(manifest_path, write=False, refresh_current=False, fetch=download):
    manifest_path = Path(manifest_path)
    if manifest_path.is_symlink():
        raise UpdateError("Manifest must not be a symlink")
    original = manifest_path.read_bytes()
    current = parse_manifest(original.decode("utf-8"))
    with tempfile.TemporaryDirectory(prefix="triage-rclone-update-") as temporary:
        scratch = Path(temporary)
        latest_path = scratch / "version.txt"
        fetch(f"{ORIGIN}/version.txt", latest_path, 128)
        match = re.fullmatch(rf"rclone v({VERSION_RE})\s*", latest_path.read_text(encoding="utf-8"))
        if not match:
            raise UpdateError("Official latest version is not a stable release")
        latest = match[1]
        if version_tuple(latest) < version_tuple(current["RCLONE_VERSION"]):
            raise UpdateError("Official version is older than the current pin; refusing downgrade")
        result = {"current_version": current["RCLONE_VERSION"], "version": latest, "changed": False, "written": False, "verified": False}
        if latest == current["RCLONE_VERSION"] and not refresh_current:
            return result
        names = {platform: f"rclone-v{latest}-{platform}-amd64.zip" for platform in ("windows", "linux")}
        sums_path = scratch / "SHA256SUMS"
        fetch(f"{ORIGIN}/v{latest}/SHA256SUMS", sums_path, 1024 * 1024)
        checksums = parse_checksums(sums_path.read_text(encoding="utf-8"), names.values())
        values = {"RCLONE_VERSION": latest}
        for platform, name in names.items():
            archive = scratch / name
            fetch(f"{ORIGIN}/v{latest}/{name}", archive, MAX_ARCHIVE)
            archive_hash = sha256_file(archive)
            if archive_hash != checksums[name]:
                raise UpdateError(f"Official {platform} archive SHA256 mismatch")
            binary = "rclone.exe" if platform == "windows" else "rclone"
            binary_hash = extract_binary_hash(archive, f"{name[:-4]}/{binary}", scratch / binary, b"MZ" if platform == "windows" else b"\x7fELF")
            values[f"RCLONE_{platform.upper()}_ZIP_SHA256"] = archive_hash
            values["RCLONE_EXE_SHA256" if platform == "windows" else "RCLONE_LINUX_EXE_SHA256"] = binary_hash
        if latest == current["RCLONE_VERSION"]:
            for key, value in current.items():
                if values[key] != value:
                    raise UpdateError("An existing release pin disagrees with the official archive; refusing replacement")
        rendered = render_manifest(values).encode("utf-8")
        # Preserve harmless existing line endings/comments when all pins match.
        changed = values != current
        if write and changed:
            atomic_write(manifest_path, rendered, original)
        result.update(changed=changed, written=write and changed, verified=True, pins=values)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[1] / "rclone-version.env")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="atomically write a verified newer pin")
    mode.add_argument("--dry-run", action="store_true", help="verify and report without editing (default)")
    parser.add_argument("--refresh-current", action="store_true", help="verify the current release too and fill missing extracted-binary pins")
    args = parser.parse_args(argv)
    try:
        result = update(args.manifest, args.write, args.refresh_current)
    except (UpdateError, OSError, UnicodeError, ValueError, zipfile.BadZipFile, urllib.error.URLError) as error:
        print(f"rclone update refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
