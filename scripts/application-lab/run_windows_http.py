#!/usr/bin/env python3
"""Hosted Windows application acceptance using an owned anonymous HTTP source.

Imports perform no native work. Raw application/bridge diagnostics remain private.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import queue
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
import types
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REMOTE = "Synthetic"
CASE_NAME = "synthetic-case"
CASE_SECONDS = 120
HEADERS = ["path_encoding", "remote", "path", "size", "modified", "is_dir", "hash", "hash_type"]
MODIFIED = "2025-01-02T03:04:05+00:00"
ROWS = (
    ("README-synthetic.txt", 30, "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf"),
    ("large/cancel.bin", 2097152, "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938"),
    ("nested/binary.bin", 256, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"),
    ("nested/spaced name.txt", 20, "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e"),
)


class ProducerError(ValueError):
    pass


def need(value, code):
    if not value:
        raise ProducerError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def plain(path, directory=False, *, allow_hardlinks=False):
    path = Path(path).absolute()
    try:
        for item in (path, *path.parents):
            info = item.lstat()
            need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                 "preservation_failed")
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and (allow_hardlinks or info.st_nlink == 1),
             "preservation_failed")
    except OSError:
        raise ProducerError("preservation_failed") from None
    return info


def identity(path):
    info = plain(path, True)
    return info.st_dev, info.st_ino


def read(path, maximum=8 * 1024 * 1024, *, allow_hardlinks=False):
    before = plain(path, allow_hardlinks=allow_hardlinks)
    need(before.st_size <= maximum, "preservation_failed")
    def common(info):
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
    with Path(path).open("rb") as stream:
        opened = os.fstat(stream.fileno())
        need(common(opened) == common(before), "preservation_failed")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        need(common(after) == common(opened) and after.st_ctime_ns == opened.st_ctime_ns,
             "preservation_failed")
    last = plain(path, allow_hardlinks=allow_hardlinks)
    need(common(last) == common(before) and last.st_ctime_ns == before.st_ctime_ns and
         len(data) == before.st_size, "preservation_failed")
    return data


def strict_json(data, maximum=8 * 1024 * 1024):
    need(type(data) is bytes and len(data) <= maximum, "manifest_invalid")
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, "manifest_invalid")
            out[key] = value
        return out
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ProducerError("manifest_invalid")))
    except (UnicodeError, json.JSONDecodeError):
        raise ProducerError("manifest_invalid") from None


def load(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    data = read(path, 512 * 1024)
    exec(compile(data, str(path), "exec"), module.__dict__)
    module.loaded_source_sha256 = sha(data)
    return module


E = load("application_evidence", ROOT / "scripts/application_evidence.py")
F = load("application_http_fixture", HERE / "fixture_http.py")
SELF_SHA256 = sha(read(Path(__file__), 512 * 1024))


def loaded_sources_preserved():
    need(all(sha(read(module.__file__, 512 * 1024)) == module.loaded_source_sha256 for module in (E, F)),
         "preservation_failed")
    need(sha(read(Path(__file__), 512 * 1024)) == SELF_SHA256, "preservation_failed")


def fixture_manifest():
    """Independent literal byte oracle; no values read from fixture state."""
    return [{"path": path, "size": size, "sha256": digest} for path, size, digest in ROWS]


def payloads():
    value = {"README-synthetic.txt": b"synthetic application fixture\n",
             "nested/spaced name.txt": b"spaces remain exact\n", "nested/binary.bin": bytes(range(256)),
             "large/cancel.bin": bytes(range(256)) * 8192}
    need([{ "path": p, "size": len(value[p]), "sha256": sha(value[p])} for p in sorted(value)] == fixture_manifest(),
         "binding_failed")
    return value


def runtime_pins(path):
    values = {}
    try:
        for line in read(path, 4096).decode("ascii").splitlines():
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            need(separator and key not in values, "binding_failed")
            values[key] = value
    except UnicodeError:
        raise ProducerError("binding_failed") from None
    keys = {"RCLONE_VERSION", "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256",
            "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256"}
    architecture_keys = {"RCLONE_WINDOWS_X86_EXE_SHA256", "RCLONE_WINDOWS_X86_ZIP_SHA256",
                         "RCLONE_WINDOWS_ARM64_EXE_SHA256", "RCLONE_WINDOWS_ARM64_ZIP_SHA256"}
    need(set(values) in (keys, keys | architecture_keys), "binding_failed")
    need(re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", values["RCLONE_VERSION"]), "binding_failed")
    need(all(re.fullmatch(r"[a-f0-9]{64}", values[key]) for key in values if key != "RCLONE_VERSION"), "binding_failed")
    # This producer exercises the x64 application; the additional pins must be
    # valid but must not replace the x64 runtime binding in its receipt.
    return {"version": values["RCLONE_VERSION"], "sha256": values["RCLONE_EXE_SHA256"], "platform": "windows"}


def hosted_guard():
    need(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true" and
         os.environ.get("RUNNER_OS") == "Windows" and
         os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "binding_failed")


def powershell():
    path = Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    # Windows services fixed OS executables through legitimate NTFS hardlinks.
    plain(path, allow_hardlinks=True)
    return str(path)


def hidden():
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = 0
    return {"startupinfo": info, "creationflags": subprocess.CREATE_NO_WINDOW}


PRIVATE_DIRECTORIES = frozenset({"temp", "home", "profile", "appdata", "localappdata", "helper-env", "output",
                                 "helper-env/temp", "helper-env/home", "helper-env/profile", "helper-env/appdata", "helper-env/localappdata",
                                 "helper-env/profile/AppData", "helper-env/profile/AppData/Roaming"})
PRIVATE_FILES = frozenset({"application.exe", "source.conf", "queue.csv", "bridge-stdout.private", "bridge-stderr.private"})
CREATION_STAGES = frozenset({"validation", "bindings", "token", "sid", "descriptor", "parent", "create",
                             "handle", "stream", "identity", "cleanup"})


def private_creation_diagnostic(member, directory, stage):
    # Fixed categories only: no SID, descriptor, exception, path or native error.
    category = ("helper_root" if member == "helper-env" else "helper_private_root" if member in PRIVATE_DIRECTORIES and member.startswith("helper-env/")
                else "application_root" if member in PRIVATE_DIRECTORIES else "bridge_log" if member in {"bridge-stdout.private", "bridge-stderr.private"}
                else "harness_file" if member in PRIVATE_FILES else "unknown")
    need(type(directory) is bool and stage in CREATION_STAGES, "case_setup_failed")
    print("application_creation_diagnostic=" + json.dumps(dict(category=category, stage=stage), sort_keys=True, separators=(",", ":")))


def private_sddl(sid, directory):
    need(type(sid) is str and re.fullmatch(r"S-1-[0-9]+(?:-[0-9]+){1,15}", sid, flags=re.ASCII) and
         len(sid) <= 184 and type(directory) is bool, "case_setup_failed")
    inherit = "OICI" if directory else ""
    return f"O:{sid}D:P(A;{inherit};FA;;;{sid})(A;{inherit};FA;;;SY)"


def _native_private_create(case, path, directory):
    """Hosted-only creation. No token mutation, post-creation ACL repair or reopen-to-write."""
    hosted_guard()
    import ctypes as c
    from ctypes import wintypes as w
    import msvcrt

    kernel = c.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
    security = c.WinDLL("advapi32.dll", use_last_error=True, winmode=0x800)
    class Attributes(c.Structure):
        _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]
    class TokenUser(c.Structure):
        _fields_ = [("sid", c.c_void_p), ("attributes", w.DWORD)]
    class FileInfo(c.Structure):
        _fields_ = [("attributes", w.DWORD), ("creation", w.FILETIME), ("access", w.FILETIME),
                    ("write", w.FILETIME), ("volume", w.DWORD), ("size_high", w.DWORD),
                    ("size_low", w.DWORD), ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]
    def bind(library, name, result, *arguments):
        call = getattr(library, name)
        call.restype, call.argtypes = result, list(arguments)
        return call
    current_process = bind(kernel, "GetCurrentProcess", w.HANDLE)
    close = bind(kernel, "CloseHandle", w.BOOL, w.HANDLE)
    free = bind(kernel, "LocalFree", c.c_void_p, c.c_void_p)
    open_token = bind(security, "OpenProcessToken", w.BOOL, w.HANDLE, w.DWORD, c.POINTER(w.HANDLE))
    token_info = bind(security, "GetTokenInformation", w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD))
    sid_text = bind(security, "ConvertSidToStringSidW", w.BOOL, c.c_void_p, c.POINTER(c.c_void_p))
    descriptor = bind(security, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL,
                      w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.POINTER(w.DWORD))
    mkdir = bind(kernel, "CreateDirectoryW", w.BOOL, w.LPCWSTR, c.POINTER(Attributes))
    create = bind(kernel, "CreateFileW", w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD, c.POINTER(Attributes), w.DWORD, w.DWORD, w.HANDLE)
    information = bind(kernel, "GetFileInformationByHandle", w.BOOL, w.HANDLE, c.POINTER(FileInfo))
    final_path = bind(kernel, "GetFinalPathNameByHandleW", w.DWORD, w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD)
    invalid = c.c_void_p(-1).value
    stage = "token"
    def close_handle(handle):
        nonlocal stage
        if not close(handle):
            stage = "cleanup"
            raise ProducerError("cleanup_failed")
    def free_memory(pointer):
        nonlocal stage
        if free(pointer):
            stage = "cleanup"
            raise ProducerError("cleanup_failed")
    def valid_handle(handle):
        need(handle not in (None, 0, invalid), "case_setup_failed")
        return handle
    def check_handle(handle, expected, is_directory):
        info, name = FileInfo(), c.create_unicode_buffer(32768)
        need(information(handle, c.byref(info)), "case_setup_failed")
        length = final_path(handle, name, len(name), 0)
        need(0 < length < len(name) and same_path(name.value, expected), "preservation_failed")
        need(not info.attributes & 0x400 and bool(info.attributes & 0x10) == is_directory, "preservation_failed")
        if not is_directory:
            need(info.links == 1 and info.size_high == 0 and info.size_low == 0, "preservation_failed")

    stream, fd = None, None
    try:
        with ExitStack() as resources:
            token, count = w.HANDLE(), w.DWORD()
            need(open_token(current_process(), 0x0008, c.byref(token)), "case_setup_failed")  # TOKEN_QUERY only.
            resources.callback(close_handle, token)
            valid_handle(token.value)
            need(not token_info(token, 1, None, 0, c.byref(count)) and 0 < count.value <= 65536, "case_setup_failed")
            buffer = c.create_string_buffer(count.value)
            need(token_info(token, 1, buffer, len(buffer), c.byref(count)) and
                 c.sizeof(TokenUser) <= count.value <= len(buffer), "case_setup_failed")
            user = c.cast(buffer, c.POINTER(TokenUser)).contents
            stage = "sid"
            text_pointer = c.c_void_p()
            need(sid_text(user.sid, c.byref(text_pointer)), "case_setup_failed")
            resources.callback(free_memory, text_pointer)
            need(text_pointer.value, "case_setup_failed")
            sddl = private_sddl(c.wstring_at(text_pointer), directory)
            stage = "descriptor"
            sd, sd_length = c.c_void_p(), w.DWORD()
            need(descriptor(sddl, 1, c.byref(sd), c.byref(sd_length)), "case_setup_failed")
            resources.callback(free_memory, sd)
            need(sd.value and 0 < sd_length.value <= 65536, "case_setup_failed")
            attributes = Attributes(c.sizeof(Attributes), sd, False)
            # Pin the case and immediate parent against rename/deletion while creating.
            stage = "parent"
            for parent in dict.fromkeys((case, path.parent)):
                handle = valid_handle(create(str(parent), 0x80, 3, None, 3, 0x02200000, None))
                resources.callback(close_handle, handle)
                check_handle(handle, parent, True)
            if directory:
                stage = "create"
                need(mkdir(str(path), c.byref(attributes)), "case_setup_failed")
                stage = "handle"
                handle = valid_handle(create(str(path), 0x80, 3, None, 3, 0x02200000, None))
                resources.callback(close_handle, handle)
                check_handle(handle, path, True)
            else:
                stage = "create"
                handle = valid_handle(create(str(path), 0x40000080, 1, c.byref(attributes), 1, 0x00200080, None))
                raw_owner = [handle]
                resources.callback(lambda: close_handle(raw_owner[0]) if raw_owner[0] is not None else None)
                stage = "handle"
                check_handle(handle, path, False)
                stage = "stream"
                fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY | os.O_NOINHERIT)
                need(type(fd) is int and fd >= 0, "case_setup_failed")
                raw_owner[0] = None  # Successful transfer: only the CRT/file stream may close it.
                stream = os.fdopen(fd, "wb", buffering=0)
                fd = None
                need(not os.get_inheritable(stream.fileno()), "preservation_failed")
        return stream
    except BaseException as error:
        try:
            if stream is not None:
                stream.close()
            elif fd is not None and fd >= 0:
                os.close(fd)
        except BaseException:
            stage, error = "cleanup", ProducerError("cleanup_failed")
        failure = error if isinstance(error, ProducerError) else ProducerError("case_setup_failed")
        failure.creation_stage = stage
        raise failure from None


def _private_create(case, member, directory):
    hosted_guard()
    need(type(member) is str and member in (PRIVATE_DIRECTORIES if directory else PRIVATE_FILES), "case_setup_failed")
    case = Path(case).absolute()
    path = case / member
    stage = "validation"
    stream = None
    try:
        original, parent = identity(case), identity(path.parent)
        stage = "bindings"
        stream = _native_private_create(case, path, directory)
        stage = "identity"
        need(identity(case) == original and identity(path.parent) == parent, "preservation_failed")
        if directory:
            need(stream is None, "case_setup_failed")
            plain(path, True)
        else:
            info = plain(path)
            opened = os.fstat(stream.fileno())
            need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and opened.st_size == info.st_size == 0 and
                 (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), "preservation_failed")
        return stream
    except BaseException as error:
        try:
            if stream is not None:
                stream.close()
        except BaseException:
            stage, error = "cleanup", ProducerError("cleanup_failed")
        try:
            private_creation_diagnostic(member, directory, getattr(error, "creation_stage", stage))
        except BaseException:
            pass
        if isinstance(error, ProducerError):
            raise error from None
        raise ProducerError("case_setup_failed") from None


def private_directory(case, member):
    _private_create(case, member, True)


def private_file(case, member):
    return _private_create(case, member, False)


def private_write(case, member, data):
    lease = identity(case)
    with private_file(case, member) as stream:
        opened = os.fstat(stream.fileno())
        need(stream.write(data) == len(data), "case_setup_failed")
        stream.flush()
        os.fsync(stream.fileno())
        last = plain(case / member)
        need(identity(case) == lease and (last.st_dev, last.st_ino, last.st_size) ==
             (opened.st_dev, opened.st_ino, len(data)), "preservation_failed")


def environment(case):
    system = Path(os.environ["SYSTEMROOT"])
    result = {"SYSTEMROOT": str(system), "WINDIR": str(system), "SYSTEMDRIVE": system.drive,
              "COMSPEC": str(system / "System32/cmd.exe"), "PATH": str(system / "System32")}
    for key, name in {"TEMP": "temp", "TMP": "temp", "HOME": "home", "USERPROFILE": "profile",
                      "APPDATA": "appdata", "LOCALAPPDATA": "localappdata"}.items():
        result[key] = str(case / name)
    return result


SETUP_STAGES = {
    "Create": ("input", "parent", "identity", "acl", "compile", "create", "verify", "complete"),
    "Verify": ("input", "parent", "identity", "verify", "complete"),
}
SETUP_OUTCOMES = frozenset({"timeout", "launch_failed", "environment_invalid", "exit_failed", "protocol_failed", "parent_changed"})
SETUP_FAILURE_REASONS = frozenset({"verification_failed", "entry_limit", "metadata_read_failed", "reparse",
                                   "owner_invalid", "root_unprotected", "acl_invalid", "acl_incomplete", "enumeration_failed"})
SETUP_NODE_CATEGORIES = frozenset({"root", "application_root", "helper_root", "helper_private_root",
                                  "helper_descendant", "helper_temp_direct", "helper_temp_deeper",
                                  "helper_home_descendant", "helper_profile_descendant", "helper_appdata_descendant",
                                  "helper_localappdata_descendant", "bridge_log", "other", "unknown",
                                  "application_binary", "source_config", "acquisition_queue", "session_transcript",
                                  "output_root", "case_root", "case_logs", "case_downloads", "case_listings", "case_config",
                                  "listing_inventory", "working_config", "config_provenance"})


def setup_failure(value):
    """Closed failure-only metadata; no child strings outside these enums."""
    owner_keys = ("owner_is_user", "owner_is_token_owner", "token_owner_is_user")
    need(type(value) is dict and set(value) == {"reason", "category", *owner_keys}, "case_setup_failed")
    need(type(value["reason"]) is str and value["reason"] in SETUP_FAILURE_REASONS and
         type(value["category"]) is str and value["category"] in SETUP_NODE_CATEGORIES, "case_setup_failed")
    if value["reason"] == "owner_invalid":
        need(value["owner_is_user"] is False, "case_setup_failed")
        token_values = [value[key] for key in owner_keys[1:]]
        need(all(item is None for item in token_values) or all(type(item) is bool for item in token_values), "case_setup_failed")
        need(not all(item is True for item in token_values), "case_setup_failed")
    else:
        need(all(value[key] is None for key in owner_keys), "case_setup_failed")
    return dict(value)


def setup_progress(data, action):
    """Accept only a complete, ordered finite prefix and an optional final record.

    A timeout can retain a fully written prefix. Partial or foreign bytes make
    the entire stream unusable; none of those bytes are returned or printed.
    """
    need(action in SETUP_STAGES and type(data) is bytes and 0 < len(data) <= 4096 and data.endswith(b"\n"), "case_setup_failed")
    data = data.replace(b"\r\n", b"\n")
    need(b"\r" not in data, "case_setup_failed")
    lines = data[:-1].split(b"\n")
    expected, stages, final, failure = SETUP_STAGES[action], [], None, None
    need(len(lines) <= len(expected) + 1, "case_setup_failed")
    for index, line in enumerate(lines):
        value = strict_json(line, 256)
        need(type(value) is dict and type(value.get("schema_version")) is int and value["schema_version"] == 1, "case_setup_failed")
        if set(value) == {"schema_version", "stage"}:
            need(final is None and len(stages) < len(expected) and value["stage"] == expected[len(stages)], "case_setup_failed")
            stages.append(value["stage"])
        else:
            need(set(value) in ({"schema_version", "ok"}, {"schema_version", "ok", "failure"}) and type(value["ok"]) is bool and
                 index == len(lines) - 1 and stages, "case_setup_failed")
            final = value["ok"]
            if "failure" in value:
                need(final is False and stages[-1] == "verify", "case_setup_failed")
                failure = setup_failure(value["failure"])
    need(stages and (final is not True or tuple(stages) == expected), "case_setup_failed")
    return stages[-1], final, failure


WEBDAV_CASE_NAMES = {name: "webdav-" + name.replace("_", "-") for name in (
    "listing", "acquisition", "mismatch", "missing", "wrong_credentials", "accepted_a",
    "revoked_a", "replacement_b", "permission_denied", "truncated_transfer", "cancellation",
)}
SETUP_SCOPES = frozenset({"suite", "webdav_suite", "webdav_credentials", "webdav_credential_setup", *E.CASE_ORDER,
                          *WEBDAV_CASE_NAMES.values()})


def setup_scope(name):
    need(type(name) is str, "case_setup_failed")
    if re.fullmatch(r"app-http-[a-f0-9]{32}", name):
        return "suite"
    if re.fullmatch(r"app-webdav-[a-f0-9]{32}", name):
        return "webdav_suite"
    if name == "webdav-credentials":
        return "webdav_credentials"
    if name == "webdav-credential-setup":
        return "webdav_credential_setup"
    need(name in E.CASE_ORDER or name in WEBDAV_CASE_NAMES.values(), "case_setup_failed")
    return name


def setup_diagnostic(outcome, action, scope, exit_code, stage, failure=None):
    """The sole public setup diagnostic: finite labels, never child text."""
    need(outcome in SETUP_OUTCOMES and action in SETUP_STAGES and scope in SETUP_SCOPES and
         (exit_code is None or type(exit_code) is int and -(2**31) <= exit_code < 2**32) and
         (stage is None or stage in SETUP_STAGES[action]), "case_setup_failed")
    value = dict(outcome=outcome, action=action, scope=scope, exit_code=exit_code, last_stage=stage)
    if failure is not None:
        need(outcome == "exit_failed" and exit_code not in (None, 0) and stage == "verify", "case_setup_failed")
        value["failure"] = setup_failure(failure)
    print("application_setup_diagnostic=" + E.compact(value).decode("ascii"), flush=True)


def setup_environment():
    """Trusted setup alone shares the hosted job's compiler environment.

    The fixed setup script only compiles its literal helper and creates/verifies
    the owned directory. It never launches the app or forwards this environment.
    The bridge and application retain their separate private case allowlists.
    """
    result = dict(os.environ)
    def existing(name):
        value = result.get(name)
        need(type(value) is str and 0 < len(value) <= 32767 and not value.startswith(("\\\\", "//")),
             "case_setup_failed")
        # Windows normalizes mixed leading separators into UNC/device drives.
        # Reject that grammar before any filesystem metadata lookup.
        need(not PureWindowsPath(value).drive.startswith("\\\\"), "case_setup_failed")
        path = Path(value)
        need(path.is_absolute(), "case_setup_failed")
        plain(path, True)
        return path
    system = existing("SYSTEMROOT")
    profile = existing("USERPROFILE")
    appdata, localappdata = existing("APPDATA"), existing("LOCALAPPDATA")
    need(same_path(str(appdata), profile / "AppData/Roaming") and
         same_path(str(localappdata), profile / "AppData/Local"), "case_setup_failed")
    existing("TEMP")
    existing("TMP")
    plain(system / "System32", True)
    return result


def prepare(parent, name, action="Create"):
    hosted_guard()
    scope = setup_scope(name)
    need(action in SETUP_STAGES, "case_setup_failed")
    parent = Path(parent).absolute()
    original = identity(parent)
    try:
        env = setup_environment()
    except (OSError, ProducerError):
        setup_diagnostic("environment_invalid", action, scope, None, None)
        raise ProducerError("case_setup_failed") from None
    try:
        result = subprocess.run([powershell(), "-NoProfile", "-NonInteractive", "-File",
                                 str(HERE / "prepare_case.ps1"), "-Action", action,
                                 "-Parent", str(parent), "-Name", name],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=20, check=False, env=env, **hidden())
    except subprocess.TimeoutExpired as error:
        try:
            stage, _, _ = setup_progress(error.stdout, action)
        except (ProducerError, TypeError, ValueError):
            stage = None
        setup_diagnostic("timeout", action, scope, None, stage)
        raise ProducerError("case_setup_failed") from None
    except OSError:
        setup_diagnostic("launch_failed", action, scope, None, None)
        raise ProducerError("case_setup_failed") from None
    try:
        stage, final, failure = setup_progress(result.stdout, action)
    except (ProducerError, TypeError, ValueError):
        stage, final, failure = None, None, None
    code = result.returncode
    code = code if type(code) is int and -(2**31) <= code < 2**32 else None
    try:
        parent_unchanged = identity(parent) == original
    except (OSError, ProducerError):
        parent_unchanged = False
    outcome = ("parent_changed" if not parent_unchanged else "protocol_failed" if code is None else
               "exit_failed" if code != 0 else "protocol_failed" if final is not True else None)
    if outcome is not None:
        setup_error = ProducerError("case_setup_failed")
        # Carry only a closed failure-context marker; never child strings.
        setup_error.helper_profile_owner_failure = (action == "Verify" and outcome == "exit_failed" and
            final is False and failure is not None and failure["reason"] == "owner_invalid" and
            failure["category"] == "helper_profile_descendant")
        try:
            setup_diagnostic(outcome, action, scope, code, stage,
                             failure if outcome == "exit_failed" and final is False else None)
        except BaseException:
            pass  # A diagnostic failure cannot replace the setup failure.
        raise setup_error
    return parent / name


def inventory(root):
    root = Path(root)
    original = identity(root)
    pending, found, total = [root], {}, 0
    while pending:
        directory = pending.pop()
        plain(directory, True)
        for path in directory.iterdir():
            info = path.lstat()
            is_dir = stat.S_ISDIR(info.st_mode)
            plain(path, is_dir)
            need(len(found) < 1024, "outputs_invalid")
            total += 0 if is_dir else info.st_size
            need(total <= 512 * 1024 * 1024, "outputs_invalid")
            found[path.relative_to(root).as_posix()] = (is_dir, info.st_size, info.st_dev, info.st_ino)
            if is_dir:
                pending.append(path)
    need(identity(root) == original, "preservation_failed")
    return found


def remove_owned(root, expected_identity):
    need(identity(root) == expected_identity, "cleanup_failed")
    before = inventory(root)
    need(inventory(root) == before and identity(root) == expected_identity, "cleanup_failed")
    shutil.rmtree(root)
    need(not root.exists(), "cleanup_failed")


SESSION_KEYS = frozenset({"schema_version", "action", "ok", "state", "app_exit_code", "runtime_image_observed",
    "runtime_sha256", "runtime_process_count", "ctrl_c_sent", "output_bytes", "output_limit_exceeded", "forced_termination",
    "app_exited", "observed_children_exited", "job_zero_confirmed", "reader_joined", "conpty_closed", "errors"})
SESSION_ERRORS = frozenset("protocol_invalid job_assignment_failed termination_failed deadline_exceeded start_failed "
    "output_limit_exceeded reader_failed job_query_failed process_observation_failed runtime_observation_failed "
    "ctrl_c_refused input_failed input_timeout forced_termination process_cleanup_failed input_cleanup_failed "
    "reader_cleanup_failed console_cleanup_failed console_cleanup_timeout".split())
SESSION_CLEANUP = ("app_exited", "observed_children_exited", "job_zero_confirmed", "reader_joined", "conpty_closed")


def validate_session(value, action):
    need(type(value) is dict and set(value) == SESSION_KEYS, "session_failed")
    need(type(value["schema_version"]) is int and value["schema_version"] == 1 and
         value["action"] == action and value["state"] in {"running", "finished"}, "session_failed")
    for key in ("ok", "runtime_image_observed", "ctrl_c_sent", "output_limit_exceeded", "forced_termination", *SESSION_CLEANUP):
        need(type(value[key]) is bool, "session_failed")
    need(type(value["output_bytes"]) is int and 0 <= value["output_bytes"] <= 8 * 1024 * 1024 + 65536, "session_failed")
    need(value["app_exit_code"] is None or type(value["app_exit_code"]) is int and 0 <= value["app_exit_code"] < 2**32, "session_failed")
    need(value["runtime_sha256"] is None or type(value["runtime_sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}", value["runtime_sha256"]), "session_failed")
    need(value["runtime_process_count"] is None or type(value["runtime_process_count"]) is int and
         0 <= value["runtime_process_count"] <= 64, "session_failed")
    need(not value["runtime_image_observed"] or value["runtime_sha256"] is not None, "session_failed")
    need(not value["app_exited"] or value["app_exit_code"] is not None, "session_failed")
    errors = value["errors"]
    need(type(errors) is list and len(errors) <= 24 and all(type(e) is str and e in SESSION_ERRORS for e in errors)
         and len(set(errors)) == len(errors) and value["ok"] == (not errors), "session_failed")
    return value


def session_failure_diagnostic(value, action):
    """Finite observations only, from a closed helper response; never credit."""
    value = validate_session(value, action)
    need(action in {"start", "poll", "observe_runtime", "ctrl_c", "finish"} and not value["ok"], "session_failed")
    count = value["runtime_process_count"]
    classification = "unavailable" if count is None else "none" if count == 0 else "single" if count == 1 else "multiple"
    payload = E.compact(dict(action=action, errors=value["errors"], forced_termination=value["forced_termination"],
        app_exited=value["app_exited"], runtime_process_count=count, count_classification=classification))
    need(len(payload) <= 4096, "session_failed")
    print("application_session_failure=" + payload.decode("ascii"), flush=True)


def validate_ready(value):
    need(type(value) is dict and set(value) == {"schema_version", "action", "ok", "state"} and
         type(value["schema_version"]) is int and value["schema_version"] == 1 and
         value["action"] == "ready" and value["ok"] is True and value["state"] == "ready", "session_failed")
    return value


def validate_close_ready(value):
    need(type(value) is dict and set(value) == {"schema_version", "action", "ok", "state"} and
         type(value["schema_version"]) is int and value["schema_version"] == 1 and
         value["action"] == "close_ready" and value["ok"] is True and value["state"] == "closed", "session_failed")
    return value


BRIDGE_ACTIONS = frozenset({"invalid", "ready", "close_ready", "start", "poll", "observe_runtime", "ctrl_c", "finish", "close"})
BRIDGE_PHASES = frozenset({"launch", "reader_start", "preflight", "write", "wait", "reply", "cleanup"})
BRIDGE_OUTCOMES = frozenset({"launch_failed", "thread_failed", "rejected", "io_failed", "timeout", "protocol_failed", "cleanup_failed"})


def bridge_stage(data):
    """Only complete, exact ordered stderr prefixes carry diagnostic meaning."""
    if type(data) is not bytes or not data or len(data) > 4096 or not data.endswith(b"\n"):
        return None
    lines = data.replace(b"\r\n", b"\n").splitlines()
    if b"\r" in data.replace(b"\r\n", b"\n"):
        return None
    expected = [b"application_bridge_stage=compile", b"application_bridge_stage=compiled"]
    return ("compile", "compiled")[len(lines) - 1] if 1 <= len(lines) <= 2 and lines == expected[:len(lines)] else None


def session_diagnostic(action, phase, outcome, last_stage=None):
    need(type(action) is str and action in BRIDGE_ACTIONS and type(phase) is str and phase in BRIDGE_PHASES and
         type(outcome) is str and outcome in BRIDGE_OUTCOMES and
         last_stage in {None, "compile", "compiled"}, "session_failed")
    print("application_session_diagnostic=" + E.compact(dict(action=action, phase=phase, outcome=outcome,
          last_stage=last_stage)).decode("ascii"), flush=True)


class Bridge:
    """One owned hidden PS5 process; fixed JSON protocol and bounded pipe readers."""
    script_name = "hosted_session.ps1"
    actions = BRIDGE_ACTIONS

    def validate_session(self, value, action):
        return validate_session(value, action)

    def failure_diagnostic(self, value, action):
        return session_failure_diagnostic(value, action)

    def __init__(self, case):
        need(self.script_name in {"hosted_session.ps1", "hosted_tui_session.ps1"}, "session_failed")
        self.case, self.last = case, None
        self.messages = queue.Queue(maxsize=4)
        self.failed, self.done = threading.Event(), threading.Event()
        self.threads, self.calls, self.forced = [], 0, False
        self.response_lock, self.responses, self.ready = threading.Lock(), 0, False
        self.closed_ready = False
        self.stage_bytes = bytearray()
        self.stage_invalid = False
        self.deadline = time.monotonic() + 165
        env = environment(case / "helper-env")
        env.update(GITHUB_ACTIONS="true", RUNNER_OS="Windows", RUNNER_ENVIRONMENT="github-hosted")
        # PS5.1 writes this optional cache asynchronously after module imports.
        # Disable it only for the helper; keep all residue checks unchanged.
        env["PSModuleAnalysisCachePath"] = "nul"
        # Both new, explicitly owned logs exist before any helper can start.
        # Unbuffered streams have no buffered-writer lock to strand on failure.
        with ExitStack() as logs:
            output = {name: logs.enter_context(private_file(case, "bridge-" + name + ".private"))
                      for name in ("stdout", "stderr")}
            try:
                self.process = subprocess.Popen([powershell(), "-NoProfile", "-NonInteractive", "-File", str(HERE / self.script_name)],
                    cwd=case, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **hidden())
            except BaseException:
                self._diagnostic("invalid", "launch", "launch_failed")
                raise
            try:
                for stream, name in ((self.process.stdout, "stdout"), (self.process.stderr, "stderr")):
                    thread = threading.Thread(target=self._reader, args=(stream, name, output[name]), daemon=True)
                    thread.start()
                    self.threads.append(thread)
                self.watchdog = threading.Thread(target=self._watch, daemon=True)
                self.watchdog.start()
            except BaseException:
                self._diagnostic("invalid", "reader_start", "thread_failed")
                self.forced = True
                self.done.set()
                try:
                    self.process.kill()
                    self.process.wait(timeout=5)
                finally:
                    try:
                        for thread in self.threads:
                            thread.join(2)
                    finally:
                        with ExitStack() as pipes:
                            pipes.callback(self.process.stdin.close)
                            for index, pipe in enumerate((self.process.stdout, self.process.stderr)):
                                if index >= len(self.threads) or not self.threads[index].is_alive():
                                    pipes.callback(pipe.close)
                raise
            logs.pop_all()  # Each started reader now owns exactly its log stream.

    def _reader(self, stream, name, log):
        total, buffer = 0, bytearray()
        try:
            with log:
                while data := stream.read1(4096):
                    total += len(data)
                    if total > 1024 * 1024:
                        self.failed.set()
                        return
                    need(log.write(data) == len(data), "session_failed")
                    if name == "stderr":
                        with self.response_lock:
                            if len(self.stage_bytes) + len(data) > 4096:
                                self.stage_invalid = True
                                self.stage_bytes.clear()
                            elif not self.stage_invalid:
                                self.stage_bytes.extend(data)
                    if name == "stdout":
                        buffer.extend(data)
                        if len(buffer) > 65536:
                            self.failed.set()
                            return
                        while b"\n" in buffer:
                            line, _, tail = buffer.partition(b"\n")
                            buffer = bytearray(tail)
                            with self.response_lock:
                                if self.responses >= self.calls:
                                    self.failed.set()
                                    return
                                self.responses += 1
                            self.messages.put_nowait(bytes(line).rstrip(b"\r"))
                if name == "stdout" and buffer:
                    self.failed.set()
        except Exception:
            self.failed.set()

    def _diagnostic(self, action, phase, outcome):
        try:
            with self.response_lock:
                stage = None if self.stage_invalid else bridge_stage(bytes(self.stage_bytes))
            session_diagnostic(action if type(action) is str and action in BRIDGE_ACTIONS else "invalid", phase, outcome, stage)
        except BaseException:
            pass  # A diagnostic cannot replace the original failure.

    def _watch(self):
        while not self.done.wait(0.05):
            if self.failed.is_set() or time.monotonic() >= self.deadline:
                self.forced = True
                if self.process.poll() is None:
                    self.process.kill()
                return

    def command(self, action, **fields):
        phase = "preflight"
        try:
            need(type(action) is str and action in self.actions - {"invalid", "close"} and not self.closed_ready and
                 not self.failed.is_set() and not self.forced and self.calls < 1024, "session_failed")
            with self.response_lock:
                need(self.messages.empty() and self.responses == self.calls and
                     (not self.ready and self.calls == 0 and not fields if action == "ready" else
                      self.ready and self.calls == 1 and not fields if action == "close_ready" else self.ready), "session_failed")
                self.calls += 1
            payload = E.compact(dict(action=action, **fields)) + b"\n"
            need(len(payload) <= 16384 and self.process.poll() is None, "session_failed")
            phase = "write"
            self.process.stdin.write(payload)
            self.process.stdin.flush()
            phase = "wait"
            # The first reply includes cold helper compilation. It consumes the
            # existing lifetime budget; later commands keep their shorter cap.
            response_seconds = 60 if action == "ready" else 35
            data = self.messages.get(timeout=max(0.01, min(response_seconds, self.deadline - time.monotonic())))
            phase = "reply"
            need(not self.failed.is_set(), "session_failed")
            value = strict_json(data, 65536)
            self.last = (validate_ready(value) if action == "ready" else validate_close_ready(value)
                         if action == "close_ready" else self.validate_session(value, action))
            if not self.last["ok"]:
                try:
                    self.failure_diagnostic(self.last, action)
                except BaseException:
                    pass  # Diagnostics cannot mask the helper's original failure.
            if action == "ready":
                self.ready = True
            if action == "close_ready":
                self.closed_ready = True
            return self.last
        except (OSError, queue.Empty, ProducerError) as error:
            self.failed.set()
            outcome = ("timeout" if isinstance(error, queue.Empty) else "io_failed" if isinstance(error, OSError)
                       else "protocol_failed" if phase == "reply" else "rejected")
            self._diagnostic(action, phase, outcome)
            raise ProducerError("session_failed") from None

    def close(self):
        try:
            if self.process.poll() is None and (self.last is None or self.last["state"] not in {"finished", "closed"}):
                try:
                    self.command("finish", grace_ms=0)
                except Exception:
                    self.forced = True
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.forced = True
                self.process.kill()
                self.process.wait(timeout=5)
        except BaseException:
            self._diagnostic("close", "cleanup", "cleanup_failed")
            raise
        finally:
            self.done.set()
            self.watchdog.join(1)
            for thread in self.threads:
                thread.join(2)
            # A blocked BufferedReader owns its lock. Closing it from this thread
            # could block past every deadline; retain uncertain handles instead.
            for thread, stream in zip(self.threads, (self.process.stdout, self.process.stderr)):
                if not thread.is_alive():
                    stream.close()
        clean = (self.process.returncode == 0 and not self.forced and not self.failed.is_set() and
                 self.messages.empty() and not self.watchdog.is_alive() and all(not t.is_alive() for t in self.threads))
        if not clean:
            self._diagnostic("close", "cleanup", "cleanup_failed")
        return clean


def queue_rows(name):
    if name == "acquisition":
        return list(ROWS)
    if name == "missing":
        return [("missing-synthetic.txt", 1, "0" * 64)]
    if name == "cancellation":
        return [ROWS[1]]
    path, size, digest = ROWS[0]
    return [(path, size, "0" * 64 if name == "mismatch" else digest)]


def queue_bytes(name):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(HEADERS)
    for path, size, digest in queue_rows(name):
        writer.writerow(["excel-safe-v1", REMOTE, path, size, MODIFIED, "false", digest, "sha256"])
    return b"\xef\xbb\xbf" + stream.getvalue().encode("utf-8")


def app_args(name, case):
    args = ["--name", CASE_NAME, "--output-dir", str(case / "output"),
            "--rclone-config-path", str(case / "source.conf")]
    return args + (["--list-remote", REMOTE] if name == "listing" else
                   ["--download", str(case / "queue.csv"), "--remote", REMOTE])


def runtime_process_limit(name):
    need(name in E.CASE_CHECKS, "session_failed")
    return 1 if name == "listing" else min(4, len(queue_rows(name)))


def same_path(value, expected):
    return type(value) is str and os.path.normcase(os.path.abspath(value.removeprefix("\\\\?\\"))) == os.path.normcase(str(expected.absolute()))


def configuration_preserved(case, expected):
    need(read(case / "source.conf", 8192) == expected, "preservation_failed")
    config = case / "output" / CASE_NAME / "config"
    entries = inventory(config)
    working = [key for key, value in entries.items() if not value[0] and re.fullmatch(r"working-[A-Za-z0-9_-]+\.conf", key)]
    need(len(working) == 1, "preservation_failed")
    path = config / working[0]
    provenance_path = path.with_suffix(".provenance.json")
    need(set(entries) == {path.name, provenance_path.name} and read(path, 8192) == expected, "preservation_failed")
    provenance = strict_json(read(provenance_path, 8192))
    need(set(provenance) == {"schema_version", "source_path", "source_sha256", "working_path", "snapshotted_at"} and
         type(provenance["schema_version"]) is int and provenance["schema_version"] == 1 and
         provenance["source_sha256"] == sha(expected) and same_path(provenance["source_path"], case / "source.conf") and
         same_path(provenance["working_path"], path) and valid_time(provenance["snapshotted_at"]), "preservation_failed")
    return path


def valid_time(value):
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)", value):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def check_listing(case):
    path = case / "output" / CASE_NAME / "listings" / "inventory.csv"
    data = read(path, 65536)
    need(data.startswith(b"\xef\xbb\xbf"), "listing_invalid")
    try:
        rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True))
    except (UnicodeError, csv.Error):
        raise ProducerError("listing_invalid") from None
    expected = [["excel-safe-v1", REMOTE, path, str(size), MODIFIED, "false", "", ""] for path, size, _ in ROWS]
    # rclone v1.75.1 fs.Dir.ModTime uses fs.ConfigOptionsInfo default_time for
    # HTTP directories with an unknown time; Rust exports that UTC instant.
    expected += [["excel-safe-v1", REMOTE, path, "", "2000-01-01T00:00:00+00:00", "true", "", ""] for path in ("large", "nested")]
    need(rows and rows[0] == HEADERS and sorted(rows[1:]) == sorted(expected), "listing_invalid")
    need(inventory(path.parent).keys() == {"inventory.csv"}, "listing_invalid")
    need(not inventory(case / "output" / CASE_NAME / "downloads"), "outputs_invalid")
    return {"inventory_exact": True, "listing_complete": True}


CLEANUP_STAGES = frozenset({"case_identity", "configuration", "application_bytes", "queue_bytes",
                            "private_inventory", "acl_verify", "owned_removal"})
PRIVATE_LOCATIONS = ("temp", "home", "profile", "appdata", "localappdata")
PRESTART_STAGES = frozenset({"helper_identity", "helper_inventory", "helper_limit", "helper_directories", "helper_layout",
                             "private_identity", "private_inventory", "private_empty"})


def create_private_roots(case):
    leases = {"application": {}, "helper": {}}
    for name in PRIVATE_LOCATIONS:
        private_directory(case, name)
        leases["application"][name] = identity(case / name)
    helper = case / "helper-env"
    private_directory(case, "helper-env")
    leases["helper_root"] = identity(helper)
    for name in PRIVATE_LOCATIONS:
        private_directory(case, "helper-env/" + name)
        leases["helper"][name] = identity(helper / name)
    # Exactly the observed helper profile support paths; create with explicit
    # ownership before the helper starts, and retain them as fixed leases.
    for name in ("profile/AppData", "profile/AppData/Roaming"):
        private_directory(case, "helper-env/" + name)
        leases["helper"][name] = identity(helper / name)
    return leases


def inventory_summary(entries):
    directories = sum(value[0] for value in entries.values())
    return dict(entries=len(entries), directories=directories, files=len(entries) - directories,
                total_bytes=sum(value[1] for value in entries.values() if not value[0]))


def diagnostic_counts(summary):
    counts = dict(entries=None, directories=None, files=None, total_bytes=None)
    if summary is not None:
        need(type(summary) is dict and set(summary) == set(counts), "cleanup_failed")
        need(all(type(summary[key]) is int and 0 <= summary[key] <= 1024 for key in ("entries", "directories", "files")) and
             summary["entries"] == summary["directories"] + summary["files"] and
             type(summary["total_bytes"]) is int and 0 <= summary["total_bytes"] <= 512 * 1024 * 1024,
             "cleanup_failed")
        counts = summary
    return counts


def helper_baseline(case, leases, *, observation=None):
    """Helper-only directories observed before any application may start."""
    def observe(stage, summary=None):
        if observation is not None:
            observation.update(stage=stage, location="helper_env", summary=summary)
    def preserved():
        need(identity(root) == leases["helper_root"] and
             all(identity(root / name) == value for name, value in leases["helper"].items()), "cleanup_failed")
    root = case / "helper-env"
    observe("helper_identity")
    preserved()
    observe("helper_inventory")
    entries = inventory(root)
    observe("helper_identity")
    preserved()
    summary = inventory_summary(entries)
    observe("helper_limit", summary)
    need(len(entries) <= 32, "cleanup_failed")
    observe("helper_directories", summary)
    need(all(value[0] for value in entries.values()), "cleanup_failed")
    observe("helper_layout", summary)
    need(set(PRIVATE_LOCATIONS).issubset(entries) and
         all(path.split("/", 1)[0] in PRIVATE_LOCATIONS for path in entries), "cleanup_failed")
    return {path: (value[2], value[3]) for path, value in entries.items()}


def application_roots_empty(case, leases, *, observation=None):
    for name in PRIVATE_LOCATIONS:
        if observation is not None:
            observation.update(stage="private_identity", location=name, summary=None)
        need(identity(case / name) == leases["application"][name], "cleanup_failed")
        if observation is not None:
            observation.update(stage="private_inventory", summary=None)
        entries = inventory(case / name)
        if observation is not None:
            observation.update(stage="private_identity", summary=None)
        need(identity(case / name) == leases["application"][name], "cleanup_failed")
        if observation is not None:
            observation.update(stage="private_empty", summary=inventory_summary(entries))
        need(not entries, "cleanup_failed")


def helper_cleanup_preserved(current, baseline):
    # Root/fixed-directory identities were just checked by helper_baseline. Only
    # already-observed descendant directories may disappear during shutdown.
    need(baseline is not None and set(current).issubset(baseline) and
         all(baseline[path] == value for path, value in current.items()), "cleanup_failed")


def prestart_diagnostic(name, stage, location, summary=None):
    """Only fixed stages and validated counts; names and identities remain private."""
    need(name in E.CASE_ORDER and stage in PRESTART_STAGES and
         (location == "helper_env" if stage.startswith("helper_") else location in PRIVATE_LOCATIONS), "cleanup_failed")
    need(summary is None or stage in {"helper_limit", "helper_directories", "helper_layout", "private_empty"}, "cleanup_failed")
    print("application_prestart_diagnostic=" + E.compact(dict(scope=name, stage=stage, location=location,
          **diagnostic_counts(summary))).decode("ascii"), flush=True)


def prestart_baseline(name, case, leases):
    observation = dict(stage="private_identity", location="temp", summary=None)
    try:
        application_roots_empty(case, leases, observation=observation)
        return helper_baseline(case, leases, observation=observation)
    except BaseException:
        # Diagnostic output must never replace the original failure.
        try:
            prestart_diagnostic(name, **observation)
        except BaseException:
            pass
        raise


POST_HELPER_STAGES = PRESTART_STAGES | {"helper_comparison", "case_inventory", "case_layout", "case_file_limit"}
HELPER_COMPARISON_FIELDS = frozenset({"new_entries", "removed_entries", "replaced_entries"})
CASE_ALLOWLIST_FIELDS = frozenset({"unexpected_directories", "missing_directories", "unexpected_files", "missing_files"})


def bounded_diagnostic_fields(value, fields, limit):
    if value is not None:
        need(type(value) is dict and set(value) == fields and
             all(type(count) is int and 0 <= count <= limit for count in value.values()), "cleanup_failed")
    return value


def post_helper_diagnostic(name, stage, location, summary=None, comparison=None, allowlist=None):
    need(all(type(value) is str for value in (name, stage, location)) and
         name in E.CASE_ORDER and stage in POST_HELPER_STAGES and
         (location == "helper_env" if stage.startswith("helper_") else location == "case_root"
          if stage.startswith("case_") else location in PRIVATE_LOCATIONS), "cleanup_failed")
    need(summary is None or stage in {"private_empty", "helper_limit", "helper_directories", "helper_layout",
         "helper_comparison", "case_layout", "case_file_limit"}, "cleanup_failed")
    need(comparison is None or stage == "helper_comparison", "cleanup_failed")
    need(allowlist is None or stage == "case_layout", "cleanup_failed")
    value = dict(scope=name, stage=stage, location=location, **diagnostic_counts(summary),
        comparison=bounded_diagnostic_fields(comparison, HELPER_COMPARISON_FIELDS, 32),
        allowlist=bounded_diagnostic_fields(allowlist, CASE_ALLOWLIST_FIELDS, 1024))
    print("application_post_helper_diagnostic=" + E.compact(value).decode("ascii"), flush=True)


# Windows KNOWNFOLDERID defaults and documented PowerShell profile/cache parents.
# These names classify observations only; they are never creation/cleanup rules.
PROFILE_NODE_LABELS = {
    "appdata": "appdata",
    "appdata/local": "local_appdata",
    "appdata/locallow": "low_appdata",
    "appdata/roaming": "roaming_appdata",
    "documents": "documents",
    "documents/windowspowershell": "powershell_documents",
    "documents/windowspowershell/modules": "powershell_modules",
    "appdata/local/microsoft": "local_microsoft",
    "appdata/local/microsoft/windows": "local_windows",
    "appdata/local/microsoft/windows/powershell": "local_powershell",
    "appdata/roaming/microsoft": "roaming_microsoft",
    "appdata/roaming/microsoft/windows": "roaming_windows",
    "appdata/roaming/microsoft/windows/powershell": "roaming_powershell",
}


def helper_profile_layout(entries):
    """Reduce an already-safe private inventory to closed labels/counts only."""
    need(type(entries) is dict and len(entries) <= 32 and all(type(path) is str and
         type(value) is tuple and len(value) == 4 and type(value[0]) is bool and
         all(type(part) is int and part >= 0 for part in value[1:]) for path, value in entries.items()), "cleanup_failed")
    need(len({path.casefold() for path in entries}) == len(entries), "cleanup_failed")
    known, unknown_directories, unknown_files = [], 0, 0
    for path, value in entries.items():
        label = PROFILE_NODE_LABELS.get(path.lower()) if path.isascii() else None
        if not value[0]:
            unknown_files += 1
        elif label is None:
            unknown_directories += 1
        else:
            known.append(label)
    return dict(known_nodes=sorted(known), unknown_directory_count=unknown_directories, unknown_file_count=unknown_files)


def helper_profile_failure_diagnostic(name, case, case_id, leases, error):
    """Best-effort observation after the specific failed ACL check; never credit."""
    try:
        if not (isinstance(error, ProducerError) and str(error) == "case_setup_failed" and
                getattr(error, "helper_profile_owner_failure", None) is True):
            return
        need(name in E.CASE_ORDER, "cleanup_failed")
        helper, profile = case / "helper-env", case / "helper-env/profile"
        def preserved():
            need(identity(case) == case_id and identity(helper) == leases["helper_root"] and
                 identity(profile) == leases["helper"]["profile"], "cleanup_failed")
        preserved()
        entries = inventory(profile)
        preserved()
        value = dict(scope=name, **helper_profile_layout(entries))
        need(inventory(profile) == entries, "cleanup_failed")
        preserved()
        rendered = "application_helper_profile_diagnostic=" + E.compact(value).decode("ascii")
        need(len(rendered.encode("ascii")) + 1 <= 4096, "cleanup_failed")
        print(rendered, flush=True)
    except BaseException:
        pass  # Uncertain metadata/output cannot replace or soften the failure.


def post_helper_preserved(name, case, leases, baseline, *, probe=False):
    """Keep the existing cleanup predicates; expose only failed finite observations."""
    observation = dict(stage="private_identity", location="temp", summary=None, comparison=None, allowlist=None)
    try:
        application_roots_empty(case, leases, observation=observation)
        current = helper_baseline(case, leases, observation=observation)
        observation.update(stage="helper_comparison", summary=dict(entries=len(current), directories=len(current), files=0, total_bytes=0))
        # Unknown/malformed private state cannot yield invented difference counts.
        if type(baseline) is dict and len(baseline) <= 32 and all(type(path) is str and type(value) is tuple and
                len(value) == 2 and all(type(part) is int and part >= 0 for part in value) for path, value in baseline.items()):
            observation["comparison"] = dict(new_entries=len(set(current) - set(baseline)),
                removed_entries=len(set(baseline) - set(current)),
                replaced_entries=sum(current[path] != baseline[path] for path in set(current) & set(baseline)))
        helper_cleanup_preserved(current, baseline)
        if not probe:
            return None
        observation.update(stage="case_inventory", location="case_root", summary=None, comparison=None)
        entries = inventory(case)
        expected_dirs = set(PRIVATE_LOCATIONS) | {"helper-env"} | {"helper-env/" + path for path in current}
        expected_files = {"bridge-stdout.private", "bridge-stderr.private"}
        directories = {path for path, value in entries.items() if value[0]}
        files = {path for path, value in entries.items() if not value[0]}
        observation.update(stage="case_layout", summary=inventory_summary(entries), allowlist=dict(
            unexpected_directories=len(directories - expected_dirs), missing_directories=len(expected_dirs - directories),
            unexpected_files=len(files - expected_files), missing_files=len(expected_files - files)))
        need(directories == expected_dirs and files == expected_files, "cleanup_failed")
        observation.update(stage="case_file_limit", allowlist=None)
        need(all(value[1] <= 1024 * 1024 for value in entries.values() if not value[0]), "cleanup_failed")
        return entries
    except BaseException:
        try:
            post_helper_diagnostic(name, **observation)
        except BaseException:
            pass
        if observation["stage"] == "case_layout":
            try:
                case_layout_diagnostic(name, directories, files, expected_dirs, expected_files)
            except BaseException:
                pass
        raise


def case_layout_diagnostic(name, directories, files, expected_dirs, expected_files):
    """Recognize only an exact path layout, never its contents or creating process."""
    need(type(name) is str and name in E.CASE_ORDER, "cleanup_failed")
    cache_dirs = {"Microsoft", "Microsoft/Windows", "Microsoft/Windows/PowerShell"}
    cache_files = {"Microsoft/Windows/PowerShell/ModuleAnalysisCache"}
    known = (expected_dirs.issubset(directories) and expected_files.issubset(files) and
             directories - expected_dirs == cache_dirs and files - expected_files == cache_files)
    label = "powershell_module_cache_path_layout" if known else "unknown"
    print("application_case_layout_diagnostic=" + E.compact(dict(scope=name, classification=label)).decode("ascii"), flush=True)


def cleanup_diagnostic(name, stage, location=None, summary=None):
    """Failure-only counts from an already bounded, link-checked inventory."""
    need(name in E.CASE_ORDER and stage in CLEANUP_STAGES and
         (location in (*PRIVATE_LOCATIONS, "helper_env") if stage == "private_inventory" else location is None),
         "cleanup_failed")
    need(summary is None or stage == "private_inventory", "cleanup_failed")
    counts = diagnostic_counts(summary)
    print("application_cleanup_diagnostic=" + E.compact(dict(scope=name, stage=stage, location=location, **counts)).decode("ascii"), flush=True)


RUNTIME_CLEANUP_PREFIX = b"runtime_cleanup_diagnostic="
RUNTIME_CLEANUP_STAGES = frozenset({"target", "open_root", "identity", "security", "remove_tree"})
RUNTIME_CLEANUP_KINDS = frozenset({"not_found", "permission_denied", "already_exists", "invalid_input",
                                  "unsupported", "interrupted", "other"})


def runtime_cleanup_value(value):
    need(type(value) is dict and list(value) == ["stage", "kind", "os_code"], "cleanup_failed")
    need(type(value["stage"]) is str and value["stage"] in RUNTIME_CLEANUP_STAGES and
         type(value["kind"]) is str and value["kind"] in RUNTIME_CLEANUP_KINDS, "cleanup_failed")
    need(value["os_code"] is None or type(value["os_code"]) is int and 0 <= value["os_code"] <= 65535,
         "cleanup_failed")
    return value


def parse_runtime_cleanup_diagnostic(data):
    """Extract one intact finite record; terminal decoration is discarded, never normalized."""
    try:
        need(type(data) is bytes and len(data) <= 8 * 1024 * 1024, "cleanup_failed")
        marker = b"runtime_cleanup_diagnostic"
        need(data.count(marker) == 1, "cleanup_failed")
        lines = data.split(b"\n")
        index = next(i for i, line in enumerate(lines) if marker in line)
        need(index < len(lines) - 1, "cleanup_failed")
        line = lines[index]
        if line.endswith(b"\r"):
            line = line[:-1]  # Only the exact LF/CRLF record ending is supported.
        need(len(line) <= 4096, "cleanup_failed")
        start = line.index(RUNTIME_CLEANUP_PREFIX)
        record = line[start:line.index(b"}", start) + 1]
        need(len(record) <= 112 and all(32 <= item <= 126 for item in record), "cleanup_failed")
        value = runtime_cleanup_value(strict_json(record[len(RUNTIME_CLEANUP_PREFIX):], 112))
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        need(record == RUNTIME_CLEANUP_PREFIX + encoded, "cleanup_failed")
        return value
    except (ProducerError, TypeError, ValueError, StopIteration):
        return None


def read_runtime_cleanup_diagnostic(case, lease):
    try:
        need(lease is not None and identity(case) == lease, "cleanup_failed")
        data = read(case / "transcript.private", 8 * 1024 * 1024)
        need(identity(case) == lease, "cleanup_failed")
        return parse_runtime_cleanup_diagnostic(data)
    except BaseException:
        return None  # Diagnostics cannot replace the original failure or permit removal.


def runtime_cleanup_diagnostic(name, value):
    need(type(name) is str and name in E.CASE_CHECKS, "cleanup_failed")
    value = runtime_cleanup_value(value)
    print("application_runtime_cleanup_diagnostic=" + E.compact(dict(scope=name, **value)).decode("ascii"), flush=True)


RUNTIME_RESIDUE_PREFIX = b"runtime_cleanup_residue="
RUNTIME_RESIDUE_COUNTS = ("other_files", "other_directories", "other_reparse_points", "other_entries")


def runtime_residue_value(value):
    """Closed observation only; never identifies a holder or authorizes removal."""
    need(type(value) is dict and list(value) == ["root", "executable", *RUNTIME_RESIDUE_COUNTS, "complete"],
         "cleanup_failed")
    need(type(value["complete"]) is bool, "cleanup_failed")
    if not value["complete"]:
        need(value["root"] == "unavailable" and value["executable"] == "unavailable" and
             all(value[key] is None for key in RUNTIME_RESIDUE_COUNTS), "cleanup_failed")
    else:
        need(value["root"] == "same_private_directory" and type(value["executable"]) is str and
             value["executable"] in {"absent", "regular_file", "directory", "reparse_point", "other"},
             "cleanup_failed")
        need(all(type(value[key]) is int and 0 <= value[key] <= 8 for key in RUNTIME_RESIDUE_COUNTS) and
             sum(value[key] for key in RUNTIME_RESIDUE_COUNTS) + int(value["executable"] != "absent") <= 8,
             "cleanup_failed")
    return value


def parse_runtime_cleanup_residue(data):
    """Accept only the intact adjacent pair emitted by the failed cleanup path."""
    try:
        diagnostic = parse_runtime_cleanup_diagnostic(data)
        need(diagnostic is not None and diagnostic["stage"] == "remove_tree", "cleanup_failed")
        marker = b"runtime_cleanup_residue"
        need(data.count(marker) == 1, "cleanup_failed")
        lines = data.split(b"\n")
        index = next(i for i, line in enumerate(lines) if marker in line)
        need(0 < index < len(lines) - 1 and RUNTIME_CLEANUP_PREFIX in lines[index - 1], "cleanup_failed")
        line = lines[index]
        if line.endswith(b"\r"):
            line = line[:-1]
        need(len(line) <= 4096, "cleanup_failed")
        start = line.index(RUNTIME_RESIDUE_PREFIX)
        record = line[start:line.index(b"}", start) + 1]
        need(len(record) <= 320 and all(32 <= item <= 126 for item in record), "cleanup_failed")
        value = runtime_residue_value(strict_json(record[len(RUNTIME_RESIDUE_PREFIX):], 320))
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        need(record == RUNTIME_RESIDUE_PREFIX + encoded, "cleanup_failed")
        return value
    except (ProducerError, TypeError, ValueError, StopIteration):
        return None


def read_runtime_cleanup_residue(case, lease, diagnostic):
    try:
        diagnostic = runtime_cleanup_value(diagnostic)
        need(lease is not None and identity(case) == lease, "cleanup_failed")
        data = read(case / "transcript.private", 8 * 1024 * 1024)
        need(identity(case) == lease, "cleanup_failed")
        # Both forwarded values must occur together in this same snapshot.
        need(parse_runtime_cleanup_diagnostic(data) == diagnostic, "cleanup_failed")
        return parse_runtime_cleanup_residue(data)
    except BaseException:
        return None


def runtime_cleanup_residue(name, value):
    need(type(name) is str and name in E.CASE_CHECKS, "cleanup_failed")
    value = runtime_residue_value(value)
    print("application_runtime_cleanup_residue=" + E.compact(dict(scope=name, **value)).decode("ascii"), flush=True)


def output_files(root):
    entries = inventory(root)
    need(not any(any(part.startswith(".triage-transfer-") for part in path.split("/")) for path in entries), "outputs_invalid")
    return {path: value for path, value in entries.items() if not value[0]}


def application_inventory(name, case, manifest_name=None):
    """Close the entire case output tree, including support artifacts and dirs."""
    base = case / "output" / CASE_NAME
    entries = inventory(base)
    files = {p for p, value in entries.items() if not value[0]}
    configs = {p for p in files if p.startswith("config/")}
    need(len(configs) == 2, "outputs_invalid")
    allowed = set(configs)
    if name == "listing":
        allowed.add("listings/inventory.csv")
    else:
        stem = manifest_name.removesuffix(".json")
        allowed.update({manifest_name, stem + ".txt", "logs/" + stem + ".log", "logs/" + stem + ".checkpoint.json"})
        if name in {"acquisition", "mismatch"}:
            allowed.update("downloads/" + REMOTE + "/" + p for p, _, _ in queue_rows(name))
    need(files == allowed, "outputs_invalid")
    required_dirs = {"logs", "downloads", "listings", "config"}
    permitted_dirs = set(required_dirs)
    # Failure paths can stop before creating their planned destination parent.
    for path, _, _ in ([] if name == "listing" else queue_rows(name)):
        parts = ("downloads/" + REMOTE + "/" + path).split("/")
        permitted_dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
    dirs = {p for p, value in entries.items() if value[0]}
    need(required_dirs <= dirs <= permitted_dirs, "outputs_invalid")
    need(set(inventory(case / "output")) == {CASE_NAME} | {CASE_NAME + "/" + p for p in entries}, "outputs_invalid")
    return True


def check_manifest(name, case, config, runtime):
    base = case / "output" / CASE_NAME
    entries = inventory(base)
    manifests = [p for p, value in entries.items() if "/" not in p and not value[0] and re.fullmatch(r"acquisition-[0-9T.]+\.json", p)]
    need(len(manifests) == 1, "manifest_invalid")
    manifest = strict_json(read(base / manifests[0]))
    need(type(manifest) is dict and set(manifest) == {"schema_version", "written_at", "rclone_version", "config_path", "plan", "results", "complete"}
         and type(manifest["schema_version"]) is int and manifest["schema_version"] == 1 and
         manifest["rclone_version"] == runtime["version"] and valid_time(manifest["written_at"]) and
         same_path(manifest["config_path"], config) and type(manifest["complete"]) is bool, "manifest_invalid")
    plan, results, rows = manifest["plan"], manifest["results"], queue_rows(name)
    need(type(plan) is dict and set(plan) == {"files", "skipped_directories"} and
         type(plan["skipped_directories"]) is int and plan["skipped_directories"] == 0 and
         type(plan["files"]) is list and type(results) is list and len(plan["files"]) == len(rows) == len(results), "manifest_invalid")
    output = base / "downloads"
    for planned, result, (path, size, digest) in zip(plan["files"], results, rows):
        destination = output / REMOTE / path
        need(type(planned) is dict and set(planned) == {"remote_name", "path", "request"} and
             planned["remote_name"] == REMOTE and planned["path"] == path, "manifest_invalid")
        request = planned["request"]
        need(type(request) is dict and set(request) == {"source", "destination", "mode", "expected_hash", "expected_hash_type", "expected_size"}
             and request["source"] == REMOTE + ":" + path and same_path(request["destination"], destination) and
             request["mode"] == "CopyTo" and request["expected_hash"] == digest and request["expected_hash_type"] == "sha256" and
             type(request["expected_size"]) is int and request["expected_size"] == size, "manifest_invalid")
        keys = {"local_sha256", "integrity", "source", "destination", "success", "error", "size", "hash", "hash_type", "hash_verified", "hash_error"}
        need(type(result) is dict and set(result) == keys and type(result["success"]) is bool and
             result["source"] == REMOTE + ":" + path and same_path(result["destination"], destination), "manifest_invalid")
        if name in {"acquisition", "mismatch"}:
            actual = next(row[2] for row in ROWS if row[0] == path)
            expected = dict(local_sha256=actual, integrity="Verified" if name == "acquisition" else "Mismatch",
                source=REMOTE + ":" + path, destination=result["destination"], success=name == "acquisition",
                error=None if name == "acquisition" else "Downloaded bytes do not match the expected source hash",
                size=size, hash=actual, hash_type="sha256", hash_verified=name == "acquisition", hash_error=None)
            need(result == expected and type(result["size"]) is int and type(result["hash_verified"]) is bool, "manifest_invalid")
            need(len(read(destination)) == size and sha(read(destination)) == actual, "outputs_invalid")
        else:
            need(not result["success"] and result["integrity"] == ("Cancelled" if name == "cancellation" else "Failed") and
                 all(result[key] is None for key in ("local_sha256", "size", "hash", "hash_type", "hash_verified", "hash_error")) and
                 type(result["error"]) is str and 0 < len(result["error"]) <= 65536, "manifest_invalid")
            if name == "missing":
                need(result["error"] == "Source was not found or is not an individual file: Synthetic:missing-synthetic.txt", "manifest_invalid")
            if name == "denial":
                need(result["error"].startswith("Cannot stat source: ") and "403 Forbidden" in result["error"], "manifest_invalid")
    wanted = {REMOTE + "/" + path for path, _, _ in rows} if name in {"acquisition", "mismatch"} else set()
    need(set(output_files(output)) == wanted, "outputs_invalid")
    need(manifest["complete"] is (name == "acquisition"), "manifest_invalid")
    application_inventory(name, case, manifests[0])
    return {"acquisition": {"manifest_complete": True, "manifest_exact": True, "output_hashes_exact": True, "outputs_exact": True},
            "mismatch": {"manifest_incomplete": True, "mismatch_exact": True, "retained_bytes_exact": True, "outputs_exact": True},
            "missing": {"manifest_incomplete": True, "missing_failure_exact": True, "no_download_outputs": True},
            "denial": {"manifest_incomplete": True, "failed_result_exact": True, "no_download_outputs": True},
            "cancellation": {"manifest_incomplete": True, "cancelled_result_exact": True, "no_partial_outputs": True, "no_download_outputs": True}}[name]


def partial_active(case, case_lease):
    need(identity(case) == case_lease, "preservation_failed")
    base = case / "output" / CASE_NAME / "downloads"
    if not base.exists():
        need(identity(case) == case_lease, "preservation_failed")
        return False
    base_lease = identity(base)
    entries = inventory(base)
    need(identity(base) == base_lease and identity(case) == case_lease, "preservation_failed")
    # Source contract, not an observation of the earlier failed native case:
    # private_fs uses 32 lowercase hex digits; pinned rclone v1.75.1 Copy's
    # default partial upload is payload.<8 lowercase CRC32 hex digits>.partial.
    matches = [(path, info) for path, info in entries.items() if not info[0] and re.fullmatch(
        r"Synthetic/large/\.triage-transfer-[0-9a-f]{32}/payload\.[0-9a-f]{8}\.partial", path)]
    need(len(matches) <= 1, "cancellation_failed")
    if not matches:
        return False
    path, observed = matches[0]
    need(all(info[0] or name == path for name, info in entries.items()), "cancellation_failed")
    stage = path.rsplit("/", 1)[0]
    stage_info = entries.get(stage)
    need(stage_info is not None and stage_info[0] and
         identity(base / stage) == stage_info[2:4], "preservation_failed")
    current = plain(base / path)
    need((current.st_dev, current.st_ino) == observed[2:4] and
         identity(base / stage) == stage_info[2:4] and identity(base) == base_lease and
         identity(case) == case_lease, "preservation_failed")
    return 0 < observed[1] < ROWS[1][1] and 0 < current.st_size < ROWS[1][1]


def fixture_valid(name, snapshot):
    need(not snapshot["errors"] and snapshot["source_preserved"] and snapshot["observation_started"] and
         snapshot["observation_released"] and snapshot["rejected"] == 0, "fixture_failed")
    events = snapshot["events"]
    need(events and events[0][0] == "observation" and sum(e[0] == "observation" for e in events) == 1, "fixture_failed")
    content = [path for event, path in events if event == "content"]
    expected = [r[0] for r in ROWS] if name == "acquisition" else [ROWS[0][0]] if name == "mismatch" else [ROWS[1][0]] if name == "cancellation" else []
    need(sorted(content) == sorted(expected), "fixture_failed")
    need(snapshot["missing"] > 0 if name == "missing" else snapshot["missing"] == 0, "fixture_failed")
    need(snapshot["denied"] > 0 if name == "denial" else snapshot["denied"] == 0, "fixture_failed")
    if name == "cancellation":
        # Aggregate body counters also include HTML metadata/error replies.
        need(snapshot["cancel_started"] and snapshot["cancel_disconnected"] and
             sum(e == ["cancel_prefix", ROWS[1][0]] for e in events) == 1 and
             sum(e == ["cancel_disconnected", ROWS[1][0]] for e in events) == 1, "cancellation_failed")
    return True


def run_case(name, suite, application, application_sha, runtime, session_factory=Bridge):
    record = {"status": "failed", "exit_code": None, "runtime_sha256": None, "failure_code": None,
              "checks": {key: False for key in sorted(E.CASE_CHECKS[name])}}
    checks = record["checks"]
    case = suite / name
    lease = bridge = server = context = state = None
    session_attempted = fixture_attempted = entered = prepared = False
    helper_closed = False
    runtime_diagnostic = None
    runtime_residue = None
    runtime_diagnostic_attempted = False
    config_bytes = None
    helper_before = private_leases = None
    def fail(code):
        if record["failure_code"] is None:
            record["failure_code"] = code
    def collect_runtime_diagnostic():
        nonlocal runtime_diagnostic, runtime_residue, runtime_diagnostic_attempted
        if not runtime_diagnostic_attempted and helper_closed and lease is not None:
            runtime_diagnostic_attempted = True
            try:
                runtime_diagnostic = read_runtime_cleanup_diagnostic(case, lease)
                if runtime_diagnostic is not None and runtime_diagnostic["stage"] == "remove_tree":
                    runtime_residue = read_runtime_cleanup_residue(case, lease, runtime_diagnostic)
            except BaseException:
                pass
    try:
        prepare(suite, name)
        prepared = True
        lease = identity(case)
        private_leases = create_private_roots(case)
        private_directory(case, "output")
        # Cargo may hardlink the release output. Only this read permits links;
        # the helper locks and executes a fresh, single-link owned copy.
        application_bytes = read(application, 512 * 1024 * 1024, allow_hardlinks=True)
        need(sha(application_bytes) == application_sha, "binding_failed")
        owned_application = case / "application.exe"
        private_write(case, "application.exe", application_bytes)
        del application_bytes
        need(sha(read(owned_application, 512 * 1024 * 1024)) == application_sha, "binding_failed")
        state = F.AppHttpState(payloads(), "baseline" if name == "acquisition" else name)
        context = F.serve_http(state)
        fixture_attempted = True
        server = context.__enter__()
        entered = True
        config_bytes = ("[Synthetic]\ntype = http\nurl = " + server.endpoint + "\n").encode("ascii")
        private_write(case, "source.conf", config_bytes)
        if name != "listing":
            private_write(case, "queue.csv", queue_bytes(name))
        deadline = time.monotonic() + CASE_SECONDS
        session_attempted = True
        bridge = session_factory(case)
        validate_ready(bridge.command("ready"))
        helper_before = prestart_baseline(name, case, private_leases)
        response = bridge.command("start", app_path=str(owned_application), app_sha256=application_sha,
            args=app_args(name, case), case_root=str(case), environment=environment(case),
            transcript_path=str(case / "transcript.private"), max_output_bytes=8 * 1024 * 1024, deadline_ms=150000,
            max_runtime_processes=runtime_process_limit(name))
        while not state.observation_started.wait(0.05):
            need(time.monotonic() < deadline, "deadline_exceeded")
            response = bridge.command("poll")
            need(response["ok"] and not response["app_exited"] and response["state"] == "running", "runtime_unobserved")
        response = bridge.command("observe_runtime", extraction_root=str(case / "temp"), expected_sha256=runtime["sha256"])
        checks["runtime_observed"] = (response["ok"] and response["runtime_image_observed"] and
            response["runtime_sha256"] == runtime["sha256"] and type(response["runtime_process_count"]) is int and
            1 <= response["runtime_process_count"] <= runtime_process_limit(name))
        need(checks["runtime_observed"], "runtime_unobserved")
        record["runtime_sha256"] = response["runtime_sha256"]
        state.release_observation()
        if name == "cancellation":
            while not (state.cancel_started.is_set() and partial_active(case, lease)):
                need(time.monotonic() < deadline, "deadline_exceeded")
                response = bridge.command("poll")
                need(response["ok"] and not response["app_exited"], "cancellation_failed")
                time.sleep(0.05)
            checks["transfer_active"] = True
            response = bridge.command("ctrl_c")
            checks["ctrl_c_sent"] = response["ok"] and response["ctrl_c_sent"]
            need(checks["ctrl_c_sent"], "cancellation_failed")
        while not response["app_exited"]:
            need(time.monotonic() < deadline, "deadline_exceeded")
            response = bridge.command("poll")
            need(response["ok"], "session_failed")
            time.sleep(0.1)
        if response["state"] != "finished":
            response = bridge.command("finish", grace_ms=15000)
        bridge.last = response
        record["exit_code"] = response["app_exit_code"]
        need(response["state"] == "finished" and response["ok"] and not response["forced_termination"] and
             response["runtime_image_observed"] and response["runtime_sha256"] == runtime["sha256"], "session_failed")
        checks["orderly_exit"] = all(response[key] for key in SESSION_CLEANUP)
        checks["exit_success" if name in {"listing", "acquisition"} else "exit_failure"] = (
            record["exit_code"] == 0 if name in {"listing", "acquisition"} else
            type(record["exit_code"]) is int and record["exit_code"] != 0)
        config = configuration_preserved(case, config_bytes)
        checks["configuration_preserved"] = True
        if name != "listing":
            need(read(case / "queue.csv", 65536) == queue_bytes(name), "preservation_failed")
        checks.update(check_listing(case) if name == "listing" else check_manifest(name, case, config, runtime))
        if name == "listing":
            application_inventory(name, case)
    except ProducerError as error:
        fail(str(error) if str(error) in E.FAILURE_CODES else "unexpected_failure")
    except BaseException:
        fail("unexpected_failure")
    finally:
        if bridge is not None:
            try:
                helper_closed = bridge.close()
                final = bridge.last
                checks["process_cleanup"] = bool(helper_closed and final and final["state"] == "finished" and
                                                 all(final[key] for key in SESSION_CLEANUP))
                if final and record["exit_code"] is None:
                    record["exit_code"] = final["app_exit_code"]
            except BaseException:
                fail("cleanup_failed")
        else:
            checks["process_cleanup"] = prepared and not session_attempted
        if entered:
            try:
                context.__exit__(None, None, None)
            except BaseException:
                fail("cleanup_failed")
        if server is not None:
            snapshot = server.snapshot()
            checks["fixture_cleanup"] = server.cleanup_complete
            checks["source_preserved"] = snapshot["source_preserved"]
            try:
                checks["fixture_valid"] = fixture_valid(name, snapshot)
                if name == "denial":
                    checks["denial_observed"] = snapshot["denied"] > 0
            except ProducerError as error:
                fail(str(error))
        else:
            checks["fixture_cleanup"] = not fixture_attempted
        if record["failure_code"] is not None or not all(value for key, value in checks.items() if key != "temp_cleanup"):
            collect_runtime_diagnostic()
        if lease is not None and checks["process_cleanup"] and checks["fixture_cleanup"]:
            cleanup_stage, cleanup_location, cleanup_summary = "case_identity", None, None
            try:
                need(identity(case) == lease, "cleanup_failed")
                if checks["configuration_preserved"]:
                    cleanup_stage = "configuration"
                    configuration_preserved(case, config_bytes)
                    cleanup_stage = "application_bytes"
                    need(sha(read(case / "application.exe", 512 * 1024 * 1024)) == application_sha, "preservation_failed")
                    if name != "listing":
                        cleanup_stage = "queue_bytes"
                        need(read(case / "queue.csv", 65536) == queue_bytes(name), "preservation_failed")
                cleanup_stage = "post_helper"
                post_helper_preserved(name, case, private_leases, helper_before)
                cleanup_stage, cleanup_location, cleanup_summary = "acl_verify", None, None
                checks["process_cleanup"] = False
                prepare(suite, name, "Verify")
                checks["process_cleanup"] = True
                cleanup_stage = "owned_removal"
                remove_owned(case, lease)
                checks["temp_cleanup"] = True
            except BaseException as error:
                fail("cleanup_failed")
                if cleanup_stage == "acl_verify":
                    helper_profile_failure_diagnostic(name, case, lease, private_leases, error)
                if cleanup_stage != "post_helper":
                    cleanup_diagnostic(name, cleanup_stage, cleanup_location, cleanup_summary)
        elif not case.exists():
            checks["temp_cleanup"] = True
    if not all(checks.values()) and record["failure_code"] is None:
        fail("session_failed")
    if record["failure_code"] is None and all(checks.values()):
        record["status"] = "passed"
    if record["status"] == "failed":
        collect_runtime_diagnostic()
        if runtime_diagnostic is not None:
            try:
                runtime_cleanup_diagnostic(name, runtime_diagnostic)
                if runtime_residue is not None:
                    runtime_cleanup_residue(name, runtime_residue)
            except BaseException:
                pass  # Printing a finite diagnostic never changes acceptance or cleanup.
    return record


def run(application, application_sha, build_commit):
    hosted_guard()
    application = Path(application).absolute()
    need(E.valid_hash(application_sha) and plain(application, allow_hardlinks=True).st_size <= 512 * 1024 * 1024, "binding_failed")
    loaded_sources_preserved()
    runtime = runtime_pins(ROOT / "rclone-version.env")
    bindings = E.compute_bindings(ROOT, application, build_commit, fixture_manifest())
    need(bindings["application_sha256"] == application_sha, "binding_failed")
    need(os.environ.get("GITHUB_SHA") == build_commit, "binding_failed")
    cases, errors, suite, suite_identity = E.empty_cases(), [], None, None
    global_cleanup = False
    try:
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        suite = parent / ("app-http-" + uuid.uuid4().hex)
        need(not suite.exists(), "case_setup_failed")
        prepare(parent, suite.name)
        suite_identity = identity(suite)
        for name in E.CASE_ORDER:
            need(identity(suite) == suite_identity, "preservation_failed")
            cases[name] = run_case(name, suite, application, application_sha, runtime)
            if cases[name]["status"] != "passed":
                errors.append(cases[name]["failure_code"])
                break
    except ProducerError as error:
        errors.append(str(error) if str(error) in E.FAILURE_CODES else "unexpected_failure")
    except BaseException:
        errors.append("unexpected_failure")
    finally:
        try:
            loaded_sources_preserved()
            need(E.compute_bindings(ROOT, application, build_commit, fixture_manifest()) == bindings and
                 runtime_pins(ROOT / "rclone-version.env") == runtime, "preservation_failed")
        except BaseException:
            errors.append("preservation_failed")
        if suite_identity is not None:
            try:
                need(all(c["status"] == "not_run" or all(c["checks"][key] for key in
                     ("process_cleanup", "fixture_cleanup", "temp_cleanup")) for c in cases.values()), "cleanup_failed")
                need(not inventory(suite), "cleanup_failed")
                prepare(suite.parent, suite.name, "Verify")
                remove_owned(suite, suite_identity)
                global_cleanup = True
            except BaseException:
                errors.append("cleanup_failed")
        elif suite is None:
            global_cleanup = True
        else:
            errors.append("cleanup_failed")
    errors = list(dict.fromkeys(errors))
    result = {"schema_version": 1, "scope": E.SCOPE, "fixture_mode": E.MODE, "backend": "http", "platform": "windows",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "runtime": runtime, "bindings": bindings,
        "cases": cases, "capabilities": E.derive_capabilities(cases, cleanup_complete=global_cleanup),
        "result": "passed" if global_cleanup and not errors and all(c["status"] == "passed" for c in cases.values()) else "failed",
        "cleanup_complete": global_cleanup, "errors": errors}
    E.validate_receipt(result, runtime, bindings)
    return result


def setup_probe():
    """Early hosted setup check only: no application, runtime or receipt."""
    try:
        hosted_guard()
        loaded_sources_preserved()
        helper_hash = sha(read(HERE / "prepare_case.ps1", 65536))
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        parent_id = identity(parent)
        suite = parent / ("app-http-" + uuid.uuid4().hex)
        need(not suite.exists(), "case_setup_failed")
        prepare(parent, suite.name)
        owned = identity(suite)
        need(identity(parent) == parent_id and not inventory(suite), "preservation_failed")
        prepare(parent, suite.name, "Verify")
        loaded_sources_preserved()
        need(identity(parent) == parent_id and identity(suite) == owned and not inventory(suite) and
             sha(read(HERE / "prepare_case.ps1", 65536)) == helper_hash, "preservation_failed")
        # No failure recovery removes a directory whose setup or verification
        # could still have an unproven child, replacement or ACL outcome.
        remove_owned(suite, owned)
        print("application_setup_probe_passed", flush=True)
        return 0
    except BaseException:
        print("application_setup_probe_failed", flush=True)
        return 1


BRIDGE_PROBE_STAGES = frozenset({"initial", "suite_setup", "case_setup", "helper_launch", "ready", "prestart",
    "close_ready", "helper_cleanup", "identity", "private_inventory", "case_acl", "source", "case_removal", "suite_acl", "suite_removal"})


def bridge_probe_diagnostic(stage, failure_code):
    need(type(stage) is str and stage in BRIDGE_PROBE_STAGES and type(failure_code) is str and
         failure_code in E.FAILURE_CODES, "session_failed")
    print("application_bridge_probe_diagnostic=" + E.compact(dict(stage=stage, failure_code=failure_code)).decode("ascii"), flush=True)


def bridge_probe(session_factory=None):
    """Hosted helper preflight only; never starts an application or fixture."""
    bridge = None
    close_attempted = False
    stage = "initial"
    try:
        hosted_guard()
        loaded_sources_preserved()
        source_paths = ("prepare_case.ps1", "hosted_session.ps1", "HostedConPtySession.cs")
        source_hashes = {name: sha(read(HERE / name, 65536)) for name in source_paths}
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        parent_id = identity(parent)
        suite = parent / ("app-http-" + uuid.uuid4().hex)
        need(not suite.exists(), "case_setup_failed")
        stage = "suite_setup"
        prepare(parent, suite.name)
        suite_id = identity(suite)
        need(identity(parent) == parent_id and not inventory(suite), "preservation_failed")
        stage = "case_setup"
        prepare(suite, "listing")
        case = suite / "listing"
        case_id = identity(case)
        private_leases = create_private_roots(case)
        stage = "helper_launch"
        bridge = (Bridge if session_factory is None else session_factory)(case)
        stage = "ready"
        validate_ready(bridge.command("ready"))
        stage = "prestart"
        baseline = prestart_baseline("listing", case, private_leases)
        stage = "close_ready"
        validate_close_ready(bridge.command("close_ready"))
        stage = "helper_cleanup"
        close_attempted = True
        need(bridge.close(), "cleanup_failed")
        stage = "identity"
        need(identity(parent) == parent_id and identity(suite) == suite_id and identity(case) == case_id,
             "preservation_failed")
        stage = "private_inventory"
        entries = post_helper_preserved("listing", case, private_leases, baseline, probe=True)
        stage = "case_acl"
        prepare(suite, "listing", "Verify")
        stage = "source"
        loaded_sources_preserved()
        need({name: sha(read(HERE / name, 65536)) for name in source_paths} == source_hashes, "preservation_failed")
        stage = "identity"
        need(identity(parent) == parent_id and identity(suite) == suite_id and
             identity(case) == case_id and inventory(case) == entries, "preservation_failed")
        stage = "case_removal"
        remove_owned(case, case_id)
        stage = "suite_acl"
        prepare(parent, suite.name, "Verify")
        stage = "source"
        loaded_sources_preserved()
        need({name: sha(read(HERE / name, 65536)) for name in source_paths} == source_hashes, "preservation_failed")
        stage = "identity"
        need(identity(parent) == parent_id and identity(suite) == suite_id and not inventory(suite), "preservation_failed")
        stage = "suite_removal"
        remove_owned(suite, suite_id)
        print("application_bridge_probe_passed", flush=True)
        return 0
    except BaseException as error:
        code = str(error) if isinstance(error, ProducerError) and str(error) in E.FAILURE_CODES else "unexpected_failure"
        if stage == "case_acl":
            helper_profile_failure_diagnostic("listing", case, case_id, private_leases, error)
        if bridge is not None and not close_attempted:
            try:
                bridge.close()
            except BaseException:
                pass
        bridge_probe_diagnostic(stage, code)
        print("application_bridge_probe_failed", flush=True)
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup-probe", action="store_true")
    parser.add_argument("--bridge-probe", action="store_true")
    parser.add_argument("--application")
    parser.add_argument("--application-sha256")
    parser.add_argument("--build-commit")
    parser.add_argument("--report")
    args = parser.parse_args(argv)
    acceptance_args = (args.application, args.application_sha256, args.build_commit, args.report)
    preflight = args.setup_probe or args.bridge_probe
    if (args.setup_probe and args.bridge_probe or preflight and any(value is not None for value in acceptance_args)
            or not preflight and any(value is None for value in acceptance_args)):
        parser.error("use one preflight flag alone or all four application acceptance arguments")
    descriptor = None
    prior_signal = None
    try:
        hosted_guard()
        def interrupted(_signal, _frame):
            raise KeyboardInterrupt()
        prior_signal = signal.signal(signal.SIGTERM, interrupted)
        if args.setup_probe:
            return setup_probe()
        if args.bridge_probe:
            return bridge_probe()
        report = Path(args.report).absolute()
        plain(report.parent, True)
        descriptor = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        result = run(args.application, args.application_sha256, args.build_commit)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(E.compact(result) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        return 0 if result["result"] == "passed" else 1
    except BaseException:
        print("application_probe_failed", file=__import__("sys").stderr)
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if prior_signal is not None:
            signal.signal(signal.SIGTERM, prior_signal)


if __name__ == "__main__":
    raise SystemExit(main())
