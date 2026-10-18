"""Literal source-graph and stale-receipt regressions; inert files only."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


S = load("snapshot_policy_test", ROOT / "scripts/application_source_snapshot.py")
CLI = load("snapshot_cli_receipts", ROOT / "scripts/tests/test_application_evidence.py")
TUI = load("snapshot_tui_receipts", ROOT / "scripts/tests/test_tui_application_evidence.py")
A, T = CLI.EVIDENCE, TUI.E
HELPER = "scripts/application_source_snapshot.py"
APP_MANIFEST = b'''[package]
name="synthetic"
version="0.0.0"
[dependencies]
alpha={path="../local/alpha"}
[build-dependencies]
builder={path="../local/builder"}
[dev-dependencies]
dev={path="../local/dev"}
[target.'cfg(windows)'.dependencies]
optional={path="../local/optional", optional=true}
'''
FILES = {
    "rclone-triage/Cargo.toml": APP_MANIFEST,
    "rclone-triage/Cargo.lock": b"version = 4\n",
    "rclone-triage/build.rs": b"fn main() {}\n",
    "rclone-triage/.cargo/config.toml": b"[target.synthetic]\nrustflags=[]\n",
    "rclone-triage/src/main.rs": b"fn main() {}\n",
    "local/alpha/Cargo.toml": b'[package]\nname="alpha"\nversion="0.0.0"\n[dependencies]\nbeta={path="../beta"}\n[lib]\npath="src/lib.rs"\n',
    "local/alpha/src/lib.rs": b'const _: &str = include_str!("../NOTES");\n',
    "local/alpha/NOTES": b"non-Rust included input\n",
    "local/beta/Cargo.toml": b'[package]\nname="beta"\nversion="0.0.0"\n',
    "local/beta/src/lib.rs": b"// nested dependency\n",
    "local/builder/Cargo.toml": b'[package]\nname="builder"\nversion="0.0.0"\n',
    "local/builder/src/lib.rs": b"// build dependency\n",
    "local/dev/Cargo.toml": b'[package]\nname="dev"\nversion="0.0.0"\n',
    "local/dev/src/lib.rs": b"// dev dependency\n",
    "local/optional/Cargo.toml": b'[package]\nname="optional"\nversion="0.0.0"\n',
    "local/optional/src/lib.rs": b"// optional target dependency\n",
}


class SourceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"CARGO_TARGET_DIR": "", "CARGO_BUILD_TARGET_DIR": ""}).start()
        for name, data in FILES.items():
            self.write(name, data)
        for name in set(A.HARNESS_FILES) | set(T.HARNESS_FILES):
            self.write(name, A._SOURCE_BYTES if name == HELPER else b"inert harness bytes\n")
        self.write("application.data", b"inert image, never executed")
        self.write("rclone-version.env", b"synthetic runtime binding\n")

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def rows(self, **kwargs):
        return S.source_rows(self.root, **kwargs)

    def bindings(self):
        app = self.root / "application.data"
        return (A.compute_bindings(self.root, app, "d" * 40, {"synthetic": "manifest"}),
                T.compute_bindings(self.root, app, "d" * 40))

    def test_literal_inventory_hashes_and_cli_tui_agreement(self):
        expected = [[name, hashlib.sha256(data).hexdigest()] for name, data in sorted(FILES.items())]
        self.assertEqual(self.rows(), expected)
        digest = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        for binding in self.bindings():
            self.assertEqual(binding["application_source_sha256"], digest)
        self.write("unrelated.txt", b"outside declared application/package input policy")
        self.assertEqual(self.rows(), expected)
        # Dependency order does not affect the sorted names; manifest bytes still bind.
        before = self.rows()
        self.assertEqual(before, self.rows())

    def test_stale_receipts_reject_dependency_edit_add_remove_without_rebuild(self):
        for mutation in ("rust", "include", "added", "removed"):
            with self.subTest(mutation=mutation):
                before = self.bindings()
                now = datetime.now(timezone.utc)
                receipts = (CLI.receipt(), TUI.receipt())
                for value, binding in zip(receipts, before):
                    value["bindings"] = binding
                    value["created_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
                A.validate_receipt(receipts[0], CLI.RUNTIME, before[0], now=now)
                T.validate_receipt(receipts[1], TUI.RUNTIME, before[1], now=now)
                name = "local/alpha/src/lib.rs" if mutation == "rust" else "local/alpha/NOTES"
                if mutation == "added": name = "local/beta/new-input.dat"
                path = self.root / name
                original = path.read_bytes() if path.exists() else None
                if mutation == "removed": path.unlink()
                else: self.write(name, b"changed dependency source\n")
                after = self.bindings()
                for old, new in zip(before, after):
                    self.assertNotEqual(old["application_source_sha256"], new["application_source_sha256"])
                    for key in ("application_sha256", "build_commit", "cargo_lock_sha256"):
                        self.assertEqual(old[key], new[key])
                with self.assertRaises(A.ApplicationEvidenceError): A.validate_receipt(receipts[0], CLI.RUNTIME, after[0], now=now)
                with self.assertRaises(T.TuiEvidenceError): T.validate_receipt(receipts[1], TUI.RUNTIME, after[1], now=now)
                if original is None: path.unlink()
                else: path.write_bytes(original)

    def test_only_immediate_target_output_is_skipped_without_descent_or_read(self):
        baseline = self.rows()
        targets = [self.root / name / "target" for name in ("rclone-triage", "local/alpha", "local/beta")]
        for target in targets:
            target.mkdir()
            # More output descendants than the entire source entry budget.
            for index in range(S.MAX_ENTRIES + 1): (target / str(index)).write_bytes(b"generated")
        real_scan, real_read = S.os.scandir, S.read_file
        def scan(path):
            self.assertFalse(any(Path(path).is_relative_to(t) for t in targets))
            return real_scan(path)
        def read(path, *args, **kwargs):
            self.assertFalse(any(Path(path).is_relative_to(t) for t in targets))
            return real_read(path, *args, **kwargs)
        with patch.object(S.os, "scandir", side_effect=scan): self.assertEqual(self.rows(reader=read), baseline)
        (targets[1] / "0").write_bytes(b"different generated bytes")
        (targets[2] / "1").unlink()
        self.assertEqual(self.rows(), baseline)
        self.write("local/alpha/src/target/ordinary-input", b"source, not build output")
        self.assertNotEqual(self.rows(), baseline)

    def test_reserved_target_file_link_reparse_and_replacement_fail(self):
        target = self.root / "local/alpha/target"
        target.write_bytes(b"not a directory")
        with self.assertRaises(S.SourceSnapshotError): self.rows()
        target.unlink();target.mkdir()
        original = Path.lstat
        for affected,kind in ((target,"symlink"),(target,"reparse"),(self.root/"local/alpha","reparse")):
            def lstat(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                if path == affected:
                    values = {name: getattr(info, name) for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")}
                    values["st_mode"] = stat.S_IFLNK if kind == "symlink" else info.st_mode
                    values["st_file_attributes"] = 0x400 if kind == "reparse" else 0
                    return types.SimpleNamespace(**values)
                return info
            with patch.object(Path, "lstat", lstat), self.assertRaises(S.SourceSnapshotError): self.rows()
        changed = False
        def read(path, *args, **kwargs):
            nonlocal changed
            data = S.read_file(path, *args, **kwargs)
            if not changed and Path(path).name == "NOTES":
                changed = True
                target.rename(self.root / "old-target")
                target.mkdir()
            return data
        with self.assertRaisesRegex(S.SourceSnapshotError, "source_changed"): self.rows(reader=read)

    def test_target_presence_change_mid_scan_is_not_portable_digest_data(self):
        baseline = self.rows();target = self.root / "local/beta/target"
        changed = False
        def read(path, *args, **kwargs):
            nonlocal changed
            data = S.read_file(path, *args, **kwargs)
            if not changed and Path(path).name == "NOTES": changed = True;target.mkdir()
            return data
        with self.assertRaises(S.SourceSnapshotError): self.rows(reader=read)
        self.assertEqual(self.rows(), baseline)
        target.rmdir();self.assertEqual(self.rows(), baseline)

    def test_explicit_source_and_dependency_paths_into_reserved_output_reject(self):
        for package in ("rclone-triage", "local/alpha"):
            path = self.root / package / "Cargo.toml";original = path.read_bytes()
            for table in ("lib", "bin", "example", "test", "bench", "build", "dependency"):
                if table == "build":
                    changed = original.replace(b'[package]\n', b'[package]\nbuild="target/hidden.rs"\n')
                elif table == "dependency":
                    changed = original + b'\n[build-dependencies.hidden]\npath="target/hidden"\n'
                else:
                    # Replace alpha's existing lib section before testing each explicit form.
                    changed = original.replace(b'[lib]\npath="src/lib.rs"\n', b'')
                    changed += ('\n[' + (table if table == "lib" else '[' + table + ']') + ']\npath="target/hidden.rs"\n').encode()
                path.write_bytes(changed)
                with self.subTest(package=package, table=table), self.assertRaises(S.SourceSnapshotError): self.rows()
            path.write_bytes(original)
        # An ancestor package's output is also reserved to a nested dependency.
        path=self.root/"local/alpha/Cargo.toml";original=path.read_bytes()
        path.write_bytes(original.replace(b'path="../beta"', b'path="../../rclone-triage/target/hidden"'))
        with self.assertRaises(S.SourceSnapshotError): self.rows()

    def test_manifest_changes_after_discovery_reject_even_when_names_match(self):
        for graph_change in (False, True):
            manifest = self.root / "local/alpha/Cargo.toml";original = manifest.read_bytes();changed = False
            def read(path, *args, **kwargs):
                nonlocal changed
                data = S.read_file(path, *args, **kwargs)
                if not changed and Path(path).name == "NOTES":
                    changed = True
                    manifest.write_bytes(original.replace(b'../beta', b'../optional') if graph_change else original + b'# graph unchanged\n')
                return data
            with self.assertRaises(S.SourceSnapshotError): self.rows(reader=read)
            manifest.write_bytes(original)

    def test_missing_escaping_cycles_overlap_and_unsupported_forms_reject(self):
        manifest = self.root / "local/alpha/Cargo.toml";original = manifest.read_bytes()
        for replacement in (b'../absent', b'../../../outside', b'../alpha', b'src', b'../BETA', b'../beta/../beta/'):
            manifest.write_bytes(original.replace(b'../beta', replacement))
            with self.subTest(path=replacement), self.assertRaises(S.SourceSnapshotError): self.rows()
        for extra in (b'\n[workspace]\n', b'\n[patch.crates-io]\n', b'\n[replace]\n',
                      b'\n[dependencies.inherited]\nworkspace=true\n'):
            manifest.write_bytes(original + extra)
            with self.assertRaises(S.SourceSnapshotError): self.rows()
        manifest.write_bytes(b'not valid TOML')
        with self.assertRaises(S.SourceSnapshotError): self.rows()
        manifest.unlink()
        with self.assertRaises(S.SourceSnapshotError): self.rows()

    def test_unsupported_output_config_and_outside_source_entry_reject(self):
        config = self.root / "rclone-triage/.cargo/config.toml";original=config.read_bytes()
        for data in (b'[build]\ntarget-dir="elsewhere"\n', b'paths=["../override"]\n', b'[source.crates-io]\nreplace-with="other"\n'):
            config.write_bytes(data)
            with self.assertRaises(S.SourceSnapshotError): self.rows()
        config.write_bytes(original)
        with patch.dict(os.environ, {"CARGO_TARGET_DIR": "elsewhere"}), self.assertRaises(S.SourceSnapshotError): self.rows()
        self.write(".cargo/config.toml", b"[target.synthetic]\nrustflags=[]\n")
        with self.assertRaises(S.SourceSnapshotError): self.rows()
        (self.root/".cargo/config.toml").unlink()
        self.write("rclone-triage/extra.rs", b"outside application src projection")
        self.write("rclone-triage/Cargo.toml", APP_MANIFEST+b'\n[[bin]]\npath="extra.rs"\n')
        with self.assertRaises(S.SourceSnapshotError): self.rows()

    def test_bounded_reads_and_mid_scan_source_enumeration_change_reject(self):
        self.write("local/beta/large-input", b"x"*(S.MAX_FILE_BYTES+1))
        with self.assertRaisesRegex(S.SourceSnapshotError, "source_limit"): self.rows()
        (self.root/"local/beta/large-input").unlink()
        with patch.object(S, "MAX_ENTRIES", 5), self.assertRaisesRegex(S.SourceSnapshotError, "source_limit"): self.rows()
        changed=False
        def read(path,*args,**kwargs):
            nonlocal changed
            data=S.read_file(path,*args,**kwargs)
            if not changed and Path(path).name=="NOTES":changed=True;self.write("local/beta/new",b"added during scan")
            return data
        with self.assertRaises(S.SourceSnapshotError):self.rows(reader=read)

    def test_shared_helper_is_bound_by_all_explicit_and_inherited_modes(self):
        modules=[A,T]+[load("snapshot_closure_"+name,ROOT/("scripts/"+name+"_application_evidence.py")) for name in
            ("webdav","webdav_bearer","ftp","b2","swift","azureblob","filesystem")]
        for module in modules:
            self.assertEqual(module.HARNESS_FILES.count(HELPER),1)
        self.assertEqual(T.CLI_HARNESS_FILES.count(HELPER),1)
        before=self.bindings()
        path=self.root/HELPER;path.write_bytes(path.read_bytes()+b"# changed\n")
        with self.assertRaises(A.ApplicationEvidenceError):self.bindings()
        with self.assertRaises(T.TuiEvidenceError):T.compute_bindings(self.root,self.root/"application.data","d"*40)
        path.write_bytes(A._SOURCE_BYTES)
        with patch.object(A.SOURCE,"read_file",return_value="f"*64), self.assertRaises(A.ApplicationEvidenceError):
            A.compute_bindings(self.root,self.root/"application.data","d"*40,{})
        read=T._file
        with patch.object(T,"_file",side_effect=lambda p,*a,**k:"f"*64 if Path(p)==T._SOURCE_PATH else read(p,*a,**k)), self.assertRaises(T.TuiEvidenceError):
            T.compute_bindings(self.root,self.root/"application.data","d"*40)
        self.assertEqual(before,self.bindings())

    def test_depth_and_dependency_root_spelling_aliases_fail_closed(self):
        self.write("local/beta/one/two/three/four/input",b"too deep for narrowed test budget")
        with patch.object(S,"MAX_DEPTH",5),self.assertRaisesRegex(S.SourceSnapshotError,"source_limit"):
            self.rows()
        # On POSIX these are distinct directories; on Windows this is an alias.
        # Both must reject instead of admitting different portable inventories.
        self.write("LOCAL/other/Cargo.toml",b'[package]\nname="other"\nversion="0.0.0"\n')
        self.write("LOCAL/other/src/lib.rs",b"// source\n")
        manifest=self.root/"rclone-triage/Cargo.toml"
        manifest.write_bytes(APP_MANIFEST+b'\n[dependencies.alias]\npath="../LOCAL/other"\n')
        with self.assertRaises(S.SourceSnapshotError):self.rows()
        manifest.write_bytes(APP_MANIFEST+b'\n[dependencies.alias]\npath="../local/cafe\xcc\x81"\n')
        with self.assertRaises(S.SourceSnapshotError):self.rows()

    def test_both_stable_readers_reject_handle_changes_and_nonregular_inputs(self):
        path=self.root/"local/alpha/NOTES"
        for reader,error in ((S.read_file,S.SourceSnapshotError),(T._file,T.TuiEvidenceError)):
            original=os.fstat;calls=[]
            def changed(fd):
                info=original(fd);calls.append(fd)
                if len(calls)==2:
                    values={name:getattr(info,name) for name in ("st_dev","st_ino","st_mode","st_size","st_mtime_ns","st_ctime_ns")}
                    values["st_ctime_ns"]+=1
                    return types.SimpleNamespace(**values)
                return info
            with patch.object(os,"fstat",side_effect=changed),self.assertRaises(error):reader(path,S.MAX_FILE_BYTES)
            self.assertEqual(len(calls),2)
        original=Path.lstat
        def nonregular(item,*args,**kwargs):
            info=original(item,*args,**kwargs)
            if item==path:
                values={name:getattr(info,name) for name in ("st_dev","st_ino","st_mode","st_size","st_mtime_ns","st_ctime_ns")}
                values["st_mode"]=stat.S_IFIFO
                return types.SimpleNamespace(**values)
            return info
        with patch.object(Path,"lstat",nonregular),self.assertRaises(S.SourceSnapshotError):self.rows()

    def metadata_read(self, *, windows=True, unequal_ctime=False, cross_change=None, same_change=None,
                      birth_presence="both"):
        path = self.root / "local/alpha/NOTES"
        original = Path.lstat
        actual = original(path)
        fields = {name: getattr(actual, name) for name in
                  ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")}
        fields.update(st_ctime_ns=200, st_birthtime_ns=100,
                      st_file_attributes=getattr(actual, "st_file_attributes", 0))
        calls = {"path": 0, "handle": 0}
        def lstat(item, *args, **kwargs):
            if item != path: return original(item, *args, **kwargs)
            calls["path"] += 1
            data = dict(fields)
            if birth_presence in {"handle", "neither"}: data.pop("st_birthtime_ns")
            if same_change == "path" and calls["path"] >= 3: data["st_ctime_ns"] += 1
            return types.SimpleNamespace(**data)
        def fstat(_fd):
            calls["handle"] += 1
            data = dict(fields)
            if unequal_ctime: data["st_ctime_ns"] = 300
            if cross_change:
                name, value = cross_change
                data[name] = value(fields[name])
            if birth_presence in {"path", "neither"}: data.pop("st_birthtime_ns")
            if same_change == "handle" and calls["handle"] >= 2: data["st_ctime_ns"] += 1
            return types.SimpleNamespace(**data)
        # Patch only the policy flag, never os.name or pathlib's platform state.
        with patch.object(S, "WINDOWS", windows), patch.object(Path, "lstat", lstat), patch.object(os, "fstat", fstat):
            return S.read_file(path)

    def test_windows_stable_unequal_cross_api_ctime_is_compatible_only_at_open(self):
        expected = hashlib.sha256(FILES["local/alpha/NOTES"]).hexdigest()
        self.assertEqual(self.metadata_read(unequal_ctime=True), expected)
        self.assertEqual(self.metadata_read(unequal_ctime=True, birth_presence="neither"), expected)
        with self.assertRaisesRegex(S.SourceSnapshotError, "source_changed"):
            self.metadata_read(windows=False, unequal_ctime=True)

    def test_same_api_ctime_changes_still_reject_with_windows_cross_api_difference(self):
        for changed in ("path", "handle"):
            with self.subTest(changed=changed), self.assertRaisesRegex(S.SourceSnapshotError, "source_changed"):
                self.metadata_read(unequal_ctime=True, same_change=changed)

    def test_open_identity_size_mtime_birthtime_and_support_mismatches_still_reject(self):
        changes = [(name, lambda value: value + 1) for name in
                   ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns")]
        changes += [("st_mode", lambda _value: stat.S_IFDIR), ("st_file_attributes", lambda value: value | 0x400)]
        for windows in (True, False):
            for field, mutation in changes:
                with self.subTest(windows=windows, field=field), self.assertRaisesRegex(S.SourceSnapshotError, "source_changed"):
                    self.metadata_read(windows=windows, cross_change=(field, mutation))
            for presence in ("path", "handle"):
                with self.subTest(windows=windows, birth_presence=presence), self.assertRaisesRegex(S.SourceSnapshotError, "source_changed"):
                    self.metadata_read(windows=windows, birth_presence=presence)

    def test_internal_parent_segments_cannot_erase_missing_or_link_components(self):
        manifest=self.root/"rclone-triage/Cargo.toml"
        manifest.write_bytes(APP_MANIFEST.replace(b'../local/alpha',b'../local/bridge/../alpha'))
        bridge=self.root/"local/bridge"
        self.assertFalse(bridge.exists())
        with self.assertRaisesRegex(S.SourceSnapshotError,"source_path_alias"):self.rows()
        bridge.mkdir();original=Path.lstat
        for kind in ("symlink","reparse"):
            calls=[]
            def lstat(path,*args,**kwargs):
                info=original(path,*args,**kwargs)
                if path==bridge:
                    calls.append(path)
                    values={name:getattr(info,name) for name in ("st_dev","st_ino","st_mode","st_size","st_mtime_ns","st_ctime_ns")}
                    values["st_mode"]=stat.S_IFLNK if kind=="symlink" else info.st_mode
                    values["st_file_attributes"]=0x400 if kind=="reparse" else 0
                    return types.SimpleNamespace(**values)
                return info
            with patch.object(Path,"lstat",lstat),self.assertRaisesRegex(S.SourceSnapshotError,"source_path_alias"):
                self.rows()
            self.assertEqual(calls,[])  # Syntax rejection precedes any erased traversal.

    def test_cli_helper_bootstrap_bounds_the_read_before_executing_source(self):
        path=ROOT/"scripts/application_evidence.py";data=path.read_bytes();reads=[]
        module=types.ModuleType("bounded_source_bootstrap_test");module.__file__=str(path)
        class Limited(io.BytesIO):
            def read(self,size=-1):
                reads.append(size)
                self_test.assertEqual(size,128*1024+1)
                return super().read(size)
        self_test=self
        original=Path.open
        def opened(item,*args,**kwargs):
            return Limited(b"x"*(128*1024+2)) if item==path.with_name("application_source_snapshot.py") else original(item,*args,**kwargs)
        with patch.object(Path,"open",opened),self.assertRaisesRegex(ValueError,"application_source_helper_invalid"):
            exec(compile(data,str(path),"exec"),module.__dict__)
        self.assertEqual(reads,[128*1024+1])

    def test_all_binding_modes_recheck_sources_after_their_last_harness_read(self):
        modules = [load("snapshot_late_" + name, ROOT / ("scripts/" + name + "_application_evidence.py"))
                   for name in ("webdav", "webdav_bearer", "ftp", "b2", "swift", "azureblob", "filesystem")]
        producer = load("snapshot_late_tui_producer_tests", ROOT / "scripts/tests/test_windows_tui_producer.py").P
        app, commit = self.root / "application.data", "d" * 40
        self.addCleanup(patch.stopall)
        patch.object(producer.H, "ROOT", self.root).start()
        patch.dict(os.environ, {"GITHUB_SHA": commit}).start()
        cases = [("cli", A, A.HARNESS_FILES, "harness_sha256",
                  lambda: A.compute_bindings(self.root, app, commit, {})),
                 ("tui", T, T.HARNESS_FILES, "tui_harness_sha256",
                  lambda: T.compute_bindings(self.root, app, commit)),
                 ("tui_producer", producer.H.E, producer.HARNESS, "tui_harness_sha256",
                  lambda: producer.source_binding(app, hashlib.sha256(app.read_bytes()).hexdigest(), commit))]
        cases += [(module.__name__, module.A, module.HARNESS_FILES, "harness_sha256",
                   lambda module=module: module.compute_bindings(self.root, app, commit)) for module in modules]
        for _, _, names, _, _ in cases:
            for name in names:
                self.write(name, (ROOT / name).read_bytes())
        target, parked = self.root / "local/alpha/target", self.root / "parked-output"
        for mode, owner, names, field, compute in cases:
            baseline = compute()
            self.assertEqual(baseline[field], A.tree_hash(self.root, names))
            reader_name = "_file" if owner is T else "file_hash"
            reader = getattr(owner, reader_name)
            original_tree_hash = owner.tree_hash
            late = self.root / sorted(names)[-1]
            for mutation in ("add", "remove", "manifest", "target_presence", "target_identity"):
                with self.subTest(mode=mode, mutation=mutation):
                    fired, gates = [], []
                    active = False
                    def tree_hash(root, requested):
                        nonlocal active
                        selected = Path(root) == self.root and tuple(requested) == tuple(names)
                        previous = active
                        if selected:
                            gates.append(tuple(requested))
                            active = True
                        try: return original_tree_hash(root, requested)
                        finally: active = previous
                    def read(path, *args, **kwargs):
                        value = reader(path, *args, **kwargs)
                        if active and Path(path) == late and not fired:
                            fired.append(mutation)
                            if mutation == "add": self.write("local/beta/new-input", b"late addition")
                            elif mutation == "remove": (self.root / "local/alpha/NOTES").unlink()
                            elif mutation == "manifest": self.write("local/alpha/Cargo.toml", FILES["local/alpha/Cargo.toml"] + b"# late\n")
                            elif mutation == "target_presence": target.mkdir()
                            else: target.rename(parked);target.mkdir()
                        return value
                    error = T.TuiEvidenceError if owner is T else owner.ApplicationEvidenceError
                    try:
                        self.assertFalse(target.exists() or parked.exists())
                        if mutation == "target_identity": target.mkdir()
                        with patch.object(owner, "tree_hash", side_effect=tree_hash), \
                                patch.object(owner, reader_name, side_effect=read), self.assertRaises(error):
                            compute()
                        self.assertEqual(gates, [tuple(names)])
                        self.assertEqual(fired, [mutation])
                        if mutation.startswith("target_"):
                            # Separate completed calls intentionally ignore output identity.
                            self.assertEqual(compute()["application_source_sha256"], baseline["application_source_sha256"])
                    finally:
                        for name in ("local/alpha/NOTES", "local/alpha/Cargo.toml"):
                            self.write(name, FILES[name])
                        (self.root / "local/beta/new-input").unlink(missing_ok=True)
                        if target.exists(): target.rmdir()
                        if parked.exists(): parked.rmdir()


if __name__ == "__main__": unittest.main()
