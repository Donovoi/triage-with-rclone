//! Real CLI regressions with the embedded runtime and isolated synthetic sources.
#![cfg(windows)]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine;
use sha2::{Digest, Sha256};

// Deterministic ZIP_STORED fixture, generated independently with Python zipfile:
// sorted names, timestamp (2020, 1, 1, 0, 0, 0), create_system=3,
// external_attr=0o100644 << 16. Payloads and zlib CRC32 values are asserted below.
const ARCHIVE_ZIP: &str = concat!(
    "UEsDBBQAAAAAAAAAIVDbfmxVEQAAABEAAAAVAAAAbmVzdGVkL3NwYWNlIG5hbWUudHh0",
    "U1lOVEhFVElDIE5FU1RFRApQSwMEFAAAAAAAAAAhUEq9JwIPAAAADwAAAAgAAAByb290",
    "LnR4dFNZTlRIRVRJQyBST09UClBLAQIUAxQAAAAAAAAAIVDbfmxVEQAAABEAAAAVAAAA",
    "AAAAAAAAAACkgQAAAABuZXN0ZWQvc3BhY2UgbmFtZS50eHRQSwECFAMUAAAAAAAAACFQ",
    "Sr0nAg8AAAAPAAAACAAAAAAAAAAAAAAApIFEAAAAcm9vdC50eHRQSwUGAAAAAAIAAgB5",
    "AAAAeQAAAAAA"
);

struct Fixture {
    temp: tempfile::TempDir,
    config: PathBuf,
    original: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        for (remote, content) in [("a", "SOURCE A"), ("b", "SOURCE B")] {
            fs::create_dir(temp.path().join(remote)).unwrap();
            fs::write(temp.path().join(remote).join("same.txt"), content).unwrap();
        }
        let original = format!(
            "[RemoteA]\ntype = alias\nremote = {}\n[RemoteB]\ntype = alias\nremote = {}\n[_triage_combined]\ntype = memory\n",
            temp.path().join("a").display(), temp.path().join("b").display()
        );
        let config = temp.path().join("original.conf");
        fs::write(&config, &original).unwrap();
        Self {
            temp,
            config,
            original,
        }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rclone-triage"));
        for (key, _) in std::env::vars_os() {
            if key
                .to_string_lossy()
                .to_ascii_uppercase()
                .starts_with("RCLONE_")
            {
                command.env_remove(key);
            }
        }
        command
            .current_dir(self.temp.path())
            .env("TEMP", self.temp.path())
            .env("TMP", self.temp.path())
            .arg("--name")
            .arg("review-case")
            .arg("--output-dir")
            .arg(self.temp.path().join("output"));
        command
    }
    fn archive(bytes: &[u8]) -> Self {
        let mut fixture = Self::new();
        let source = fixture.temp.path().join("synthetic.zip");
        fs::write(&source, bytes).unwrap();
        // The pinned archive backend requires slash-separated upstream paths.
        fixture.original = format!(
            "[Archive]\ntype = archive\nremote = {}\n",
            source.to_string_lossy().replace('\\', "/")
        );
        fs::write(&fixture.config, &fixture.original).unwrap();
        fixture
    }
    fn assert_archive_preserved(&self, expected: &[u8]) {
        assert_eq!(
            fs::read(self.temp.path().join("synthetic.zip")).unwrap(),
            expected
        );
        assert_eq!(fs::read_to_string(&self.config).unwrap(), self.original);
    }
    fn acquire(&self, csv: &str) -> Output {
        let queue = self.temp.path().join("queue.csv");
        fs::write(&queue, csv).unwrap();
        self.command()
            .arg("--download")
            .arg(queue)
            .arg("--rclone-config-path")
            .arg(&self.config)
            .output()
            .unwrap()
    }
    fn manifest(&self) -> serde_json::Value {
        let path = files(&self.temp.path().join("output"))
            .into_iter()
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("acquisition-")
                    && path.extension().is_some_and(|ext| ext == "json")
                    && !path.to_string_lossy().contains("checkpoint")
            })
            .unwrap();
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }
}
fn files(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            if entry.file_type().unwrap().is_dir() {
                result.extend(files(&entry.path()));
            } else {
                result.push(entry.path());
            }
        }
    }
    result
}

fn listing_command(fixture: &Fixture, remote: &str) -> Command {
    let mut command = fixture.command();
    command
        .arg("--list-remote")
        .arg(remote)
        .arg("--rclone-config-path")
        .arg(&fixture.config);
    command
}

fn listing_path(fixture: &Fixture) -> PathBuf {
    fixture
        .temp
        .path()
        .join("output/review-case/listings/inventory.csv")
}

fn read_listing(path: &Path) -> Vec<csv::StringRecord> {
    let bytes = fs::read(path).unwrap();
    assert!(bytes.starts_with(&[0xef, 0xbb, 0xbf]));
    let mut reader = csv::Reader::from_reader(&bytes[3..]);
    assert_eq!(
        reader.headers().unwrap(),
        &csv::StringRecord::from(vec![
            "path_encoding",
            "remote",
            "path",
            "size",
            "modified",
            "is_dir",
            "hash",
            "hash_type",
        ])
    );
    reader.records().map(Result::unwrap).collect()
}

fn assert_no_published_listing(fixture: &Fixture) {
    assert!(!listing_path(fixture).exists());
    assert!(files(&fixture.temp.path().join("output/review-case/listings")).is_empty());
}

#[test]
fn cli_imported_listing_is_complete_recursive_and_preserves_exact_provenance() {
    let fixture = Fixture::new();
    let source = fixture.temp.path().join("a");
    fs::create_dir(source.join("nested")).unwrap();
    let payloads: &[(&str, &[u8])] = &[
        ("same.txt", b"SOURCE A"),
        ("nested/empty.bin", b""),
        ("nested/space name.txt", b"NESTED SYNTHETIC\n"),
        ("=formula.txt", b"SYNTHETIC FORMULA NAME\n"),
    ];
    for (path, bytes) in payloads {
        fs::write(source.join(path), bytes).unwrap();
    }
    let output = listing_command(&fixture, "RemoteA").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = read_listing(&listing_path(&fixture));
    let mut expected = std::collections::BTreeMap::new();
    expected.insert("nested".to_owned(), None);
    for (path, bytes) in payloads {
        let exported = if path.starts_with('=') {
            format!("'{path}")
        } else {
            (*path).to_owned()
        };
        expected.insert(exported, Some(bytes.len()));
    }
    assert_eq!(rows.len(), expected.len());
    for row in rows {
        assert_eq!(&row[0], "excel-safe-v1");
        assert_eq!(&row[1], "RemoteA");
        assert_eq!(&row[6], "");
        assert_eq!(&row[7], "");
        match expected
            .remove(&row[2])
            .expect("unexpected or duplicate path")
        {
            Some(size) => {
                assert_eq!(row[3].parse::<usize>().unwrap(), size);
                assert_eq!(&row[5], "false");
            }
            None => assert_eq!(&row[5], "true"),
        }
    }
    assert!(expected.is_empty());
    for (path, bytes) in payloads {
        assert_eq!(fs::read(source.join(path)).unwrap(), *bytes);
    }
    assert_eq!(
        fs::read_to_string(&fixture.config).unwrap(),
        fixture.original
    );
    let config_files = files(&fixture.temp.path().join("output/review-case/config"));
    let snapshots: Vec<_> = config_files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "conf"))
        .collect();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(fs::read_to_string(snapshots[0]).unwrap(), fixture.original);
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(snapshots[0].with_extension("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(
        provenance["source_sha256"],
        hex::encode(Sha256::digest(fixture.original.as_bytes()))
    );
    assert_eq!(
        fs::canonicalize(provenance["working_path"].as_str().unwrap()).unwrap(),
        fs::canonicalize(snapshots[0]).unwrap()
    );
    assert!(files(&fixture.temp.path().join("output/review-case/downloads")).is_empty());
    assert_eq!(
        files(&fixture.temp.path().join("output/review-case/listings")),
        vec![listing_path(&fixture)]
    );
}

#[test]
fn cli_imported_listing_streams_complete_bounded_large_inventory() {
    const FILES: usize = 512;
    let fixture = Fixture::new();
    let source = fixture.temp.path().join("a");
    fs::remove_file(source.join("same.txt")).unwrap();
    fs::create_dir(source.join("many")).unwrap();
    for index in 0..FILES {
        fs::write(
            source.join(format!("many/file-{index:04}.txt")),
            b"SYNTHETIC",
        )
        .unwrap();
    }
    let output = listing_command(&fixture, "RemoteA").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = read_listing(&listing_path(&fixture));
    assert_eq!(rows.len(), FILES + 1);
    let mut expected: std::collections::BTreeSet<_> = (0..FILES)
        .map(|i| format!("many/file-{i:04}.txt"))
        .collect();
    let mut directories = 0;
    for row in rows {
        assert_eq!(&row[1], "RemoteA");
        if &row[5] == "true" {
            assert_eq!(&row[2], "many");
            directories += 1;
        } else {
            assert!(expected.remove(&row[2]), "unexpected or repeated path");
            assert_eq!(&row[3], "9");
        }
    }
    assert_eq!(directories, 1);
    assert!(expected.is_empty());
    assert_eq!(
        fs::read_to_string(&fixture.config).unwrap(),
        fixture.original
    );
}

#[test]
fn cli_imported_listing_publishes_at_long_windows_path_without_clobber() {
    let fixture = Fixture::new();
    let mut parent = fixture.temp.path().join("long-output");
    while parent.as_os_str().to_string_lossy().len() < 280 {
        parent = parent.join("synthetic-parent-component-0123456789");
    }
    // Use the public, unprefixed path. The application must canonicalize the
    // existing listings parent for tempfile's direct Win32 no-replace rename.
    let mut command = Command::new(env!("CARGO_BIN_EXE_rclone-triage"));
    command
        .current_dir(fixture.temp.path())
        .env("TEMP", fixture.temp.path())
        .env("TMP", fixture.temp.path())
        .args([
            "--name",
            "long-case",
            "--list-remote",
            "RemoteA",
            "--rclone-config-path",
        ])
        .arg(&fixture.config)
        .arg("--output-dir")
        .arg(&parent);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listing = parent.join("long-case/listings/inventory.csv");
    let rows = read_listing(&listing);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (&rows[0][1], &rows[0][2], &rows[0][3]),
        ("RemoteA", "same.txt", "8")
    );
    let before = fs::read(&listing).unwrap();
    let second = command.output().unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("requires a new case directory"));
    assert_eq!(fs::read(&listing).unwrap(), before);
    assert_eq!(files(listing.parent().unwrap()), vec![listing]);
    assert_eq!(
        fs::read_to_string(&fixture.config).unwrap(),
        fixture.original
    );
}

#[test]
fn cli_imported_listing_empty_remote_publishes_explicit_empty_csv_schema() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.temp.path().join("a/same.txt")).unwrap();
    let output = listing_command(&fixture, "RemoteA").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(read_listing(&listing_path(&fixture)).is_empty());
    assert_eq!(
        fs::read_to_string(&fixture.config).unwrap(),
        fixture.original
    );
}

#[test]
fn cli_imported_listing_ignores_inherited_config_and_backend_overrides() {
    let fixture = Fixture::new();
    fs::write(fixture.temp.path().join("b/foreign.txt"), b"FOREIGN").unwrap();
    let output = listing_command(&fixture, "RemoteA")
        .env("RCLONE_CONFIG", fixture.temp.path().join("missing.conf"))
        .env(
            "RCLONE_CONFIG_REMOTEA_REMOTE",
            fixture.temp.path().join("b"),
        )
        .env("RCLONE_CONFIG_REMOTEA_TYPE", "memory")
        .env("RCLONE_DRY_RUN", "true")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = read_listing(&listing_path(&fixture));
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (&rows[0][1], &rows[0][2], &rows[0][3]),
        ("RemoteA", "same.txt", "8")
    );
    assert_eq!(
        fs::read_to_string(&fixture.config).unwrap(),
        fixture.original
    );
}

#[test]
fn cli_imported_listing_refuses_unknown_ambiguous_or_typeless_sections() {
    for (config, requested, reason) in [
        ("[Other]\ntype = invalid-synthetic-backend\n", "RemoteA", "unknown or ambiguous"),
        ("[RemoteA]\ntype = invalid-synthetic-backend\n[RemoteA]\ntype = invalid-synthetic-backend\n", "RemoteA", "unknown or ambiguous"),
        ("[RemoteA]\ntype = invalid-synthetic-backend\n[remotea]\ntype = invalid-synthetic-backend\n", "RemoteA", "unknown or ambiguous"),
        ("[RemoteA]\ntype = invalid-synthetic-backend\n", "remotea", "unknown or ambiguous"),
        ("[RemoteA]\nremote = synthetic\n", "RemoteA", "no backend type"),
    ] {
        let fixture = Fixture::new();
        fs::write(&fixture.config, config).unwrap();
        let output = listing_command(&fixture, requested).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(reason));
        assert_no_published_listing(&fixture);
        assert_eq!(fs::read_to_string(&fixture.config).unwrap(), config);
    }
}

#[test]
fn cli_imported_listing_refuses_inline_override_even_when_literal_section_exists() {
    let fixture = Fixture::new();
    // There is a real base remote and a different literal section. Passing this
    // selector to rclone would instead parse RemoteA plus an alias-root override.
    let config = format!(
        "{}\n[RemoteA,remote=other]\ntype = alias\nremote = {}\n",
        fixture.original,
        fixture.temp.path().join("b").display()
    );
    fs::write(&fixture.config, &config).unwrap();
    fs::create_dir(fixture.temp.path().join("other")).unwrap();
    fs::write(
        fixture.temp.path().join("other/foreign.txt"),
        b"FOREIGN ROOT",
    )
    .unwrap();
    let output = listing_command(&fixture, "RemoteA,remote=other")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2)); // Clap rejects before extraction/remote reads.
    assert!(String::from_utf8_lossy(&output.stderr).contains("without a path or inline options"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Case initialized"));
    assert!(!fixture.temp.path().join("output").exists());
    assert_eq!(fs::read_to_string(&fixture.config).unwrap(), config);
    assert_eq!(
        fs::read(fixture.temp.path().join("a/same.txt")).unwrap(),
        b"SOURCE A"
    );
    assert_eq!(
        fs::read(fixture.temp.path().join("b/same.txt")).unwrap(),
        b"SOURCE B"
    );
    assert_eq!(
        fs::read(fixture.temp.path().join("other/foreign.txt")).unwrap(),
        b"FOREIGN ROOT"
    );
}

#[test]
fn cli_imported_listing_remote_failure_never_publishes_a_partial_inventory() {
    let fixture = Fixture::new();
    let config = format!(
        "[MissingRoot]\ntype = alias\nremote = {}\n",
        fixture.temp.path().join("absent-source").display()
    );
    fs::write(&fixture.config, &config).unwrap();
    let output = listing_command(&fixture, "MissingRoot").output().unwrap();
    assert!(!output.status.success());
    assert_no_published_listing(&fixture);
    assert_eq!(fs::read_to_string(&fixture.config).unwrap(), config);
}

#[test]
fn cli_imported_listing_requires_a_fresh_case_and_preserves_existing_outputs() {
    let fixture = Fixture::new();
    let path = listing_path(&fixture);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"PRIOR SYNTHETIC INVENTORY").unwrap();
    let output = listing_command(&fixture, "RemoteA").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires a new case directory"));
    assert_eq!(fs::read(path).unwrap(), b"PRIOR SYNTHETIC INVENTORY");
    assert_eq!(
        fs::read_to_string(&fixture.config).unwrap(),
        fixture.original
    );
}

#[test]
fn cli_imported_listing_missing_input_and_invalid_output_fail_without_publication() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.config).unwrap();
    let output = listing_command(&fixture, "RemoteA").output().unwrap();
    assert!(!output.status.success());
    assert_no_published_listing(&fixture);
    assert!(!fixture.config.exists());

    let fixture = Fixture::new();
    fs::write(fixture.temp.path().join("output"), b"OUTPUT SENTINEL").unwrap();
    let output = listing_command(&fixture, "RemoteA").output().unwrap();
    assert!(!output.status.success());
    assert_no_published_listing(&fixture);
    assert_eq!(
        fs::read(fixture.temp.path().join("output")).unwrap(),
        b"OUTPUT SENTINEL"
    );
    assert_eq!(
        fs::read_to_string(&fixture.config).unwrap(),
        fixture.original
    );
}

#[test]
fn cli_preserves_remote_identity_and_original_config() {
    let fixture = Fixture::new();
    let output = fixture.acquire("Path,Remote,Size\nsame.txt,RemoteA,8\nsame.txt,RemoteB,8\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest = fixture.manifest();
    assert_eq!(manifest["complete"], true);
    let results = manifest["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    for (result, expected) in results.iter().zip(["SOURCE A", "SOURCE B"]) {
        assert_eq!(
            fs::read_to_string(result["destination"].as_str().unwrap()).unwrap(),
            expected
        );
        assert_eq!(result["local_sha256"].as_str().unwrap().len(), 64);
    }
    assert_eq!(
        fs::read_to_string(&fixture.config).unwrap(),
        fixture.original
    );
}

#[test]
fn cli_rejects_traversal_before_transfer() {
    let fixture = Fixture::new();
    fs::write(fixture.temp.path().join("outside.txt"), "SYNTHETIC OUTSIDE").unwrap();
    let output = fixture.acquire("Path,Remote\n../outside.txt,RemoteA\n");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unsafe"));
    assert!(!files(&fixture.temp.path().join("output"))
        .iter()
        .any(|path| path.file_name().unwrap() == "outside.txt"));
}

#[test]
fn cli_uses_snapshot_despite_inherited_remote_and_dry_run_overrides() {
    let fixture = Fixture::new();
    let queue = fixture.temp.path().join("queue.csv");
    fs::write(&queue, "Path,Remote\nsame.txt,RemoteA\n").unwrap();
    let output = fixture
        .command()
        .arg("--download")
        .arg(queue)
        .arg("--rclone-config-path")
        .arg(&fixture.config)
        .env(
            "RCLONE_CONFIG_REMOTEA_REMOTE",
            fixture.temp.path().join("b"),
        )
        .env("RCLONE_DRY_RUN", "true")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest = fixture.manifest();
    let destination = manifest["results"][0]["destination"].as_str().unwrap();
    assert_eq!(fs::read_to_string(destination).unwrap(), "SOURCE A");
}

#[test]
fn cli_hash_mismatch_and_missing_source_are_nonzero_with_manifests() {
    for csv in [
        format!(
            "Path,Remote,Hash,HashType\nsame.txt,RemoteA,{},SHA256\n",
            "0".repeat(64)
        ),
        "Path,Remote\nmissing.txt,RemoteA\n".into(),
    ] {
        let fixture = Fixture::new();
        let output = fixture.acquire(&csv);
        assert!(!output.status.success());
        let manifest = fixture.manifest();
        assert_eq!(manifest["complete"], false);
        assert_eq!(manifest["results"][0]["success"], false);
    }
}

#[test]
fn cli_archive_acquires_exact_members_with_crc32_and_independent_sha256() {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ARCHIVE_ZIP)
        .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "daf25c00640824774c0c187071029a4cd33a4c940ab1335e78416facbfd9cea5"
    );
    let fixture = Fixture::archive(&bytes);
    let output = fixture.acquire(concat!(
        "Path,Remote,Size,Hash,HashType\n",
        "root.txt,Archive,15,0227bd4a,CRC32\n",
        "nested/space name.txt,Archive,17,556c7edb,CRC32\n"
    ));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest = fixture.manifest();
    assert_eq!(manifest["complete"], true);
    let results = manifest["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    for (source, expected) in [
        ("Archive:root.txt", b"SYNTHETIC ROOT\n".as_slice()),
        (
            "Archive:nested/space name.txt",
            b"SYNTHETIC NESTED\n".as_slice(),
        ),
    ] {
        let result = results
            .iter()
            .find(|result| result["source"] == source)
            .unwrap();
        let acquired = fs::read(result["destination"].as_str().unwrap()).unwrap();
        assert_eq!(acquired, expected);
        assert_eq!(
            result["local_sha256"],
            hex::encode(Sha256::digest(expected))
        );
        assert_eq!(result["success"], true);
        assert_eq!(result["hash_type"], "CRC32");
        assert_eq!(result["hash_verified"], true);
        assert_eq!(result["integrity"], "Verified");
    }
    fixture.assert_archive_preserved(&bytes);
}

#[test]
fn cli_archive_rejects_missing_directory_corrupt_and_truncated_sources() {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ARCHIVE_ZIP)
        .unwrap();
    let mut corrupt = bytes.clone();
    let payload_offset = corrupt
        .windows(b"SYNTHETIC ROOT".len())
        .position(|part| part == b"SYNTHETIC ROOT")
        .unwrap();
    corrupt[payload_offset] ^= 1; // Keep the original central-directory CRC32.
    let truncated = bytes[..bytes.len() - 22].to_vec(); // Remove the ZIP end record.
    for (source, csv, expected_error) in [
        (
            &bytes,
            "Path,Remote\nmissing.txt,Archive\n",
            "Source was not found",
        ),
        (
            &bytes,
            "Path,Remote\nnested,Archive\n",
            "is not a regular file",
        ),
        (
            &corrupt,
            "Path,Remote,Size,Hash,HashType\nroot.txt,Archive,15,0227bd4a,CRC32\n",
            "zip: checksum error",
        ),
        (
            &truncated,
            "Path,Remote\nroot.txt,Archive\n",
            "zip: not a valid zip file",
        ),
    ] {
        let fixture = Fixture::archive(source);
        let output = fixture.acquire(csv);
        assert!(!output.status.success());
        let manifest = fixture.manifest();
        assert_eq!(manifest["complete"], false);
        let results = manifest["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["success"], false);
        assert!(results[0]["error"]
            .as_str()
            .unwrap()
            .contains(expected_error));
        assert!(!Path::new(results[0]["destination"].as_str().unwrap()).exists());
        assert!(!files(&fixture.temp.path().join("output"))
            .iter()
            .any(|path| path.file_name().unwrap() == "space name.txt"));
        fixture.assert_archive_preserved(source);
    }
}

#[test]
fn diagnostics_remove_canary_secrets_before_archiving() {
    let fixture = Fixture::new();
    let source = fixture.temp.path().join("output/review-case/config");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("rclone.conf"),
        "[canary]\ntype = s3\nunknown_key = CANARY-CONFIG-SECRET\n",
    )
    .unwrap();
    let output = fixture
        .command()
        .arg("--collect-logs")
        .env(
            "RCLONE_CONFIG_CANARY_SECRET_ACCESS_KEY",
            "CANARY-ENV-SECRET",
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let archive = files(&fixture.temp.path().join("output"))
        .into_iter()
        .find(|path| path.to_string_lossy().ends_with(".tar.gz"))
        .unwrap();
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(
        fs::File::open(archive).unwrap(),
    ));
    let mut combined = String::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.header().entry_type().is_file() {
            entry.read_to_string(&mut combined).unwrap();
        }
    }
    assert!(combined.contains("REDACTED"));
    assert!(!combined.contains("CANARY-ENV-SECRET"));
    assert!(!combined.contains("CANARY-CONFIG-SECRET"));
    assert!(fs::read_to_string(source.join("rclone.conf"))
        .unwrap()
        .contains("CANARY-CONFIG-SECRET"));
}
