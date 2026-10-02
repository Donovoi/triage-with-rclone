//! Real CLI regressions with the embedded runtime and isolated synthetic sources.
#![cfg(windows)]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
        .env("RCLONE_CONFIG_REMOTEA_REMOTE", fixture.temp.path().join("b"))
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
