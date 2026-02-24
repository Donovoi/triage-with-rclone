//! Rclone mount functionality
//!
//! Mounts cloud storage remotes as local file systems and opens file explorer.
//! Supports Windows (via WinFsp), Linux (via FUSE), and macOS (via macFUSE).

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Windows-specific: CREATE_NO_WINDOW flag
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// A mounted rclone remote
pub struct MountedRemote {
    /// The rclone process handle
    process: Child,
    /// Mount point path
    mount_point: PathBuf,
    /// Remote name (e.g., "gdrive:")
    remote: String,
    /// Whether the mount is active
    active: Arc<AtomicBool>,
}

impl MountedRemote {
    /// Get the mount point path
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    /// Get the remote name
    pub fn remote(&self) -> &str {
        &self.remote
    }

    /// Check if the mount is still active
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Unmount and cleanup
    pub fn unmount(mut self) -> Result<()> {
        self.active.store(false, Ordering::SeqCst);

        // Kill the rclone process
        let _ = self.process.kill();
        let _ = self.process.wait();

        // On Windows, we may need to use fusermount or just wait
        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("fusermount")
                .args(["-u", self.mount_point.to_str().unwrap_or("")])
                .output();
        }

        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("umount").arg(&self.mount_point).output();
        }

        // Clean up mount point directory if empty
        if self.mount_point.exists() {
            let _ = std::fs::remove_dir(&self.mount_point);
        }

        Ok(())
    }
}

impl Drop for MountedRemote {
    fn drop(&mut self) {
        self.active.store(false, Ordering::SeqCst);
        let _ = self.process.kill();
    }
}

/// Download the latest WinFSP MSI from GitHub and install it silently.
/// Uses `ureq` (already a project dependency) for HTTP and `msiexec` for installation.
/// Returns `Ok(true)` if the MSI was downloaded and msiexec exited successfully.
#[cfg(windows)]
fn download_and_install_winfsp() -> Result<bool> {
    use std::io::Write;

    // 1. Query the GitHub releases API for the latest tag.
    let api_url = "https://api.github.com/repos/winfsp/winfsp/releases/latest";
    let response = ureq::get(api_url)
        .set("User-Agent", "rclone-triage")
        .set("Accept", "application/vnd.github+json")
        .call()?;
    let release: serde_json::Value = response.into_json()?;

    // 2. Find the .msi asset URL from the release assets.
    let msi_url = release["assets"]
        .as_array()
        .and_then(|assets| {
            assets.iter().find_map(|asset| {
                let name = asset["name"].as_str().unwrap_or("");
                if name.ends_with(".msi") {
                    asset["browser_download_url"].as_str().map(String::from)
                } else {
                    None
                }
            })
        })
        .or_else(|| {
            // Fallback: construct URL from tag name.
            let tag = release["tag_name"].as_str()?;
            let version = tag.strip_prefix('v').unwrap_or(tag);
            Some(format!(
                "https://github.com/winfsp/winfsp/releases/download/{}/winfsp-{}.msi",
                tag, version
            ))
        });

    let Some(msi_url) = msi_url else {
        bail!("Could not determine WinFSP MSI download URL from GitHub releases");
    };

    // 3. Download the MSI to a temp file.
    let tmp_dir = std::env::temp_dir();
    let msi_path = tmp_dir.join("winfsp-latest.msi");

    let dl_response = ureq::get(&msi_url)
        .set("User-Agent", "rclone-triage")
        .call()?;
    let mut body = dl_response.into_reader();
    let mut file = std::fs::File::create(&msi_path)?;
    std::io::copy(&mut body, &mut file)?;
    file.flush()?;
    drop(file);

    // 4. Run msiexec silently.
    let status = Command::new("msiexec")
        .args(["/i", &msi_path.to_string_lossy(), "/qn", "/norestart"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status();

    // 5. Clean up the MSI.
    let _ = std::fs::remove_file(&msi_path);

    Ok(status.is_ok_and(|s| s.success()))
}

/// Mount manager for handling multiple mounts
pub struct MountManager {
    /// Path to rclone executable
    rclone_path: PathBuf,
    /// Path to rclone config file
    config_path: Option<PathBuf>,
    /// rclone cache directory (for VFS cache, etc.)
    cache_dir: Option<PathBuf>,
    /// Base directory for mount points
    mount_base: PathBuf,
}

impl MountManager {
    /// Create a new mount manager
    pub fn new(rclone_path: impl AsRef<Path>) -> Result<Self> {
        let mount_base = Self::default_mount_base()?;

        Ok(Self {
            rclone_path: rclone_path.as_ref().to_path_buf(),
            config_path: None,
            cache_dir: None,
            mount_base,
        })
    }

    /// Set the rclone config file path
    pub fn with_config(mut self, config_path: impl AsRef<Path>) -> Self {
        self.config_path = Some(config_path.as_ref().to_path_buf());
        self
    }

    /// Set custom rclone cache directory (e.g., inside a case folder).
    pub fn with_cache_dir(mut self, cache_dir: impl AsRef<Path>) -> Self {
        self.cache_dir = Some(cache_dir.as_ref().to_path_buf());
        self
    }

    /// Set custom mount base directory
    pub fn with_mount_base(mut self, mount_base: impl AsRef<Path>) -> Self {
        self.mount_base = mount_base.as_ref().to_path_buf();
        self
    }

    /// Get the default mount base directory
    fn default_mount_base() -> Result<PathBuf> {
        #[cfg(windows)]
        {
            // On Windows, use a directory in temp or user profile
            // Note: WinFsp can also mount as drive letters like X:
            Ok(dirs::data_local_dir()
                .context("Could not find local data directory")?
                .join("rclone-triage")
                .join("mounts"))
        }

        #[cfg(target_os = "linux")]
        {
            // On Linux, use ~/mnt or /tmp/rclone-mounts
            Ok(dirs::home_dir()
                .context("Could not find home directory")?
                .join("mnt")
                .join("rclone-triage"))
        }

        #[cfg(target_os = "macos")]
        {
            // On macOS, use ~/mnt or /Volumes
            Ok(dirs::home_dir()
                .context("Could not find home directory")?
                .join("mnt")
                .join("rclone-triage"))
        }
    }

    /// Check if FUSE/WinFsp is available
    pub fn check_fuse_available(&self) -> Result<bool> {
        #[cfg(windows)]
        {
            // Check for WinFsp
            let winfsp_path = PathBuf::from(r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll");
            let winfsp_path_alt = PathBuf::from(r"C:\Program Files\WinFsp\bin\winfsp-x64.dll");
            Ok(winfsp_path.exists() || winfsp_path_alt.exists())
        }

        #[cfg(target_os = "linux")]
        {
            // Check for FUSE
            Ok(PathBuf::from("/dev/fuse").exists())
        }

        #[cfg(target_os = "macos")]
        {
            // Check for macFUSE
            let macfuse = PathBuf::from("/Library/Filesystems/macfuse.fs");
            let osxfuse = PathBuf::from("/Library/Filesystems/osxfuse.fs");
            Ok(macfuse.exists() || osxfuse.exists())
        }
    }

    /// Attempt to install FUSE/WinFSP automatically and return whether installation succeeded.
    pub fn install_fuse(&self) -> Result<bool> {
        #[cfg(windows)]
        {
            // Strategy 1: winget (built into Windows 10 1709+ / Windows 11).
            let winget_ok = Command::new("winget")
                .args(["install", "--id", "WinFsp.WinFsp", "-e",
                       "--accept-source-agreements", "--accept-package-agreements"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::null())
                .output()
                .is_ok_and(|o| o.status.success());

            if winget_ok {
                std::thread::sleep(Duration::from_secs(2));
                if self.check_fuse_available().unwrap_or(false) {
                    return Ok(true);
                }
            }

            // Strategy 2: Pure Rust — download the MSI from GitHub releases via ureq,
            // write to a temp file, and run msiexec silently.
            if let Ok(true) = download_and_install_winfsp() {
                std::thread::sleep(Duration::from_secs(2));
                if self.check_fuse_available().unwrap_or(false) {
                    return Ok(true);
                }
            }

            Ok(false)
        }

        #[cfg(target_os = "linux")]
        {
            // Try installing fuse3 (Debian/Ubuntu/Fedora/Arch).
            let strategies: &[(&str, &[&str])] = &[
                ("sudo", &["apt-get", "install", "-y", "fuse3"]),
                ("pkexec", &["apt-get", "install", "-y", "fuse3"]),
                ("sudo", &["dnf", "install", "-y", "fuse3"]),
                ("sudo", &["pacman", "-S", "--noconfirm", "fuse3"]),
            ];

            for (cmd, args) in strategies {
                let installed = Command::new(cmd)
                    .args(*args)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .stdin(Stdio::null())
                    .output()
                    .is_ok_and(|o| o.status.success());

                if installed && self.check_fuse_available().unwrap_or(false) {
                    return Ok(true);
                }
            }

            Ok(false)
        }

        #[cfg(target_os = "macos")]
        {
            // Try Homebrew.
            let installed = Command::new("brew")
                .args(["install", "--cask", "macfuse"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::null())
                .output()
                .is_ok_and(|o| o.status.success());

            if installed && self.check_fuse_available().unwrap_or(false) {
                return Ok(true);
            }

            Ok(false)
        }
    }

    /// Check for FUSE and auto-install if missing. Returns true if FUSE is available.
    pub fn ensure_fuse_available(&self) -> Result<bool> {
        if self.check_fuse_available()? {
            return Ok(true);
        }
        self.install_fuse()
    }

    /// Mount a remote and return the mount handle
    pub fn mount(&self, remote: &str, subfolder: Option<&str>) -> Result<MountedRemote> {
        // Check FUSE availability, auto-install if missing
        if !self.ensure_fuse_available()? {
            bail!(
                "FUSE is not available and auto-install failed. Please install manually:\n\
                - Windows: winget install WinFsp.WinFsp\n\
                - Linux: sudo apt install fuse3\n\
                - macOS: brew install --cask macfuse"
            );
        }

        // Build remote path (e.g., "gdrive:" or "gdrive:subfolder")
        let remote_path = match subfolder {
            Some(folder) => format!("{}:{}", remote.trim_end_matches(':'), folder),
            None => format!("{}:", remote.trim_end_matches(':')),
        };

        // Create mount point directory
        let safe_name = remote
            .trim_end_matches(':')
            .replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        let mount_point = self.mount_base.join(&safe_name);

        std::fs::create_dir_all(&mount_point)
            .with_context(|| format!("Failed to create mount point: {:?}", mount_point))?;

        // Build rclone mount command
        let mut cmd = Command::new(&self.rclone_path);

        if let Some(ref config) = self.config_path {
            cmd.arg("--config").arg(config);
        }

        if let Some(ref cache_dir) = self.cache_dir {
            std::fs::create_dir_all(cache_dir)
                .with_context(|| format!("Failed to create cache directory: {:?}", cache_dir))?;
            cmd.arg("--cache-dir").arg(cache_dir);
        }

        cmd.arg("mount")
            .arg(&remote_path)
            .arg(&mount_point)
            // Mount options for better forensic use
            .arg("--read-only") // Read-only for forensic integrity
            .arg("--no-modtime") // Don't update modification times
            .arg("--no-checksum") // Skip checksums for faster browsing
            .arg("--dir-cache-time")
            .arg("30m") // Cache directory listings
            .arg("--vfs-cache-mode")
            .arg("full") // Cache files for better performance
            .arg("--vfs-read-chunk-size")
            .arg("64M") // Larger chunks for streaming
            .arg("--vfs-cache-max-age")
            .arg("1h")
            .arg("--log-level")
            .arg("NOTICE"); // Reduce log verbosity

        // Platform-specific options
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
            // WinFsp options
            cmd.arg("--volname").arg(format!("rclone-{}", safe_name));
        }

        #[cfg(target_os = "linux")]
        {
            cmd.arg("--allow-other"); // Allow other users to access (if configured in fuse.conf)
        }

        cmd.stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Spawn the mount process
        let process = cmd
            .spawn()
            .with_context(|| format!("Failed to start rclone mount for {}", remote))?;

        let active = Arc::new(AtomicBool::new(true));

        // Wait a moment for mount to initialize
        std::thread::sleep(Duration::from_millis(500));

        // Verify mount point is accessible
        let mount_ok = Self::wait_for_mount(&mount_point, Duration::from_secs(10));

        if !mount_ok {
            // Mount failed - try to get error from stderr
            tracing::warn!("Mount point {:?} not accessible after timeout", mount_point);
        }

        Ok(MountedRemote {
            process,
            mount_point,
            remote: remote.to_string(),
            active,
        })
    }

    /// Wait for mount point to become accessible
    fn wait_for_mount(mount_point: &Path, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            // Try to read the directory
            if mount_point.read_dir().is_ok() {
                // Additional check - see if we can actually list contents
                if let Ok(mut entries) = mount_point.read_dir() {
                    // If we get at least one entry or it doesn't error, mount is ready
                    if entries.next().is_some() || mount_point.read_dir().is_ok() {
                        return true;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        // Final check
        mount_point.read_dir().is_ok()
    }

    /// Mount a remote and open file explorer
    pub fn mount_and_explore(
        &self,
        remote: &str,
        subfolder: Option<&str>,
    ) -> Result<MountedRemote> {
        let mounted = self.mount(remote, subfolder)?;

        // Open file explorer
        open_file_explorer(mounted.mount_point())?;

        Ok(mounted)
    }

    /// Get the mount base directory
    pub fn mount_base(&self) -> &Path {
        &self.mount_base
    }
}

/// Open a file explorer window at the given path
pub fn open_file_explorer(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        Command::new("explorer")
            .arg(path)
            .spawn()
            .context("Failed to open Windows Explorer")?;
    }

    #[cfg(target_os = "linux")]
    {
        // Try common file managers in order
        let managers = [
            "xdg-open", "nautilus", "dolphin", "thunar", "pcmanfm", "nemo",
        ];

        let mut opened = false;
        for manager in managers {
            if Command::new(manager).arg(path).spawn().is_ok() {
                opened = true;
                break;
            }
        }

        if !opened {
            bail!("Could not find a file manager. Please install one (nautilus, dolphin, thunar, etc.)");
        }
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(path)
            .spawn()
            .context("Failed to open Finder")?;
    }

    Ok(())
}

/// Open a file explorer window with a specific file selected
#[allow(dead_code)]
pub fn open_file_explorer_select(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        Command::new("explorer")
            .arg("/select,")
            .arg(path)
            .spawn()
            .context("Failed to open Windows Explorer")?;
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .args(["-R", path.to_str().unwrap_or("")])
            .spawn()
            .context("Failed to open Finder")?;
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux, most file managers don't support selecting a file directly
        // Open the parent directory instead
        if let Some(parent) = path.parent() {
            open_file_explorer(parent)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_mount_base() {
        let base = MountManager::default_mount_base();
        assert!(base.is_ok());
        let base = base.unwrap();
        assert!(base.to_str().unwrap().contains("rclone-triage"));
    }

    #[test]
    fn test_safe_remote_name() {
        let remote = "my:remote/with\\special*chars";
        let safe = remote
            .trim_end_matches(':')
            .replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        assert!(!safe.contains('/'));
        assert!(!safe.contains('\\'));
        assert!(!safe.contains(':'));
        assert!(!safe.contains('*'));
    }

    #[test]
    fn test_mount_manager_creation() {
        // Just test that we can create a mount manager
        // Actual mounting requires rclone and FUSE to be installed
        let temp_dir = tempfile::tempdir().unwrap();
        let fake_rclone = temp_dir.path().join("rclone");

        // Create a fake rclone file
        std::fs::write(&fake_rclone, "fake").unwrap();

        let manager = MountManager::new(&fake_rclone);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_check_fuse_available() {
        // This test just checks the function doesn't panic
        let temp_dir = tempfile::tempdir().unwrap();
        let fake_rclone = temp_dir.path().join("rclone");
        std::fs::write(&fake_rclone, "fake").unwrap();

        let manager = MountManager::new(&fake_rclone).unwrap();
        let _result = manager.check_fuse_available();
        // Result depends on system configuration
    }
}
