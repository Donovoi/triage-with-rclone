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

/// Mount manager for handling multiple mounts
pub struct MountManager {
    /// Path to rclone executable
    rclone_path: PathBuf,
    /// Path to rclone config file
    config_path: Option<PathBuf>,
    /// Base directory for mount points
    mount_base: PathBuf,
}

impl MountManager {
    /// Create a new mount manager
    pub fn new(rclone_path: impl AsRef<Path>) -> Result<Self> {
        let mount_base = Self::default_mount_base()?;

        // Ensure mount base exists
        std::fs::create_dir_all(&mount_base)
            .with_context(|| format!("Failed to create mount directory: {:?}", mount_base))?;

        Ok(Self {
            rclone_path: rclone_path.as_ref().to_path_buf(),
            config_path: None,
            mount_base,
        })
    }

    /// Set the rclone config file path
    pub fn with_config(mut self, config_path: impl AsRef<Path>) -> Self {
        self.config_path = Some(config_path.as_ref().to_path_buf());
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

    /// Mount a remote and return the mount handle
    pub fn mount(&self, remote: &str, subfolder: Option<&str>) -> Result<MountedRemote> {
        // Check FUSE availability
        if !self.check_fuse_available()? {
            bail!(
                "FUSE is not available. Please install:\n\
                - Windows: WinFsp (https://winfsp.dev/)\n\
                - Linux: fuse or fuse3\n\
                - macOS: macFUSE (https://osxfuse.github.io/)"
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
