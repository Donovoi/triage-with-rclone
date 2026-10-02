//! rclone Web GUI helper

use anyhow::Result;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Running rclone web GUI process
pub struct WebGuiProcess {
    child: Child,
}

impl WebGuiProcess {
    /// Stop the web GUI process
    pub fn stop(&mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        Ok(())
    }

    /// Wait for the web GUI process to exit
    pub fn wait(&mut self) -> Result<std::process::ExitStatus> {
        Ok(self.child.wait()?)
    }

    pub fn wait_cancellable(
        &mut self,
        cancel: &Arc<AtomicBool>,
    ) -> Result<std::process::ExitStatus> {
        loop {
            if cancel.load(Ordering::Relaxed) {
                let _ = self.child.kill();
            }
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

impl Drop for WebGuiProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start rclone Web GUI (`rclone rcd --rc-web-gui`).
pub fn start_web_gui(
    rclone_path: impl AsRef<Path>,
    config_path: Option<&Path>,
    port: u16,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<WebGuiProcess> {
    let mut cmd = Command::new(rclone_path.as_ref());
    cmd.arg("rcd")
        .arg("--rc-web-gui")
        .arg("--rc-addr")
        .arg(format!("127.0.0.1:{}", port))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    if let Some(config) = config_path {
        crate::rclone::process::isolate_rclone_environment(&mut cmd);
        cmd.arg("--config").arg(config);
    }
    if let Some(user) = user {
        cmd.arg("--rc-user").arg(user);
    }
    if let Some(pass) = pass {
        cmd.arg("--rc-pass").arg(pass);
    }

    let child = cmd.spawn()?;
    Ok(WebGuiProcess { child })
}
