//! rclone Web GUI helper

use anyhow::Result;
use std::path::Path;
use std::process::{Child, Command, Stdio};

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
