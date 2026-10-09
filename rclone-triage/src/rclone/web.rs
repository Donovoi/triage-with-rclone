//! Owned rclone Web GUI process and runtime lifetime.

use crate::embedded::ExtractedBinary;
use crate::rclone::process::{ManagedChild, RcloneRunner, STOP_TIMEOUT};
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub struct WebGuiProcess {
    child: ManagedChild,
    runtime: Option<ExtractedBinary>,
    finished: Option<ExitStatus>,
    failed: bool,
}
impl WebGuiProcess {
    fn retain(&mut self) {
        self.failed = true;
        self.child.retain();
        if let Some(runtime) = self.runtime.as_mut() {
            runtime.retain();
        }
    }
    fn finalize(&mut self) -> Result<ExitStatus> {
        if self.failed {
            bail!("Earlier Web GUI shutdown failed; runtime retained");
        }
        if let Some(status) = self.finished {
            return Ok(status);
        }
        let result = (|| {
            let status = self
                .child
                .finish()
                .context("Web GUI child finalization failed")?;
            if let Some(runtime) = self.runtime.as_mut() {
                runtime.cleanup()?;
            }
            Ok(status)
        })();
        match result {
            Ok(status) => {
                self.finished = Some(status);
                Ok(status)
            }
            Err(error) => {
                self.retain();
                Err(error)
            }
        }
    }
    pub fn stop(&mut self) -> Result<()> {
        if self.failed {
            bail!("Earlier Web GUI shutdown failed; runtime retained");
        }
        if self.finished.is_some() {
            return Ok(());
        }
        if let Err(error) = self.child.stop_and_reap(STOP_TIMEOUT) {
            self.retain();
            return Err(error).context("Web GUI child shutdown failed");
        }
        self.finalize().map(|_| ())
    }
    pub fn wait(&mut self) -> Result<ExitStatus> {
        if self.failed {
            bail!("Earlier Web GUI shutdown failed; runtime retained");
        }
        if let Some(status) = self.finished {
            return Ok(status);
        }
        if let Err(error) = self.child.wait() {
            self.retain();
            return Err(error).context("Web GUI wait failed");
        }
        self.finalize()
    }
    pub fn wait_cancellable(&mut self, cancel: &Arc<AtomicBool>) -> Result<ExitStatus> {
        loop {
            if cancel.load(Ordering::Relaxed) {
                self.stop()?;
                return self.finished.context("Web GUI exit was not confirmed");
            }
            match self.child.try_wait() {
                Ok(Some(_)) => return self.finalize(),
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(error) => {
                    self.retain();
                    return Err(error).context("Web GUI wait failed");
                }
            }
        }
    }
}
impl Drop for WebGuiProcess {
    fn drop(&mut self) {
        if !self.failed && self.finished.is_none() {
            let _ = self.stop();
        }
    }
}
fn start(
    binary: &ExtractedBinary,
    config: Option<&Path>,
    port: u16,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<ManagedChild> {
    let runner = RcloneRunner::from_extracted(binary);
    let mut cmd = Command::new(binary.path());
    cmd.arg("rcd")
        .arg("--rc-web-gui")
        .arg("--rc-addr")
        .arg(format!("127.0.0.1:{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    if let Some(config) = config {
        crate::rclone::process::isolate_rclone_environment(&mut cmd);
        cmd.arg("--config").arg(config);
    }
    if let Some(user) = user {
        cmd.arg("--rc-user").arg(user);
    }
    if let Some(pass) = pass {
        cmd.arg("--rc-pass").arg(pass);
    }
    runner.spawn_command(&mut cmd)
}
/// Borrow the CLI's outer owner; the child still holds its tracked runtime lease.
pub fn start_web_gui(
    binary: &ExtractedBinary,
    config: Option<&Path>,
    port: u16,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<WebGuiProcess> {
    Ok(WebGuiProcess {
        child: start(binary, config, port, user, pass)?,
        runtime: None,
        finished: None,
        failed: false,
    })
}
/// The TUI service retains its runtime until explicit, confirmed shutdown.
pub fn start_web_gui_owned(
    mut binary: ExtractedBinary,
    config: Option<&Path>,
    port: u16,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<WebGuiProcess> {
    match start(&binary, config, port, user, pass) {
        Ok(child) => Ok(WebGuiProcess {
            child,
            runtime: Some(binary),
            finished: None,
            failed: false,
        }),
        Err(error) => match binary.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "Web GUI startup runtime cleanup also failed: {cleanup}"
            ))),
        },
    }
}
