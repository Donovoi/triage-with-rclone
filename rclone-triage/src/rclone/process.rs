//! Rclone process runner
//!
//! Wraps spawning rclone processes with Windows-specific handling
//! for hiding console windows and capturing output.

use super::runtime::{RuntimeLease, RuntimeTracker};
use anyhow::{bail, Context, Result};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex, TryLockError,
};
use std::thread;
use std::time::{Duration, Instant};

pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const PROVIDER_CATALOG_ARGS: &[&str] = &["config", "providers"];

/// Windows-specific: CREATE_NO_WINDOW flag
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Output from a rclone process
#[derive(Debug, Clone)]
pub struct RcloneOutput {
    /// Standard output lines
    pub stdout: Vec<String>,
    /// Standard error lines
    pub stderr: Vec<String>,
    /// Exit status
    pub status: i32,
    /// Whether the process was killed due to timeout
    pub timed_out: bool,
    pub cancelled: bool,
}

impl RcloneOutput {
    /// Check if the command succeeded
    pub fn success(&self) -> bool {
        self.status == 0 && !self.timed_out && !self.cancelled
    }

    /// Get stdout as a single string
    pub fn stdout_string(&self) -> String {
        self.stdout.join("\n")
    }

    /// Get stderr as a single string
    pub fn stderr_string(&self) -> String {
        self.stderr.join("\n")
    }
}

/// Runs rclone processes with proper configuration
#[derive(Debug, Clone)]
pub struct RcloneRunner {
    /// Path to rclone executable
    exe_path: PathBuf,
    /// Path to rclone config file (optional)
    config_path: Option<PathBuf>,
    /// Default timeout for commands
    default_timeout: Option<Duration>,
    cancel: Vec<Arc<AtomicBool>>,
    runtime: Option<Arc<RuntimeTracker>>,
}

impl RcloneRunner {
    /// Create a new rclone runner
    pub fn new(exe_path: impl AsRef<Path>) -> Self {
        Self {
            exe_path: exe_path.as_ref().to_path_buf(),
            config_path: None,
            default_timeout: None,
            cancel: Vec::new(),
            runtime: None,
        }
    }

    /// Bind every child and reader to the extraction's atomic cleanup gate.
    pub fn from_extracted(binary: &crate::embedded::ExtractedBinary) -> Self {
        let mut runner = Self::new(binary.path());
        runner.runtime = Some(binary.tracker());
        runner
    }

    /// Set the config file path
    pub fn with_config(mut self, config_path: impl AsRef<Path>) -> Self {
        self.config_path = Some(config_path.as_ref().to_path_buf());
        self
    }

    /// Set default timeout for commands
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = Some(timeout);
        self
    }

    /// Run a rclone command and capture output
    pub fn run(&self, args: &[&str]) -> Result<RcloneOutput> {
        self.run_with_timeout(args, self.default_timeout)
    }

    /// Read the built-in provider registry without loading a user config or
    /// creating its default directory. Rclone may still inspect standard paths.
    pub fn provider_catalog(&self) -> Result<RcloneOutput> {
        self.provider_catalog_runner().run(PROVIDER_CATALOG_ARGS)
    }

    fn provider_catalog_runner(&self) -> Self {
        // Rclone 1.75.2 treats an explicit empty --config as memory-only.
        // Clone retains runtime ownership, cancellation and timeout controls.
        self.clone().with_config("")
    }

    /// Run a rclone command with additional environment variables
    pub fn run_with_env(&self, args: &[&str], envs: &[(&str, &str)]) -> Result<RcloneOutput> {
        self.run_with_timeout_env(args, self.default_timeout, envs)
    }

    pub fn with_cancel_flag(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel.push(cancel);
        self
    }

    pub fn cancel_flag(&self) -> Option<Arc<AtomicBool>> {
        self.cancel.last().cloned()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.iter().any(|flag| flag.load(Ordering::Relaxed))
    }

    pub fn run_with_timeout(
        &self,
        args: &[&str],
        timeout: Option<Duration>,
    ) -> Result<RcloneOutput> {
        self.run_controlled(args, timeout, &[], |_, _| {})
    }

    pub fn run_with_timeout_env(
        &self,
        args: &[&str],
        timeout: Option<Duration>,
        envs: &[(&str, &str)],
    ) -> Result<RcloneOutput> {
        self.run_controlled(args, timeout, envs, |_, _| {})
    }

    pub fn run_streaming<F: FnMut(&str)>(
        &self,
        args: &[&str],
        mut on_line: F,
    ) -> Result<RcloneOutput> {
        self.run_controlled(args, self.default_timeout, &[], |stderr, line| {
            if !stderr {
                on_line(line);
            }
        })
    }

    pub fn run_streaming_stderr<F: FnMut(&str)>(
        &self,
        args: &[&str],
        mut on_line: F,
    ) -> Result<RcloneOutput> {
        self.run_controlled(args, self.default_timeout, &[], |stderr, line| {
            if stderr {
                on_line(line);
            }
        })
    }

    // The owning thread polls the child independently of stdout/stderr, including
    // when a remote produces no bytes. Reader channels apply backpressure.
    fn run_controlled<F: FnMut(bool, &str)>(
        &self,
        args: &[&str],
        timeout: Option<Duration>,
        envs: &[(&str, &str)],
        mut on_line: F,
    ) -> Result<RcloneOutput> {
        if self.is_cancelled() {
            bail!("Operation cancelled");
        }
        let mut runner = self.clone();
        runner.default_timeout = timeout;
        let mut child = runner.spawn_command(&mut self.build_command_with_env(args, Some(envs)))?;
        let (tx, rx) = mpsc::sync_channel(256);
        let out_tx = tx.clone();
        let mut readers = [None, None];
        let setup = (|| -> Result<()> {
            let stdout = child.stdout.take().context("Missing child stdout")?;
            let stderr = child.stderr.take().context("Missing child stderr")?;
            readers[0] = Some(child.spawn_reader("rclone-stdout", move || {
                read_process_lines(stdout, |line| {
                    let _ = out_tx.send((false, line));
                })
            })?);
            readers[1] = Some(child.spawn_reader("rclone-stderr", move || {
                read_process_lines(stderr, |line| {
                    let _ = tx.send((true, line));
                })
            })?);
            Ok(())
        })();
        if let Err(failure) = setup {
            drop(rx);
            let mut failure = Some(failure);
            if let Err(cleanup) = child.stop_and_reap(STOP_TIMEOUT) {
                combine_error(&mut failure, cleanup.into());
            }
            finish_readers(&mut child, readers, &mut failure);
            return Err(failure.expect("reader setup failure retained"));
        }
        let started = std::time::Instant::now();
        let mut output = RcloneOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            status: -1,
            timed_out: false,
            cancelled: false,
        };
        let mut exited = false;
        let mut disconnected = false;
        let mut error = None;
        let mut exit_time = None;
        loop {
            if !exited {
                output.cancelled = self.is_cancelled();
                output.timed_out = timeout.is_some_and(|limit| started.elapsed() >= limit);
                match child.try_wait() {
                    Ok(Some(status)) => {
                        output.status = status.code().unwrap_or(-1);
                        exited = true;
                        exit_time = Some(Instant::now());
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error = Some(anyhow::Error::new(e));
                        break;
                    }
                }
            }
            match rx.recv_timeout(Duration::from_millis(25)) {
                Ok((is_stderr, line)) => {
                    on_line(is_stderr, &line);
                    if is_stderr {
                        // Diagnostic history is bounded; progress is already delivered.
                        if output.stderr.len() == 2048 {
                            output.stderr.remove(0);
                        }
                        output.stderr.push(line);
                    } else {
                        output.stdout.push(line);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => disconnected = true,
            }
            if exited && disconnected {
                break;
            }
            if exit_time.is_some_and(|time| time.elapsed() >= JOIN_TIMEOUT) {
                child.retain();
                error = Some(anyhow::anyhow!("child_pipe_drain_timeout"));
                break;
            }
            if disconnected && !exited {
                thread::sleep(Duration::from_millis(25));
            }
        }
        // Release channel backpressure before bounded stop/join on an error.
        drop(rx);
        if !exited {
            if let Err(cleanup) = child.stop_and_reap(STOP_TIMEOUT) {
                combine_error(&mut error, cleanup.into());
            }
        }
        finish_readers(&mut child, readers, &mut error);
        if let Some(error) = error {
            return Err(error);
        }
        if output.cancelled {
            output.stderr.push("Operation cancelled".into());
        }
        if output.timed_out {
            output.stderr.push("Operation timed out".into());
        }
        Ok(output)
    }

    /// Spawn a rclone command, returning a live child process.
    ///
    /// This is useful for streaming large outputs without buffering them in memory.
    pub fn spawn(&self, args: &[&str]) -> Result<ManagedChild> {
        self.spawn_command(&mut self.build_command_with_env(args, None))
    }

    /// Reserve ownership before spawning, including raw mount/auth commands.
    pub fn spawn_command(&self, command: &mut Command) -> Result<ManagedChild> {
        if self.is_cancelled() {
            bail!("Operation cancelled");
        }
        if command.get_program() != self.exe_path.as_os_str() {
            bail!("runtime_command_mismatch");
        }
        let lease = self
            .runtime
            .as_ref()
            .map(|tracker| tracker.reserve())
            .transpose()?;
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                if let Some(lease) = lease {
                    lease.complete();
                }
                return Err(error).context("Failed to spawn rclone");
            }
        };
        // From this line onward a guard owns the exact process, even if pipe
        // setup or watchdog thread creation fails.
        let mut child = ManagedChild::new(child, lease, self.runtime.clone())?;
        if let Err(error) = child.start_watchdog(self.clone()) {
            let mut failure = Some(anyhow::Error::new(error));
            if let Err(cleanup) = child.stop_and_reap(STOP_TIMEOUT) {
                combine_error(&mut failure, cleanup.into());
            }
            if let Err(cleanup) = child.finish() {
                combine_error(&mut failure, cleanup.into());
            }
            return Err(failure.expect("thread creation error retained"));
        }
        Ok(child)
    }

    /// Get rclone version
    pub fn version(&self) -> Result<String> {
        let output = self.run(&["version"])?;
        if !output.success() {
            bail!("rclone version failed: {}", output.stderr_string());
        }
        // First line usually contains "rclone vX.Y.Z"
        Ok(output.stdout.first().cloned().unwrap_or_default())
    }

    /// List configured remotes
    pub fn list_remotes(&self) -> Result<Vec<String>> {
        let output = self.run(&["listremotes"])?;
        if !output.success() {
            bail!("rclone listremotes failed: {}", output.stderr_string());
        }
        Ok(output
            .stdout
            .iter()
            .map(|s| s.trim_end_matches(':').to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    /// Build the command with appropriate flags
    fn build_command_with_env(&self, args: &[&str], envs: Option<&[(&str, &str)]>) -> Command {
        let mut cmd = Command::new(&self.exe_path);

        // Add config flag if set
        if let Some(ref config) = self.config_path {
            isolate_rclone_environment(&mut cmd);
            cmd.arg("--config").arg(config);
        }

        // Add user args
        cmd.args(args);

        if let Some(envs) = envs {
            for (key, value) in envs {
                cmd.env(key, value);
            }
        }

        // Configure stdio
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Windows: hide console window
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        cmd
    }

    /// Get the executable path
    pub fn exe_path(&self) -> &Path {
        &self.exe_path
    }

    /// Get the config path if set
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// Get the default timeout
    pub fn timeout(&self) -> Option<Duration> {
        self.default_timeout
    }
}

/// A supplied config is authoritative. Inherited backend, filtering, dry-run,
/// or RC settings must not silently override the acquisition plan. Explicit
/// per-call environment is applied afterwards; encrypted config passwords remain
/// supported without copying the password into the snapshot.
pub(crate) fn isolate_rclone_environment(command: &mut Command) {
    remove_rclone_env_overrides(command, std::env::vars_os().map(|(key, _)| key));
}

fn remove_rclone_env_overrides(
    command: &mut Command,
    keys: impl IntoIterator<Item = std::ffi::OsString>,
) {
    for key in keys {
        let upper = key.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("RCLONE_") && upper != "RCLONE_CONFIG_PASS" {
            command.env_remove(key);
        }
    }
}

fn combine_error(primary: &mut Option<anyhow::Error>, failure: anyhow::Error) {
    *primary = Some(match primary.take() {
        Some(original) => {
            original.context(format!("Additional child finalization failure: {failure}"))
        }
        None => failure,
    });
}

fn finish_readers(
    child: &mut ManagedChild,
    readers: [Option<DrainHandle<io::Result<()>>>; 2],
    error: &mut Option<anyhow::Error>,
) {
    for reader in readers.into_iter().flatten() {
        if let Err(failure) = reader.join(JOIN_TIMEOUT).and_then(|result| result) {
            child.retain();
            combine_error(error, failure.into());
        }
    }
    if let Err(cleanup) = child.finish() {
        combine_error(error, cleanup.into());
    }
}

struct ChildScope {
    runtime: Option<Arc<RuntimeTracker>>,
    resources: AtomicUsize,
    uncertain: AtomicBool,
}

impl ChildScope {
    fn new(runtime: Option<Arc<RuntimeTracker>>) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            resources: AtomicUsize::new(0),
            uncertain: AtomicBool::new(false),
        })
    }

    fn retain(&self) {
        self.uncertain.store(true, Ordering::SeqCst);
        if let Some(runtime) = &self.runtime {
            runtime.retain();
        }
    }

    fn resource(self: &Arc<Self>) -> io::Result<ResourceLease> {
        self.resources
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_add(1).filter(|count| *count <= 64)
            })
            .map_err(|_| {
                self.retain();
                io::Error::other("child_resource_limit")
            })?;
        Ok(ResourceLease {
            scope: self.clone(),
            completed: false,
        })
    }
}

struct ResourceLease {
    scope: Arc<ChildScope>,
    completed: bool,
}

impl ResourceLease {
    fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for ResourceLease {
    fn drop(&mut self) {
        if !self.completed {
            self.scope.retain();
        }
        self.scope.resources.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A moved pipe keeps the child scope outstanding until its actual handle closes.
pub struct TrackedPipe<T> {
    pipe: Option<T>,
    lease: Option<ResourceLease>,
}

impl<T> TrackedPipe<T> {
    fn new(pipe: T, scope: &Arc<ChildScope>) -> io::Result<Self> {
        Ok(Self {
            pipe: Some(pipe),
            lease: Some(scope.resource()?),
        })
    }
}

impl<T: Read> Read for TrackedPipe<T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.pipe.as_mut().expect("live pipe").read(buffer)
    }
}

impl<T> Drop for TrackedPipe<T> {
    fn drop(&mut self) {
        drop(self.pipe.take());
        if let Some(lease) = self.lease.take() {
            lease.complete();
        }
    }
}

/// Dropping a join handle is not joining a thread, even if its pipe reached EOF.
pub struct DrainHandle<T> {
    thread: Option<thread::JoinHandle<T>>,
    lease: Option<ResourceLease>,
    scope: Arc<ChildScope>,
}

impl<T> std::fmt::Debug for DrainHandle<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DrainHandle")
            .field(
                "finished",
                &self
                    .thread
                    .as_ref()
                    .is_some_and(thread::JoinHandle::is_finished),
            )
            .finish_non_exhaustive()
    }
}

impl<T> DrainHandle<T> {
    pub fn join(mut self, timeout: Duration) -> io::Result<T> {
        let started = Instant::now();
        while !self.thread.as_ref().expect("live reader").is_finished() {
            if started.elapsed() >= timeout.min(JOIN_TIMEOUT) {
                self.scope.retain();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child_reader_join_timeout",
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
        match self.thread.take().expect("live reader").join() {
            Ok(value) => {
                if let Some(lease) = self.lease.take() {
                    lease.complete();
                }
                Ok(value)
            }
            Err(_) => {
                self.scope.retain();
                Err(io::Error::other("child_reader_panicked"))
            }
        }
    }
}

struct ChildControl {
    child: Option<Child>,
    exit: Option<ExitStatus>,
}

fn poll_control(
    control: &Mutex<ChildControl>,
    scope: &ChildScope,
) -> io::Result<Option<ExitStatus>> {
    let mut state = match control.try_lock() {
        Ok(state) => state,
        Err(TryLockError::WouldBlock) => return Ok(None),
        Err(TryLockError::Poisoned(_)) => {
            scope.retain();
            return Err(io::Error::other("child_lock_poisoned"));
        }
    };
    if state.exit.is_none() {
        state.exit = state
            .child
            .as_mut()
            .ok_or_else(|| {
                scope.retain();
                io::Error::other("child_handle_missing")
            })?
            .try_wait()
            .inspect_err(|_| scope.retain())?;
    }
    Ok(state.exit)
}

fn kill_control(control: &Mutex<ChildControl>) -> io::Result<bool> {
    let mut state = match control.try_lock() {
        Ok(state) => state,
        Err(TryLockError::WouldBlock) => return Ok(false),
        Err(TryLockError::Poisoned(_)) => return Err(io::Error::other("child_lock_poisoned")),
    };
    if state.exit.is_none() {
        state
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("child_handle_missing"))?
            .kill()?;
    }
    Ok(true)
}

fn stop_control(
    control: &Mutex<ChildControl>,
    scope: &ChildScope,
    timeout: Duration,
) -> io::Result<ExitStatus> {
    let started = Instant::now();
    let mut killed = false;
    let mut kill_error = None;
    loop {
        if let Some(status) = poll_control(control, scope)? {
            return Ok(status);
        }
        if !killed {
            match kill_control(control) {
                Ok(attempted) => killed = attempted,
                Err(error) => {
                    killed = true;
                    kill_error = Some(error.kind());
                }
            }
        }
        if started.elapsed() >= timeout.min(STOP_TIMEOUT) {
            scope.retain();
            return Err(io::Error::new(
                kill_error.unwrap_or(io::ErrorKind::TimedOut),
                "child_stop_unconfirmed",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Owns one exact child. Exit observation and full finalization are separate.
pub struct ManagedChild {
    pub stdout: Option<TrackedPipe<ChildStdout>>,
    pub stderr: Option<TrackedPipe<ChildStderr>>,
    child: Arc<Mutex<ChildControl>>,
    scope: Arc<ChildScope>,
    lease: Option<RuntimeLease>,
    done: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
    stop_failed: Arc<AtomicBool>,
    watchdog: Option<thread::JoinHandle<()>>,
    finalized: bool,
}

impl std::fmt::Debug for ManagedChild {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedChild")
            .field("finalized", &self.finalized)
            .field("uncertain", &self.scope.uncertain.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl ManagedChild {
    fn new(
        child: Child,
        lease: Option<RuntimeLease>,
        runtime: Option<Arc<RuntimeTracker>>,
    ) -> io::Result<Self> {
        let mut owned = Self {
            stdout: None,
            stderr: None,
            child: Arc::new(Mutex::new(ChildControl {
                child: Some(child),
                exit: None,
            })),
            scope: ChildScope::new(runtime),
            lease,
            done: Arc::new(AtomicBool::new(false)),
            stop_requested: Arc::new(AtomicBool::new(false)),
            stop_failed: Arc::new(AtomicBool::new(false)),
            watchdog: None,
            finalized: false,
        };
        let (stdout, stderr) = {
            let mut state = owned
                .child
                .lock()
                .map_err(|_| io::Error::other("child_lock_poisoned"))?;
            // No supported command is interactive through stdin. Closing it also
            // prevents wait deadlocks for raw commands supplied by callers.
            let child = state.child.as_mut().expect("new child owned");
            drop(child.stdin.take());
            (child.stdout.take(), child.stderr.take())
        };
        owned.stdout = stdout
            .map(|pipe| TrackedPipe::new(pipe, &owned.scope))
            .transpose()?;
        owned.stderr = stderr
            .map(|pipe| TrackedPipe::new(pipe, &owned.scope))
            .transpose()?;
        Ok(owned)
    }

    fn start_watchdog(&mut self, runner: RcloneRunner) -> io::Result<()> {
        self.start_watchdog_with(runner, |watch| {
            thread::Builder::new()
                .name("rclone-watchdog".into())
                .spawn(watch)
        })
    }

    fn start_watchdog_with<S>(&mut self, runner: RcloneRunner, spawn: S) -> io::Result<()>
    where
        S: FnOnce(Box<dyn FnOnce() + Send>) -> io::Result<thread::JoinHandle<()>>,
    {
        let control = self.child.clone();
        let scope = self.scope.clone();
        let done = self.done.clone();
        let requested = self.stop_requested.clone();
        let failed = self.stop_failed.clone();
        self.watchdog = Some(spawn(Box::new(move || {
            let started = Instant::now();
            while !done.load(Ordering::SeqCst) {
                if requested.load(Ordering::SeqCst)
                    || runner.is_cancelled()
                    || runner
                        .timeout()
                        .is_some_and(|limit| started.elapsed() >= limit)
                {
                    if stop_control(&control, &scope, STOP_TIMEOUT).is_err() {
                        failed.store(true, Ordering::SeqCst);
                    }
                    done.store(true, Ordering::SeqCst);
                    return;
                }
                thread::sleep(POLL_INTERVAL);
            }
        }))?);
        Ok(())
    }

    pub fn spawn_reader<T, F>(&self, name: &str, read: F) -> io::Result<DrainHandle<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        self.spawn_reader_with(read, |read| {
            thread::Builder::new().name(name.to_owned()).spawn(read)
        })
    }

    fn spawn_reader_with<T, F, S>(&self, read: F, spawn: S) -> io::Result<DrainHandle<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
        S: FnOnce(F) -> io::Result<thread::JoinHandle<T>>,
    {
        if self.finalized {
            return Err(io::Error::other("child_already_finalized"));
        }
        let lease = self.scope.resource()?;
        match spawn(read) {
            Ok(thread) => Ok(DrainHandle {
                thread: Some(thread),
                lease: Some(lease),
                scope: self.scope.clone(),
            }),
            Err(error) => {
                lease.complete();
                Err(error)
            }
        }
    }

    pub fn retain(&self) {
        self.scope.retain();
    }

    pub fn kill(&mut self) -> io::Result<()> {
        self.stop_requested.store(true, Ordering::SeqCst);
        kill_control(&self.child).map(|_| ())
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.stop_failed.load(Ordering::SeqCst)
            || (self
                .watchdog
                .as_ref()
                .is_some_and(thread::JoinHandle::is_finished)
                && !self.done.load(Ordering::SeqCst))
        {
            self.retain();
            return Err(io::Error::other("child_watchdog_failed"));
        }
        let status = poll_control(&self.child, &self.scope)?;
        if status.is_some() {
            self.done.store(true, Ordering::SeqCst);
        }
        Ok(status)
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    pub fn stop_and_reap(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        self.stop_requested.store(true, Ordering::SeqCst);
        let result = stop_control(&self.child, &self.scope, timeout);
        if result.is_ok() {
            self.done.store(true, Ordering::SeqCst);
        }
        result
    }

    /// Call after dropping/joining caller-owned pipes/readers. A timeout or an
    /// earlier uncertain result permanently retains the runtime, even if a later
    /// observation sees exit. This never treats a wait error as an exit status.
    pub fn finish(&mut self) -> io::Result<ExitStatus> {
        if self.finalized {
            return Err(io::Error::other("child_already_finalized"));
        }
        self.finalized = true;
        drop(self.stdout.take());
        drop(self.stderr.take());
        let mut result = self.finish_inner();
        if result.is_ok() {
            if let Some(lease) = self.lease.take() {
                lease.complete();
            }
        } else {
            self.retain();
            // A mistaken early finish must not abandon a live owned process.
            // Preserve the failed finalization even if this bounded stop works.
            if let Err(cleanup) = self.stop_and_reap(STOP_TIMEOUT) {
                let primary = result.expect_err("failed finalization");
                result = Err(io::Error::new(
                    primary.kind(),
                    format!("{primary}; additional stop failure: {cleanup}"),
                ));
            }
        }
        result
    }

    fn finish_inner(&mut self) -> io::Result<ExitStatus> {
        let started = Instant::now();
        let status = loop {
            if let Some(status) = poll_control(&self.child, &self.scope)? {
                break status;
            }
            // A watchdog can briefly hold the control mutex while recording
            // exit. Do not mistake that contention for an unconfirmed exit.
            if started.elapsed() >= JOIN_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child_exit_unconfirmed",
                ));
            }
            thread::sleep(POLL_INTERVAL);
        };
        self.done.store(true, Ordering::SeqCst);
        while self.scope.resources.load(Ordering::SeqCst) != 0
            || self
                .watchdog
                .as_ref()
                .is_some_and(|thread| !thread.is_finished())
        {
            if started.elapsed() >= JOIN_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child_finalization_timeout",
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
        if let Some(watchdog) = self.watchdog.take() {
            watchdog
                .join()
                .map_err(|_| io::Error::other("child_watchdog_panicked"))?;
        }
        // The guard can remain in a long-lived wrapper after finish. Close the
        // exact process handle here, before the runtime lease can be released.
        let process = self
            .child
            .try_lock()
            .map_err(|_| io::Error::other("child_handle_close_unconfirmed"))?
            .child
            .take();
        drop(process);
        if self.scope.uncertain.load(Ordering::SeqCst) || self.stop_failed.load(Ordering::SeqCst) {
            return Err(io::Error::other("child_finalization_uncertain"));
        }
        Ok(status)
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.finalized {
            if self.stop_and_reap(STOP_TIMEOUT).is_err() {
                self.retain();
            }
            let _ = self.finish();
        }
        // A timed-out detached watchdog/reader may still hold the scope. Its
        // uncertainty was recorded before any runtime owner can attempt cleanup.
        self.done.store(true, Ordering::SeqCst);
    }
}

/// Parse progress lines without retaining a duplicate transcript. Limit malformed
/// single-line output to 1 MiB so an untrusted child cannot grow the buffer forever.
fn read_process_lines<R: Read, F: FnMut(String)>(
    mut reader: R,
    mut on_line: F,
) -> std::io::Result<()> {
    let mut buffer = [0u8; 8192];
    let mut current = Vec::new();
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        for &byte in &buffer[..count] {
            if byte == b'\n' || byte == b'\r' {
                if !current.is_empty() {
                    on_line(String::from_utf8_lossy(&current).into_owned());
                    current.clear();
                }
            } else {
                current.push(byte);
                if current.len() == 1024 * 1024 {
                    on_line(String::from_utf8_lossy(&current).into_owned());
                    current.clear();
                }
            }
        }
    }
    if !current.is_empty() {
        on_line(String::from_utf8_lossy(&current).into_owned());
    }
    Ok(())
}

#[cfg(test)]
mod catalog_tests {
    use super::*;

    #[test]
    fn catalog_uses_empty_config_without_changing_the_callers_config() {
        for config in [None, Some(PathBuf::from("synthetic saved config.conf"))] {
            let mut runner = RcloneRunner::new("unused-synthetic-runtime");
            runner.config_path = config.clone();
            let catalog = runner.provider_catalog_runner();
            let command = catalog.build_command_with_env(PROVIDER_CATALOG_ARGS, None);
            let args: Vec<_> = command.get_args().collect();
            assert_eq!(
                args,
                ["--config", "", "config", "providers"].map(std::ffi::OsStr::new)
            );
            assert_eq!(command.get_program(), runner.exe_path().as_os_str());
            assert_eq!(catalog.config_path(), Some(Path::new("")));
            assert_eq!(runner.config_path, config);
        }
    }

    #[test]
    fn catalog_retains_runtime_gate_cancel_flags_and_timeout() {
        let tracker = RuntimeTracker::new();
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        let mut runner = RcloneRunner::new("unused-synthetic-runtime")
            .with_config("saved.conf")
            .with_timeout(Duration::from_secs(17))
            .with_cancel_flag(first.clone())
            .with_cancel_flag(second.clone());
        runner.runtime = Some(tracker.clone());
        let catalog = runner.provider_catalog_runner();
        assert_eq!(catalog.exe_path(), runner.exe_path());
        assert_eq!(catalog.timeout(), Some(Duration::from_secs(17)));
        assert_eq!(catalog.cancel.len(), 2);
        assert!(Arc::ptr_eq(&catalog.cancel[0], &first));
        assert!(Arc::ptr_eq(&catalog.cancel[1], &second));
        assert!(Arc::ptr_eq(catalog.runtime.as_ref().unwrap(), &tracker));
        assert!(!catalog.is_cancelled());
        first.store(true, Ordering::SeqCst);
        assert!(catalog.is_cancelled() && runner.is_cancelled());
        first.store(false, Ordering::SeqCst);
        second.store(true, Ordering::SeqCst);
        assert!(catalog.is_cancelled() && runner.is_cancelled());
        tracker.seal().unwrap();
        assert!(catalog.runtime.as_ref().unwrap().reserve().is_err());
        assert!(runner.runtime.as_ref().unwrap().reserve().is_err());
        assert_eq!(runner.config_path(), Some(Path::new("saved.conf")));
    }

    #[test]
    fn catalog_keeps_existing_environment_isolation_and_password_policy() {
        // Seed the command directly; do not mutate process-global environment.
        let runner = RcloneRunner::new("unused-synthetic-runtime").provider_catalog_runner();
        let mut command = runner.build_command_with_env(PROVIDER_CATALOG_ARGS, None);
        let keys = [
            "RCLONE_CONFIG",
            "RCLONE_CONFIG_SOURCE_REMOTE",
            "RCLONE_DRY_RUN",
            "RCLONE_CONFIG_PASS",
        ];
        for key in keys {
            command.env(key, "synthetic-canary");
        }
        remove_rclone_env_overrides(&mut command, keys.map(std::ffi::OsString::from));
        let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        for key in &keys[..3] {
            assert_eq!(env.get(std::ffi::OsStr::new(key)), Some(&None));
        }
        assert_eq!(
            env.get(std::ffi::OsStr::new("RCLONE_CONFIG_PASS")),
            Some(&Some(std::ffi::OsStr::new("synthetic-canary")))
        );
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    fn exited_child(tracker: &Arc<RuntimeTracker>) -> ManagedChild {
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;
        #[cfg(windows)]
        use std::os::windows::process::ExitStatusExt;
        ManagedChild {
            stdout: None,
            stderr: None,
            child: Arc::new(Mutex::new(ChildControl {
                child: None,
                exit: Some(ExitStatus::from_raw(0)),
            })),
            scope: ChildScope::new(Some(tracker.clone())),
            lease: Some(tracker.reserve().unwrap()),
            done: Arc::new(AtomicBool::new(false)),
            stop_requested: Arc::new(AtomicBool::new(false)),
            stop_failed: Arc::new(AtomicBool::new(false)),
            watchdog: None,
            finalized: false,
        }
    }

    #[test]
    fn exit_observation_does_not_release_the_child_lease() {
        let tracker = RuntimeTracker::new();
        let mut child = exited_child(&tracker);
        assert!(child.try_wait().unwrap().unwrap().success());
        assert!(child.lease.is_some());
        child.finish().unwrap();
        assert!(child.lease.is_none());
        assert!(child.child.lock().unwrap().child.is_none());
        tracker.seal().unwrap();
        assert!(tracker.reserve().is_err());
    }

    #[test]
    fn moved_pipe_prevents_finalization_and_late_close_cannot_clear_failure() {
        let tracker = RuntimeTracker::new();
        let mut child = exited_child(&tracker);
        let pipe = TrackedPipe::new(io::Cursor::new(b"synthetic"), &child.scope).unwrap();
        assert_eq!(child.scope.resources.load(Ordering::SeqCst), 1);
        assert!(child.finish().is_err());
        drop(pipe);
        assert!(child.finish().is_err());
        drop(child);
        assert!(tracker.seal().is_err());
    }

    #[test]
    fn detached_and_panicked_readers_poison_runtime_cleanup() {
        let tracker = RuntimeTracker::new();
        let mut child = exited_child(&tracker);
        let reader = child.spawn_reader("synthetic-reader", || ()).unwrap();
        drop(reader);
        assert!(child.finish().is_err());
        assert!(tracker.seal().is_err());

        let tracker = RuntimeTracker::new();
        let mut child = exited_child(&tracker);
        let reader = child
            .spawn_reader("synthetic-panic", || panic!("synthetic reader panic"))
            .unwrap();
        assert!(reader.join(JOIN_TIMEOUT).is_err());
        assert!(child.finish().is_err());
        assert!(tracker.seal().is_err());
    }

    #[test]
    fn reader_timeout_is_sticky_after_the_thread_later_finishes() {
        let tracker = RuntimeTracker::new();
        let mut child = exited_child(&tracker);
        let (release, blocked) = mpsc::channel();
        let (completed, completion) = mpsc::channel();
        let reader = child
            .spawn_reader("synthetic-blocked", move || {
                blocked.recv().unwrap();
                completed.send(()).unwrap();
            })
            .unwrap();
        assert!(reader.join(Duration::ZERO).is_err());
        release.send(()).unwrap();
        completion.recv_timeout(JOIN_TIMEOUT).unwrap();
        assert!(child.finish().is_err());
        assert!(tracker.seal().is_err());
    }

    #[test]
    fn thread_start_failure_releases_only_the_unstarted_reservation() {
        let tracker = RuntimeTracker::new();
        let mut child = exited_child(&tracker);
        let pipe = TrackedPipe::new(io::Cursor::new(b"synthetic"), &child.scope).unwrap();
        let result = child.spawn_reader_with(
            move || drop(pipe),
            |_read| Err(io::Error::other("synthetic thread creation failure")),
        );
        assert!(result.is_err());
        assert_eq!(child.scope.resources.load(Ordering::SeqCst), 0);
        assert!(child.lease.is_some());
        assert!(child
            .start_watchdog_with(RcloneRunner::new("unused"), |_watch| {
                Err(io::Error::other("synthetic watchdog creation failure"))
            })
            .is_err());
        assert!(child.lease.is_some());
        child.stop_and_reap(STOP_TIMEOUT).unwrap();
        child.finish().unwrap();
        tracker.seal().unwrap();
    }

    #[test]
    fn missing_or_poisoned_control_never_synthesizes_exit() {
        let tracker = RuntimeTracker::new();
        let mut child = exited_child(&tracker);
        child.child.lock().unwrap().exit = None;
        assert!(child.try_wait().is_err());
        assert!(child.finish().is_err());
        assert!(tracker.seal().is_err());

        let tracker = RuntimeTracker::new();
        let mut child = exited_child(&tracker);
        let control = child.child.clone();
        let _ = std::panic::catch_unwind(move || {
            let _guard = control.lock().unwrap();
            panic!("synthetic lock poison");
        });
        assert!(child.try_wait().is_err());
        assert!(child.finish().is_err());
        assert!(tracker.seal().is_err());
    }

    #[test]
    fn reader_io_failure_keeps_primary_error_and_runtime_retention() {
        let tracker = RuntimeTracker::new();
        let mut child = exited_child(&tracker);
        let reader = child
            .spawn_reader("synthetic-io", || {
                Err(io::Error::other("synthetic read failure"))
            })
            .unwrap();
        let mut error = Some(anyhow::anyhow!("synthetic operation failure"));
        finish_readers(&mut child, [Some(reader), None], &mut error);
        let errors = format!("{:#}", error.unwrap());
        assert!(errors.contains("synthetic operation failure"));
        assert!(errors.contains("synthetic read failure"));
        assert!(tracker.seal().is_err());
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::embedded::ExtractedBinary;

    #[test]
    fn finalized_live_guard_no_longer_holds_runtime_or_process_handle() {
        let mut binary = ExtractedBinary::extract().unwrap();
        let runner = RcloneRunner::from_extracted(&binary);
        let mut child = runner.spawn(&["version"]).unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let out = child
            .spawn_reader("test-runtime-out", move || {
                read_process_lines(stdout, |_| {})
            })
            .unwrap();
        let err = child
            .spawn_reader("test-runtime-err", move || {
                read_process_lines(stderr, |_| {})
            })
            .unwrap();
        assert!(child.wait().unwrap().success());
        out.join(JOIN_TIMEOUT).unwrap().unwrap();
        err.join(JOIN_TIMEOUT).unwrap().unwrap();
        child.finish().unwrap();
        assert!(child.child.lock().unwrap().child.is_none());
        binary.cleanup().unwrap();
        assert!(!binary.exists());
        assert!(runner.spawn(&["version"]).is_err());
        drop(child);
    }

    #[test]
    fn watchdog_start_failure_keeps_immediate_owned_child_until_reaped() {
        let tracker = RuntimeTracker::new();
        let runner = RcloneRunner::new("powershell.exe");
        let lease = tracker.reserve().unwrap();
        let raw = runner
            .build_command_with_env(
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 60",
                ],
                None,
            )
            .spawn()
            .unwrap();
        let mut child = ManagedChild::new(raw, Some(lease), Some(tracker.clone())).unwrap();
        assert!(child
            .start_watchdog_with(runner, |_watch| Err(io::Error::other(
                "synthetic watchdog start"
            )))
            .is_err());
        child.stop_and_reap(STOP_TIMEOUT).unwrap();
        child.finish().unwrap();
        assert!(child.child.lock().unwrap().child.is_none());
        tracker.seal().unwrap();
    }

    #[test]
    fn explicit_config_environment_keeps_only_password_and_explicit_overrides() {
        let mut cmd = Command::new("unused");
        for key in [
            "RCLONE_CONFIG_SOURCE_REMOTE",
            "RCLONE_DRY_RUN",
            "RCLONE_CONFIG_PASS",
        ] {
            cmd.env(key, "fixture");
        }
        remove_rclone_env_overrides(
            &mut cmd,
            [
                "RCLONE_CONFIG_SOURCE_REMOTE",
                "RCLONE_DRY_RUN",
                "RCLONE_CONFIG_PASS",
            ]
            .map(std::ffi::OsString::from),
        );
        let env: std::collections::BTreeMap<_, _> = cmd.get_envs().collect();
        assert_eq!(env.get(std::ffi::OsStr::new("RCLONE_DRY_RUN")), Some(&None));
        assert_eq!(
            env.get(std::ffi::OsStr::new("RCLONE_CONFIG_SOURCE_REMOTE")),
            Some(&None)
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("RCLONE_CONFIG_PASS")),
            Some(&Some(std::ffi::OsStr::new("fixture")))
        );
        cmd.env("RCLONE_DRY_RUN", "false");
        assert!(cmd
            .get_envs()
            .any(|(key, value)| key == "RCLONE_DRY_RUN"
                && value == Some(std::ffi::OsStr::new("false"))));
    }

    #[test]
    fn quiet_process_cancellation_is_bounded() {
        let cancel = Arc::new(AtomicBool::new(false));
        let trigger = cancel.clone();
        let signal = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            trigger.store(true, Ordering::Relaxed);
        });
        let runner = RcloneRunner::new("powershell.exe").with_cancel_flag(cancel);
        let start = std::time::Instant::now();
        let output = runner
            .run_streaming_stderr(
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 60",
                ],
                |_| {},
            )
            .unwrap();
        signal.join().unwrap();
        assert!(output.cancelled);
        assert!(!output.success());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn streaming_child_timeout_reaps_quiet_process() {
        let runner = RcloneRunner::new("powershell.exe").with_timeout(Duration::from_millis(150));
        let start = std::time::Instant::now();
        let mut child = runner
            .spawn(&[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 60",
            ])
            .unwrap();
        assert!(!child.wait().unwrap().success());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn test_run_version() {
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::from_extracted(&binary);

        let version = runner.version().expect("Failed to get version");
        assert!(
            version.contains("rclone") || version.contains("v"),
            "Unexpected version: {}",
            version
        );
    }

    #[test]
    fn test_run_help() {
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::from_extracted(&binary);

        let output = runner.run(&["--help"]).expect("Failed to run help");
        assert!(output.success());
        assert!(!output.stdout.is_empty());
    }

    #[test]
    fn test_run_streaming() {
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::from_extracted(&binary);

        let mut lines_received = 0;
        let output = runner
            .run_streaming(&["--help"], |_line| {
                lines_received += 1;
            })
            .expect("Failed to run streaming");

        assert!(output.success());
        assert!(lines_received > 0);
    }

    #[test]
    fn test_timeout() {
        let binary = ExtractedBinary::extract().expect("Failed to extract rclone");
        let runner = RcloneRunner::from_extracted(&binary).with_timeout(Duration::from_millis(1)); // Very short timeout

        // This should timeout (though rclone --help might be faster)
        let output = runner.run(&["--help"]).expect("Failed to run");
        // Either it succeeds fast or times out - both are valid
        assert!(output.success() || output.timed_out);
    }
}
