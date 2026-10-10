//! Hosted-only calibration. No production executable is loaded or run.
use std::{
    env,
    mem::{offset_of, size_of},
    os::windows::ffi::OsStrExt,
    ptr,
    sync::mpsc,
    time::Duration,
};
use windows_sys::{
    core::{w, GUID, PCWSTR},
    Win32::{
        Foundation::*,
        Storage::FileSystem::*,
        System::{
            Diagnostics::Etw::*, Performance::QueryPerformanceCounter,
            Threading::GetCurrentThreadId,
        },
    },
};

const SESSION: PCWSTR = w!("Triage Owned FileIo Calibration");
const FLAGS: u32 =
    EVENT_TRACE_FLAG_FILE_IO_INIT | EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_NO_SYSCONFIG;
const MODE: u32 = EVENT_TRACE_REAL_TIME_MODE
    | EVENT_TRACE_SYSTEM_LOGGER_MODE
    | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING
    // Otherwise ETW supplies a session-dependent shutdown default on query.
    | EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN;
const MAX_ENDS: usize = 8192;
const MAX_CALLBACKS: u32 = 50_000;
type Outcome = Result<(), &'static str>;

#[repr(C)]
struct Properties {
    value: EVENT_TRACE_PROPERTIES,
    name: [u16; 1024],
}
impl Properties {
    fn new() -> Self {
        let mut x = Self {
            value: EVENT_TRACE_PROPERTIES::default(),
            name: [0; 1024],
        };
        x.value.Wnode.BufferSize = size_of::<Self>() as u32;
        x.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        x.value.Wnode.ClientContext = 1; // QPC, paired with RAW_TIMESTAMP below.
        x.value.LoggerNameOffset = offset_of!(Self, name) as u32;
        x
    }
    fn lossless(&self) -> bool {
        self.value.EventsLost == 0
            && self.value.LogBuffersLost == 0
            && self.value.RealTimeBuffersLost == 0
    }
    fn bounded(&self) -> bool {
        (4..=64).contains(&self.value.BufferSize)
            && (2..=16).contains(&self.value.MinimumBuffers)
            && self.value.MaximumBuffers >= self.value.MinimumBuffers
            && self.value.MaximumBuffers <= 16
            && self.value.NumberOfBuffers <= 16
    }
}
fn same_guid(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

#[derive(Clone, Copy)]
struct Start {
    qpc: i64,
    irp: u64,
    share: u32,
}
#[derive(Clone, Copy)]
struct End {
    qpc: i64,
    irp: u64,
    status: u32,
}
struct Collector {
    tid: u64,
    path: Vec<u16>,
    starts: Vec<Start>,
    ends: Vec<End>,
    callbacks: u32,
    error: Option<&'static str>,
    ready: Option<mpsc::SyncSender<()>>,
}
impl Collector {
    fn new(tid: u64, path: Vec<u16>) -> Result<Self, &'static str> {
        let mut x = Self {
            tid,
            path,
            starts: Vec::new(),
            ends: Vec::new(),
            callbacks: 0,
            error: None,
            ready: None,
        };
        x.starts
            .try_reserve_exact(2)
            .map_err(|_| "budget_exceeded")?;
        x.ends
            .try_reserve_exact(MAX_ENDS)
            .map_err(|_| "budget_exceeded")?;
        Ok(x)
    }
    fn correlate(&self, before: i64, after: i64) -> Outcome {
        if let Some(e) = self.error {
            return Err(e);
        }
        if before <= 0 || after < before {
            return Err("clock_unavailable");
        }
        let starts: Vec<_> = self
            .starts
            .iter()
            .filter(|s| before <= s.qpc && s.qpc <= after)
            .collect();
        if starts.len() != 1 {
            return Err("correlation_missing_or_ambiguous");
        }
        let s = starts[0];
        if s.irp == 0 || s.share != FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE {
            return Err("schema_unavailable");
        }
        let ends: Vec<_> = self
            .ends
            .iter()
            .filter(|e| e.irp == s.irp && before <= e.qpc && e.qpc <= after)
            .collect();
        if ends.len() != 1 || ends[0].qpc < s.qpc {
            return Err("correlation_missing_or_ambiguous");
        }
        if ends[0].status != 0xc0000043 {
            return Err("unexpected_status");
        }
        Ok(())
    }
}

// TDH supplies property sizes, including pointer-width qualifiers. No payload offsets.
unsafe fn property(
    e: *const EVENT_RECORD,
    name: PCWSTR,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    let p = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut len = 0;
    if TdhGetPropertySize(e, 0, ptr::null(), 1, &p, &mut len) != 0
        || len == 0
        || len as usize > out.len()
    {
        return Err("schema_unavailable");
    }
    if TdhGetProperty(e, 0, ptr::null(), 1, &p, len, out.as_mut_ptr()) != 0 {
        return Err("schema_unavailable");
    }
    Ok(len as usize)
}
unsafe fn number(e: *const EVENT_RECORD, name: PCWSTR, pointer: bool) -> Result<u64, &'static str> {
    let mut out = [0; 8];
    let n = property(e, name, &mut out)?;
    if (pointer && n != 8) || (!pointer && n != 4) {
        return Err("schema_unavailable");
    }
    Ok(u64::from_le_bytes(out))
}
unsafe fn consume(e: *const EVENT_RECORD, s: &mut Collector) -> Outcome {
    let h = &(*e).EventHeader;
    if !same_guid(h.ProviderId, FileIoGuid) || !matches!(h.EventDescriptor.Opcode, 64 | 76) {
        return Ok(());
    }
    if h.EventDescriptor.Version != 2
        || h.Flags as u32 & EVENT_HEADER_FLAG_64_BIT_HEADER == 0
        || h.Flags as u32 & EVENT_HEADER_FLAG_32_BIT_HEADER != 0
    {
        return Err("schema_unavailable");
    }
    if h.EventDescriptor.Opcode == 76 {
        if s.ends.len() == MAX_ENDS {
            return Err("budget_exceeded");
        }
        s.ends.push(End {
            qpc: h.TimeStamp,
            irp: number(e, w!("IrpPtr"), true)?,
            status: number(e, w!("NtStatus"), false)? as u32,
        });
    } else {
        // TTID is Pointer-qualified in the documented version-2 MOF, not a guessed u32 offset.
        if number(e, w!("TTID"), true)? != s.tid {
            return Ok(());
        }
        let mut path = [0u8; 2048];
        let n = property(e, w!("OpenPath"), &mut path)?;
        if n % 2 != 0 || n < 2 || path[n - 2..n] != [0, 0] {
            return Err("schema_unavailable");
        }
        if n / 2 != s.path.len() + 1
            || !path[..n - 2]
                .chunks_exact(2)
                .zip(&s.path)
                .all(|(a, b)| u16::from_le_bytes([a[0], a[1]]) == *b)
        {
            return Ok(()); // Other paths are discarded; never printed or retained.
        }
        if s.starts.len() == 2 {
            return Err("budget_exceeded");
        }
        s.starts.push(Start {
            qpc: h.TimeStamp,
            irp: number(e, w!("IrpPtr"), true)?,
            share: number(e, w!("ShareAccess"), false)? as u32,
        });
    }
    Ok(())
}
unsafe extern "system" fn on_event(e: *mut EVENT_RECORD) {
    if e.is_null() || (*e).UserContext.is_null() {
        return;
    }
    let s = &mut *((*e).UserContext as *mut Collector);
    if let Some(ready) = s.ready.take() {
        let _ = ready.try_send(());
    }
    if s.error.is_some() {
        return;
    }
    s.callbacks += 1;
    if s.callbacks > MAX_CALLBACKS {
        s.error = Some("budget_exceeded");
        return;
    }
    if let Err(reason) = consume(e, s) {
        s.error = Some(reason);
    }
}
unsafe extern "system" fn on_buffer(log: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if log.is_null() || (*log).Context.is_null() {
        return 0;
    }
    let s = &mut *((*log).Context as *mut Collector);
    if let Some(ready) = s.ready.take() {
        let _ = ready.try_send(());
    }
    if (*log).EventsLost != 0 {
        s.error = Some("event_loss");
    }
    1 // Drain even after an error; the controller owns STOP.
}

struct Consumer {
    state: Box<Collector>,
    log: Box<EVENT_TRACE_LOGFILEW>,
    handle: PROCESSTRACE_HANDLE,
}
// Boxes have stable addresses. Only ProcessTrace's one consumer thread accesses
// callback state; the controller sees it only after the thread returns and joins.
unsafe impl Send for Consumer {}
impl Consumer {
    unsafe fn open(state: Collector) -> Result<Self, &'static str> {
        let mut x = Self {
            state: Box::new(state),
            log: Box::new(EVENT_TRACE_LOGFILEW::default()),
            handle: PROCESSTRACE_HANDLE::default(),
        };
        x.log.LoggerName = SESSION as *mut u16;
        x.log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
            | PROCESS_TRACE_MODE_EVENT_RECORD
            | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        x.log.Anonymous2.EventRecordCallback = Some(on_event);
        x.log.BufferCallback = Some(on_buffer);
        x.log.Context = (&mut *x.state as *mut Collector).cast();
        x.handle = OpenTraceW(&mut *x.log);
        if x.handle.Value == u64::MAX {
            return Err("consumer_unavailable");
        }
        Ok(x)
    }
    unsafe fn process(self) -> (u32, Self) {
        let code = ProcessTrace(&self.handle, 1, ptr::null(), ptr::null());
        (code, self) // Keep both callback allocations until controller CloseTrace.
    }
}

struct SessionSettings {
    enable_flags: u32,
    log_mode: u32,
    clock_selector: u32,
}

#[derive(Default)]
struct Proof {
    queried_session_settings: Option<SessionSettings>,
    started: bool,
    stop_attempted: bool,
    stopped: bool,
    consumer: bool,
    lossless: bool,
    bounded: bool,
    identity: bool,
    directory: bool,
    paired: bool,
    cleaned: bool,
    probe: bool,
}
unsafe fn qpc() -> Result<i64, &'static str> {
    let mut x = 0;
    if QueryPerformanceCounter(&mut x) == 0 || x <= 0 {
        Err("clock_unavailable")
    } else {
        Ok(x)
    }
}

// Exactly one STOP, using only the handle returned by our successful StartTraceW.
// A subsequent name QUERY is read-only and must report absence; a replacement
// session or uncertain query is never stopped. CloseTrace does not stop a session.
unsafe fn stop_owned(handle: CONTROLTRACE_HANDLE, proof: &mut Proof) {
    proof.stop_attempted = true;
    let mut stopped = Properties::new();
    let status = ControlTraceW(
        handle,
        ptr::null(),
        &mut stopped.value,
        EVENT_TRACE_CONTROL_STOP,
    );
    let mut absent = Properties::new();
    let queried = ControlTraceW(
        CONTROLTRACE_HANDLE::default(),
        SESSION,
        &mut absent.value,
        EVENT_TRACE_CONTROL_QUERY,
    );
    proof.stopped = status == ERROR_SUCCESS && queried == ERROR_WMI_INSTANCE_NOT_FOUND;
    proof.lossless = status == ERROR_SUCCESS && stopped.lossless();
    proof.bounded &= status == ERROR_SUCCESS && stopped.bounded();
}

unsafe fn trace(path: &[u16], holder: HANDLE, proof: &mut Proof) -> Outcome {
    let mut native_path = [0u16; 1024];
    let len = GetFinalPathNameByHandleW(
        holder,
        native_path.as_mut_ptr(),
        native_path.len() as u32,
        VOLUME_NAME_NT,
    );
    if len == 0 || len as usize >= native_path.len() {
        return Err("identity_unavailable");
    }
    let mut state = Collector::new(
        GetCurrentThreadId() as u64,
        native_path[..len as usize].to_vec(),
    )?;
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    state.ready = Some(ready_tx);
    let mut properties = Properties::new();
    properties.value.BufferSize = 64;
    properties.value.MinimumBuffers = 4;
    properties.value.MaximumBuffers = 16;
    properties.value.LogFileMode = MODE;
    properties.value.EnableFlags = FLAGS;
    properties.value.FlushTimer = 1;
    let mut handle = CONTROLTRACE_HANDLE::default();
    let started = StartTraceW(&mut handle, SESSION, &mut properties.value);
    if started != ERROR_SUCCESS {
        return Err(if started == ERROR_ALREADY_EXISTS {
            "session_collision"
        } else if started == ERROR_ACCESS_DENIED {
            "access_denied"
        } else {
            "session_unavailable"
        });
    }
    proof.started = true;
    let operation = (|| -> Outcome {
        let mut actual = Properties::new();
        if ControlTraceW(
            handle,
            ptr::null(),
            &mut actual.value,
            EVENT_TRACE_CONTROL_QUERY,
        ) != 0
        {
            return Err("session_unavailable");
        }
        proof.queried_session_settings = Some(SessionSettings {
            enable_flags: actual.value.EnableFlags,
            log_mode: actual.value.LogFileMode,
            clock_selector: actual.value.Wnode.ClientContext,
        });
        proof.bounded = actual.bounded();
        if !proof.bounded {
            return Err("budget_exceeded");
        }
        if !actual.lossless() {
            return Err("event_loss");
        }
        if actual.value.EnableFlags != FLAGS
            || actual.value.LogFileMode != MODE
            || actual.value.Wnode.ClientContext != 1
        {
            return Err("session_configuration_mismatch");
        }
        let consumer = Consumer::open(state)?;
        let reader = consumer.handle;
        let (tx, rx) = mpsc::sync_channel(1);
        let (bootstrap_tx, bootstrap_rx) = mpsc::sync_channel::<Consumer>(1);
        let worker = std::thread::Builder::new()
            .name("etw-consumer".into())
            .spawn(move || {
                if let Ok(consumer) = bootstrap_rx.recv() {
                    let result = consumer.process();
                    if let Err(undelivered) = tx.send(result) {
                        // The controller timed out. Retain callback storage until
                        // process exit rather than assume CloseTrace succeeded.
                        std::mem::forget(undelivered.0);
                    }
                }
            });
        let worker = match worker {
            Ok(w) => w,
            Err(_) => {
                return Err(if CloseTrace(reader) == ERROR_SUCCESS {
                    "consumer_unavailable"
                } else {
                    std::mem::forget(consumer);
                    "cleanup_uncertain"
                });
            }
        };
        if let Err(undelivered) = bootstrap_tx.send(consumer) {
            if CloseTrace(reader) != ERROR_SUCCESS {
                std::mem::forget(undelivered.0);
            }
            return Err("cleanup_uncertain");
        }
        // No retries, no disposition, no execution. GetLastError is saved immediately.
        let observation = (|| -> Result<(i64, i64), &'static str> {
            ready_rx
                .recv_timeout(Duration::from_secs(3))
                .map_err(|_| "consumer_unavailable")?;
            let before = qpc()?;
            let probe = CreateFileW(
                path.as_ptr(),
                DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            );
            let error = GetLastError();
            let after = qpc();
            if probe != INVALID_HANDLE_VALUE {
                return Err(if CloseHandle(probe) != 0 {
                    "unexpected_status"
                } else {
                    "cleanup_uncertain"
                });
            }
            proof.probe = error == ERROR_SHARING_VIOLATION;
            if !proof.probe {
                return Err("unexpected_status");
            }
            Ok((before, after?))
        })();
        stop_owned(handle, proof);
        // STOP drains the real-time session. Wait before CloseTrace: forcing a
        // consumer to close must not masquerade as complete event delivery.
        let completion = rx.recv_timeout(Duration::from_secs(10));
        let closed = CloseTrace(reader);
        let complete = match completion {
            Ok(x) => Some(x),
            Err(_) => {
                if let Ok(late) = rx.recv_timeout(Duration::from_secs(5)) {
                    // ProcessTrace has returned; pending close is now drained.
                    if closed != ERROR_SUCCESS && closed != ERROR_CTX_CLOSE_PENDING {
                        std::mem::forget(late);
                    }
                }
                None
            }
        };
        if let Some((code, consumer)) = complete {
            if closed != ERROR_SUCCESS {
                std::mem::forget(consumer);
                return Err("cleanup_uncertain");
            }
            if consumer.state.error == Some("event_loss") {
                proof.lossless = false;
            }
            proof.consumer =
                worker.join().is_ok() && code == ERROR_SUCCESS && closed == ERROR_SUCCESS;
            if !proof.consumer || !proof.stopped {
                return Err("cleanup_uncertain");
            }
            if !proof.lossless {
                return Err("event_loss");
            }
            if !proof.bounded {
                return Err("budget_exceeded");
            }
            let (before, after) = observation?;
            consumer.state.correlate(before, after)?;
            proof.paired = true;
            Ok(())
        } else {
            // Detached worker retains its own callback storage. No dangling context.
            // Process termination/job timeout is NOT a session-stop certificate.
            Err("cleanup_uncertain")
        }
    })();
    // Setup failures still require one owned STOP; failed STOP is never retried.
    if !proof.stop_attempted {
        stop_owned(handle, proof);
    }
    if !proof.stopped {
        Err("cleanup_uncertain")
    } else {
        operation
    }
}

fn identity(h: HANDLE, directory: bool) -> Result<BY_HANDLE_FILE_INFORMATION, &'static str> {
    let mut x = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(h, &mut x) } == 0
        || x.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (x.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (x.nFileIndexHigh == 0 && x.nFileIndexLow == 0)
        || (!directory && (x.nFileSizeHigh != 0 || x.nFileSizeLow != 0 || x.nNumberOfLinks != 1))
    {
        return Err("identity_unavailable");
    }
    Ok(x)
}
fn same_file(a: &BY_HANDLE_FILE_INFORMATION, b: &BY_HANDLE_FILE_INFORMATION) -> bool {
    a.dwVolumeSerialNumber == b.dwVolumeSerialNumber
        && a.nFileIndexHigh == b.nFileIndexHigh
        && a.nFileIndexLow == b.nFileIndexLow
}
fn verified_identity(
    first: &Result<BY_HANDLE_FILE_INFORMATION, &'static str>,
    h: HANDLE,
    directory: bool,
) -> bool {
    match (first, identity(h, directory)) {
        (Ok(a), Ok(b)) => same_file(a, &b),
        _ => false,
    }
}
unsafe fn mark_owned_for_deletion(h: HANDLE) -> bool {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    SetFileInformationByHandle(
        h,
        FileDispositionInfo,
        (&disposition as *const FILE_DISPOSITION_INFO).cast(),
        size_of::<FILE_DISPOSITION_INFO>() as u32,
    ) != 0
}
unsafe fn absent(path: &[u16]) -> bool {
    // Read-only absence check. Access denial/delete-pending/unknown parent is not absence.
    GetFileAttributesW(path.as_ptr()) == INVALID_FILE_ATTRIBUTES
        && GetLastError() == ERROR_FILE_NOT_FOUND
}
fn run(proof: &mut Proof) -> Outcome {
    if !cfg!(target_arch = "aarch64")
        || env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        || env::var("RUNNER_ARCH").as_deref() != Ok("ARM64")
    {
        return Err("unsupported_environment");
    }
    let root =
        std::path::PathBuf::from(env::var_os("RUNNER_TEMP").ok_or("unsupported_environment")?)
            .join("triage-etw-calibration-owned");
    std::fs::create_dir(&root).map_err(|_| "owned_file_unavailable")?; // Never reuse an existing directory.
    let root_path: Vec<u16> = root.as_os_str().encode_wide().chain(Some(0)).collect();
    let directory = unsafe {
        CreateFileW(
            root_path.as_ptr(),
            FILE_LIST_DIRECTORY | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if directory == INVALID_HANDLE_VALUE {
        return Err("cleanup_uncertain");
    }
    let directory_first = identity(directory, true);
    if directory_first.is_err() {
        unsafe {
            CloseHandle(directory);
        }
        return Err("cleanup_uncertain"); // Retain unknown directory; no named-path deletion.
    }
    let file = root.join("inert.txt");
    let path: Vec<u16> = file.as_os_str().encode_wide().chain(Some(0)).collect();
    let holder = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_DATA | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if holder == INVALID_HANDLE_VALUE {
        unsafe {
            CloseHandle(directory);
        }
        return Err("cleanup_uncertain");
    }
    let first = identity(holder, false);
    let operation = if first.is_ok() {
        unsafe { trace(&path, holder, proof) }
    } else {
        Err("identity_unavailable")
    };
    proof.identity = verified_identity(&first, holder, false);
    proof.directory = verified_identity(&directory_first, directory, true);
    // The original CREATE_NEW handle is the cleanup target, never a pathname.
    // Keep its no-delete-share hold until this sole post-capture disposition.
    let marked = proof.identity && proof.directory && unsafe { mark_owned_for_deletion(holder) };
    let closed = unsafe { CloseHandle(holder) } != 0;
    let removed = marked && closed && unsafe { absent(&path) };
    // The directory remains pinned until the file is confirmed absent. No retries.
    let directory_marked =
        removed && proof.directory && unsafe { mark_owned_for_deletion(directory) };
    let directory_closed = unsafe { CloseHandle(directory) } != 0;
    proof.cleaned = directory_marked && directory_closed && unsafe { absent(&root_path) };
    if !proof.cleaned {
        return Err("cleanup_uncertain");
    }
    operation?;
    if !proof.identity {
        return Err("identity_unavailable");
    }
    Ok(())
}
fn main() {
    std::panic::set_hook(Box::new(|_| {})); // Never publish panic paths/state.
    let mut p = Proof::default();
    let outcome = run(&mut p);
    let observed = outcome.is_ok()
        && p.started
        && p.stopped
        && p.consumer
        && p.lossless
        && p.bounded
        && p.identity
        && p.directory
        && p.paired
        && p.cleaned
        && p.probe;
    let reason = if observed {
        "none"
    } else {
        outcome.err().unwrap_or("cleanup_uncertain")
    };
    let settings = match p.queried_session_settings {
        Some(s) => format!(
            "{{\"enable_flags\":{},\"log_mode\":{},\"clock_selector\":{}}}",
            s.enable_flags, s.log_mode, s.clock_selector
        ),
        None => "null".into(),
    };
    println!("{{\"schema\":3,\"scope\":\"synthetic_open_only\",\"status\":\"{}\",\"reason\":\"{}\",\"api\":\"CreateFileW_DELETE_OPEN_EXISTING\",\"holder_access\":\"READ_DATA|DELETE_without_delete_share\",\"queried_session_settings\":{},\"win32_sharing_violation\":{},\"create_opend_pair\":{},\"same_owned_file\":{},\"same_owned_directory\":{},\"session_started\":{},\"session_stop_verified\":{},\"consumer_completed\":{},\"zero_loss\":{},\"effective_buffers_within_budget\":{},\"owned_file_cleaned\":{}}}",
        if observed { "observed" } else { "unavailable" }, reason, settings, p.probe, p.paired, p.identity, p.directory, p.started, p.stopped, p.consumer, p.lossless, p.bounded, p.cleaned);
    std::process::exit(if observed { 0 } else { 2 });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Collector {
        let mut c = Collector::new(1, vec![120]).unwrap();
        c.starts.push(Start {
            qpc: 101,
            irp: 7,
            share: 7,
        });
        c.ends.push(End {
            qpc: 102,
            irp: 7,
            status: 0xc0000043,
        });
        c
    }
    #[test]
    fn complete_pair_and_unrelated_end() {
        let mut c = fixture();
        c.ends.insert(
            0,
            End {
                qpc: 100,
                irp: 8,
                status: 0,
            },
        );
        assert!(c.correlate(100, 103).is_ok());
    }
    #[test]
    fn duplicate_reused_irp_is_unavailable() {
        let mut c = fixture();
        c.ends.push(c.ends[0]);
        assert!(c.correlate(100, 103).is_err());
    }
    #[test]
    fn missing_outside_or_wrong_status_is_unavailable() {
        let mut c = fixture();
        c.ends[0].qpc = 104;
        assert!(c.correlate(100, 103).is_err());
        c.ends[0].qpc = 100;
        assert!(c.correlate(100, 103).is_err());
        c.ends[0].qpc = 102;
        c.ends[0].status = 0;
        assert!(c.correlate(100, 103).is_err());
    }
    #[test]
    fn loss_or_decode_failure_is_unavailable() {
        let mut c = fixture();
        c.error = Some("event_loss");
        assert!(c.correlate(100, 103).is_err());
        c.error = Some("schema_unavailable");
        assert!(c.correlate(100, 103).is_err());
    }
}
