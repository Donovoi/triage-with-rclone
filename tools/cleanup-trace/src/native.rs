use crate::admission::{self, Admission, CaptureGate, Decision, PublishedBounds};
use crate::model::{self, CallbackStorage, Counts, End, Start, MAX_STARTS};
use crate::ownership::{
    self, Buffer as OwnershipBuffer, Event as OwnershipEvent, Reason as OwnershipReason,
};
use crate::schema_metadata;
use crate::{resource_use, resource_use_windows};
use std::{
    env,
    fs::File,
    io,
    io::Write,
    mem::{offset_of, size_of},
    os::windows::io::AsRawHandle,
    ptr,
    sync::{mpsc, Arc},
    thread::JoinHandle,
    time::Duration,
};
use windows_sys::{
    core::{w, GUID, PCWSTR},
    Win32::{
        Foundation::*,
        Storage::FileSystem::*,
        System::{
            Diagnostics::Etw::*,
            Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
            Threading::{GetCurrentThreadId, WaitForSingleObject},
        },
    },
};
const SESSION: PCWSTR = w!("Triage Original Runtime Cleanup Trace");
const FLAGS: u32 =
    EVENT_TRACE_FLAG_FILE_IO_INIT | EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_NO_SYSCONFIG;
const MODE: u32 = EVENT_TRACE_REAL_TIME_MODE
    | EVENT_TRACE_SYSTEM_LOGGER_MODE
    | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING
    | EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN;
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
enum SchemaStage {
    Version,
    HeaderFlags,
    TdhSize,
    PropertyBound,
    TdhRead,
    NumericWidth,
    PathEncoding,
}
impl SchemaStage {
    fn label(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::HeaderFlags => "header_flags",
            Self::TdhSize => "tdh_size",
            Self::PropertyBound => "property_bound",
            Self::TdhRead => "tdh_read",
            Self::NumericWidth => "numeric_width",
            Self::PathEncoding => "path_encoding",
        }
    }
}
#[derive(Clone, Copy)]
enum KnownProperty {
    Ttid,
    IrpPtr,
    NtStatus,
    OpenPath,
    ShareAccess,
}
impl KnownProperty {
    fn name(self) -> PCWSTR {
        match self {
            Self::Ttid => w!("TTID"),
            Self::IrpPtr => w!("IrpPtr"),
            Self::NtStatus => w!("NtStatus"),
            Self::OpenPath => w!("OpenPath"),
            Self::ShareAccess => w!("ShareAccess"),
        }
    }
    fn json(self) -> &'static str {
        match self {
            Self::Ttid => "\"TTID\"",
            Self::IrpPtr => "\"IrpPtr\"",
            Self::NtStatus => "\"NtStatus\"",
            Self::OpenPath => "\"OpenPath\"",
            Self::ShareAccess => "\"ShareAccess\"",
        }
    }
}
#[derive(Clone, Copy)]
struct SchemaHeader {
    opcode: u8,
    version: u8,
    flags: u16,
}
#[derive(Clone, Copy)]
struct SchemaRejection {
    header: SchemaHeader,
    stage: SchemaStage,
    property: Option<KnownProperty>,
    tdh_status: Option<u32>,
    size: Option<u32>,
}
impl SchemaRejection {
    fn json(self) -> String {
        let number = |x: Option<u32>| x.map_or_else(|| "null".into(), |n| n.to_string());
        format!(
            "{{\"attribution\":\"unattributed_fileio\",\"stage\":\"{}\",\"property\":{},\"opcode\":{},\"version\":{},\"header_flags\":{},\"tdh_status\":{},\"size\":{}}}",
            self.stage.label(), self.property.map_or("null", KnownProperty::json),
            self.header.opcode, self.header.version, self.header.flags,
            number(self.tdh_status), number(self.size)
        )
    }
}

struct Collector {
    path: Vec<u16>,
    starts: Vec<Start>,
    admission: Option<Admission>,
    published: Arc<PublishedBounds>,
    callbacks: u32,
    error: Option<&'static str>,
    schema_rejection: Option<SchemaRejection>,
    ready: Option<mpsc::SyncSender<()>>,
    ownership: OwnershipBuffer,
    metadata: schema_metadata::Capture,
}
impl Collector {
    fn new(path: Vec<u16>, published: Arc<PublishedBounds>) -> Result<Self, &'static str> {
        let mut x = Self {
            path,
            starts: Vec::new(),
            admission: None,
            published,
            callbacks: 0,
            error: None,
            schema_rejection: None,
            ready: None,
            ownership: OwnershipBuffer::default(),
            metadata: schema_metadata::Capture::new(),
        };
        x.starts
            .try_reserve_exact(MAX_STARTS)
            .map_err(|_| "start_reservation_failed")?;
        x.admission = Some(Admission::new().map_err(|reason| reason.label())?);
        x.ownership.reserve(); // Supplemental allocation failure cannot replace the original gate.
        Ok(x)
    }
    fn reject(
        &mut self,
        header: SchemaHeader,
        stage: SchemaStage,
        property: Option<KnownProperty>,
        tdh_status: Option<u32>,
        size: Option<u32>,
    ) -> &'static str {
        self.schema_rejection.get_or_insert(SchemaRejection {
            header,
            stage,
            property,
            tdh_status,
            size,
        });
        "schema_unavailable"
    }
}
// TDH supplies property sizes, including pointer-width qualifiers. No payload offsets.
unsafe fn property(
    e: *const EVENT_RECORD,
    s: &mut Collector,
    header: SchemaHeader,
    name: KnownProperty,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    let p = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name.name() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut len = 0;
    let status = TdhGetPropertySize(e, 0, ptr::null(), 1, &p, &mut len);
    if status != 0 {
        return Err(s.reject(header, SchemaStage::TdhSize, Some(name), Some(status), None));
    }
    if len == 0 || len as usize > out.len() {
        return Err(s.reject(
            header,
            SchemaStage::PropertyBound,
            Some(name),
            Some(status),
            Some(len),
        ));
    }
    let status = TdhGetProperty(e, 0, ptr::null(), 1, &p, len, out.as_mut_ptr());
    if status != 0 {
        return Err(s.reject(
            header,
            SchemaStage::TdhRead,
            Some(name),
            Some(status),
            Some(len),
        ));
    }
    Ok(len as usize)
}
unsafe fn number(
    e: *const EVENT_RECORD,
    s: &mut Collector,
    header: SchemaHeader,
    name: KnownProperty,
    pointer: bool,
) -> Result<u64, &'static str> {
    let mut out = [0; 8];
    let n = property(e, s, header, name, &mut out)?;
    if (pointer && n != 8) || (!pointer && n != 4) {
        return Err(s.reject(
            header,
            SchemaStage::NumericWidth,
            Some(name),
            Some(ERROR_SUCCESS),
            Some(n as u32),
        ));
    }
    Ok(u64::from_le_bytes(out))
}
unsafe fn consume(e: *const EVENT_RECORD, s: &mut Collector) -> Result<Option<End>, &'static str> {
    let h = &(*e).EventHeader;
    if !same_guid(h.ProviderId, FileIoGuid) || !matches!(h.EventDescriptor.Opcode, 64 | 76) {
        return Ok(None);
    }
    let header = SchemaHeader {
        opcode: h.EventDescriptor.Opcode,
        version: h.EventDescriptor.Version,
        flags: h.Flags,
    };
    if !matches!(h.EventDescriptor.Version, 2 | 3) {
        return Err(s.reject(header, SchemaStage::Version, None, None, None));
    }
    if h.Flags as u32 & EVENT_HEADER_FLAG_64_BIT_HEADER == 0
        || h.Flags as u32 & EVENT_HEADER_FLAG_32_BIT_HEADER != 0
    {
        return Err(s.reject(header, SchemaStage::HeaderFlags, None, None, None));
    }
    if h.EventDescriptor.Opcode == 76 {
        let end = End {
            qpc: h.TimeStamp,
            irp: number(e, s, header, KnownProperty::IrpPtr, true)?,
            status: number(e, s, header, KnownProperty::NtStatus, false)? as u32,
        };
        let snapshot = s.published.snapshot();
        let owner = s
            .admission
            .as_mut()
            .ok_or("end_omission_accounting_unavailable")?;
        let handoff = owner.decoded_end(end, snapshot);
        if let Decision::Rejected(reason) = handoff.decision {
            return Err(reason.label());
        }
        return Ok(Some(handoff.end));
    } else {
        // Classic v2 TTID is Pointer-qualified; v3 uses u32 (Microsoft TraceEvent).
        // TDH must resolve the same named property and return the exact versioned width.
        let tid = number(e, s, header, KnownProperty::Ttid, header.version == 2)?;
        let mut path = [0u8; 2048];
        let n = property(e, s, header, KnownProperty::OpenPath, &mut path)?;
        if n % 2 != 0 || n < 2 || path[n - 2..n] != [0, 0] {
            return Err(s.reject(
                header,
                SchemaStage::PathEncoding,
                Some(KnownProperty::OpenPath),
                Some(ERROR_SUCCESS),
                Some(n as u32),
            ));
        }
        if n / 2 != s.path.len() + 1
            || !path[..n - 2]
                .chunks_exact(2)
                .zip(&s.path)
                .all(|(a, b)| u16::from_le_bytes([a[0], a[1]]) == *b)
        {
            return Ok(None); // Other paths are discarded; never printed or retained.
        }
        if s.starts.len() == MAX_STARTS {
            return Err("target_start_capacity_reached");
        }
        let start = Start {
            qpc: h.TimeStamp,
            irp: number(e, s, header, KnownProperty::IrpPtr, true)?,
            share: number(e, s, header, KnownProperty::ShareAccess, false)? as u32,
            tid,
        };
        s.starts.push(start);
    }
    Ok(None)
}
// Only additional begin events need TDH calls. Selected Creates and all Ends
// reuse the original decoder's values. This error channel never calls s.reject.
unsafe fn ownership_irp(e: *const EVENT_RECORD) -> Result<u64, OwnershipReason> {
    let property = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: KnownProperty::IrpPtr.name() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    ownership::read_irp(
        || {
            let mut length = 0;
            if TdhGetPropertySize(e, 0, ptr::null(), 1, &property, &mut length) == 0 {
                Ok(length)
            } else {
                Err(())
            }
        },
        |out| {
            if TdhGetProperty(e, 0, ptr::null(), 1, &property, 8, out.as_mut_ptr()) == 0 {
                Ok(())
            } else {
                Err(())
            }
        },
    )
}
unsafe fn consume_ownership(
    e: *const EVENT_RECORD,
    s: &mut Collector,
    prior_starts: usize,
    decoded_end: Option<End>,
) {
    let h = &(*e).EventHeader;
    if !s.ownership.active() || !same_guid(h.ProviderId, FileIoGuid) {
        return;
    }
    let result = (|| {
        let Some(kind) =
            ownership::kind(h.EventDescriptor.Opcode, h.EventDescriptor.Version, h.Flags)?
        else {
            return Ok(());
        };
        let irp = if h.EventDescriptor.Opcode == 64 && s.starts.len() > prior_starts {
            s.starts[prior_starts].irp
        } else if h.EventDescriptor.Opcode == 76 {
            decoded_end.ok_or(OwnershipReason::Schema)?.irp
        } else {
            ownership_irp(e)?
        };
        s.ownership.push(OwnershipEvent {
            ordinal: s.callbacks,
            qpc: h.TimeStamp,
            irp,
            kind,
        });
        Ok(())
    })();
    if let Err(reason) = result {
        s.ownership.reject(reason);
        if matches!(reason, OwnershipReason::UnsupportedOpcode { .. }) {
            s.metadata.observe(e);
        }
    }
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
        s.error = Some("callback_limit_exceeded");
        return;
    }
    let prior_starts = s.starts.len();
    match consume(e, s) {
        Err(reason) => s.error = Some(reason),
        Ok(decoded_end) => consume_ownership(e, s, prior_starts, decoded_end),
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
    state: CallbackStorage<Collector>,
    log: CallbackStorage<EVENT_TRACE_LOGFILEW>,
    handle: PROCESSTRACE_HANDLE,
}
// Boxes have stable addresses. Only ProcessTrace's one consumer thread accesses
// callback state; the controller sees it only after the thread returns and joins.
unsafe impl Send for Consumer {}
impl Consumer {
    fn release_after_close(&mut self, closed: bool) {
        if closed {
            self.state.allow_drop();
            self.log.allow_drop();
        }
    }
    unsafe fn open(state: Collector) -> Result<Self, &'static str> {
        let mut x = Self {
            state: CallbackStorage::new(state),
            log: CallbackStorage::new(EVENT_TRACE_LOGFILEW::default()),
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
            x.release_after_close(true); // OpenTrace did not acquire a handle.
            return Err("consumer_unavailable");
        }
        Ok(x)
    }
    unsafe fn process(self) -> (u32, Self) {
        let code = ProcessTrace(&self.handle, 1, ptr::null(), ptr::null());
        (code, self) // Keep both callback allocations until controller CloseTrace.
    }
}

#[derive(Default)]
struct Proof {
    started: bool,
    settings: bool,
    bounded: bool,
    lossless: bool,
    stopped: bool,
    absent: bool,
    completed: bool,
    closed: bool,
    joined: bool,
    identity: bool,
}
/// Owns only ETW resources. Never holds a runtime or directory handle.
pub struct Trace {
    published: Arc<PublishedBounds>,
    control: Option<CONTROLTRACE_HANDLE>,
    reader: Option<PROCESSTRACE_HANDLE>,
    worker: Option<JoinHandle<()>>,
    rx: Option<mpsc::Receiver<(u32, Consumer)>>,
    proof: Proof,
    reason: Option<&'static str>,
    path: Vec<u16>,
    identity: Option<BY_HANDLE_FILE_INFORMATION>,
    runtime_sha256: String,
    frequency: i64,
    emitted: bool,
    resource_probe: Option<Option<resource_use_windows::Probe>>,
    prior_probe_closed: bool,
    primary_written: bool,
}
impl Trace {
    pub fn arm(file: &File, runtime_sha256: &str) -> Option<Self> {
        if env::var("TRIAGE_RUNTIME_CLEANUP_TRACE").as_deref() != Ok("1") {
            return None;
        }
        let mut x = Self {
            published: Arc::new(PublishedBounds::default()),
            control: None,
            reader: None,
            worker: None,
            rx: None,
            proof: Proof::default(),
            reason: None,
            path: Vec::new(),
            identity: None,
            runtime_sha256: if runtime_sha256.len() == 64
                && runtime_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                runtime_sha256.into()
            } else {
                "0".repeat(64)
            },
            frequency: 0,
            emitted: false,
            resource_probe: None,
            prior_probe_closed: true,
            primary_written: false,
        };
        // Environment authorization precedes any native identity or ETW call.
        let setup = if !cfg!(target_arch = "aarch64")
            || env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            || env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
            || env::var("RUNNER_ARCH").as_deref() != Ok("ARM64")
            || runtime_sha256.len() != 64
            || !runtime_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Err("unsupported_environment")
        } else {
            unsafe { x.setup(file) }
        };
        if let Err(reason) = setup {
            x.reason = Some(reason);
            if let Some(c) = x.shutdown() {
                if !x.proof.closed {
                    std::mem::forget(c);
                }
            }
        }
        Some(x)
    }
    unsafe fn setup(&mut self, file: &File) -> Outcome {
        let handle = file.as_raw_handle();
        let id = identity(handle)?;
        // Separate explicit opt-in, still behind original hosted ARM64 authorization.
        if env::var("TRIAGE_RUNTIME_RESOURCE_USE").as_deref() == Ok("1") {
            self.resource_probe = Some(resource_use_windows::Probe::capture(file, id));
        }
        let mut path = [0u16; 1024];
        let n =
            GetFinalPathNameByHandleW(handle, path.as_mut_ptr(), path.len() as u32, VOLUME_NAME_NT);
        if n == 0 || n as usize >= path.len() {
            return Err("identity_unavailable");
        }
        if QueryPerformanceFrequency(&mut self.frequency) == 0 || self.frequency <= 0 {
            return Err("clock_unavailable");
        }
        self.path = path[..n as usize].to_vec();
        self.identity = Some(id);
        let mut state = Collector::new(self.path.clone(), Arc::clone(&self.published))?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        state.ready = Some(ready_tx);
        let mut props = Properties::new();
        props.value.BufferSize = 64;
        props.value.MinimumBuffers = 4;
        props.value.MaximumBuffers = 16;
        props.value.LogFileMode = MODE;
        props.value.EnableFlags = FLAGS;
        props.value.FlushTimer = 1;
        let mut control = CONTROLTRACE_HANDLE::default();
        let status = StartTraceW(&mut control, SESSION, &mut props.value);
        if status != ERROR_SUCCESS {
            return Err(match status {
                ERROR_ALREADY_EXISTS => "session_collision",
                ERROR_ACCESS_DENIED => "access_denied",
                _ => "session_unavailable",
            });
        }
        self.control = Some(control);
        self.proof.started = true;
        let mut actual = Properties::new();
        if ControlTraceW(
            control,
            ptr::null(),
            &mut actual.value,
            EVENT_TRACE_CONTROL_QUERY,
        ) != ERROR_SUCCESS
        {
            return Err("session_unavailable");
        }
        self.proof.bounded = actual.bounded();
        self.proof.lossless = actual.lossless();
        self.proof.settings = actual.value.EnableFlags == FLAGS
            && actual.value.LogFileMode == MODE
            && actual.value.Wnode.ClientContext == 1;
        if !self.proof.settings {
            return Err("session_configuration_mismatch");
        }
        if !self.proof.bounded {
            return Err("initial_session_bounds_unverified");
        }
        if !self.proof.lossless {
            return Err("event_loss");
        }
        let mut consumer = Consumer::open(state)?;
        self.reader = Some(consumer.handle);
        let (tx, rx) = mpsc::sync_channel(1);
        self.rx = Some(rx);
        let (bootstrap_tx, bootstrap_rx) = mpsc::sync_channel::<Consumer>(1);
        let worker = std::thread::Builder::new()
            .name("cleanup-etw-consumer".into())
            .spawn(move || {
                if let Ok(consumer) = bootstrap_rx.recv() {
                    let result = consumer.process();
                    if let Err(undelivered) = tx.send(result) {
                        std::mem::forget(undelivered.0);
                    }
                }
            });
        match worker {
            Ok(worker) => self.worker = Some(worker),
            Err(_) => {
                let closed = CloseTrace(self.reader.take().unwrap());
                self.proof.closed = closed == ERROR_SUCCESS;
                consumer.release_after_close(self.proof.closed);
                if !self.proof.closed {
                    std::mem::forget(consumer);
                    return Err("cleanup_uncertain");
                }
                return Err("consumer_unavailable");
            }
        }
        if let Err(mut undelivered) = bootstrap_tx.send(consumer) {
            let closed = CloseTrace(self.reader.take().unwrap());
            self.proof.closed = closed == ERROR_SUCCESS;
            undelivered.0.release_after_close(self.proof.closed);
            if !self.proof.closed {
                std::mem::forget(undelivered.0);
            }
            return Err("cleanup_uncertain");
        }
        ready_rx
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| "consumer_unavailable")?;
        Ok(())
    }
    /// The caller has already checked and dropped the original root pin. Invoke its
    /// original remove closure exactly once. No trace error changes this result.
    pub fn measure(&mut self, remove: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        let (before, tid) = if self.proof.started && self.reason.is_none() {
            unsafe { (qpc(), GetCurrentThreadId() as u64) }
        } else {
            (Err("operation_not_observed"), 0)
        };
        if let Ok(value) = before {
            if let Err(reason) = self.published.publish_before(value) {
                self.reason.get_or_insert(reason.label());
            }
        }
        model::original_then(remove, |original| {
            let after = if before.is_ok() {
                unsafe { qpc() }
            } else {
                Err("operation_not_observed")
            };
            if let Ok(value) = after {
                if let Err(reason) = self.published.publish_after(value) {
                    self.reason.get_or_insert(reason.label());
                }
            }
            let code = original
                .as_ref()
                .err()
                .and_then(|e| e.raw_os_error())
                .map(|v| v as u32);
            // Registration uses the extraction handle. After an actual removal failure,
            // a read-only metadata handle may establish the surviving object's identity;
            // it never authorizes another removal and is never held across the operation.
            if original.is_err() && self.identity.is_some() {
                unsafe {
                    self.verify_survivor();
                }
            }
            let window = before.and_then(|a| after.map(|b| (a, b, tid)));
            self.finish(Some(original.is_ok()), code, window);
            // Failure-only; primary trace has already been attempted and ETW stopped.
            // This runs before returning into private_fs residue inspection.
            if code == Some(32) {
                self.observe_resource_use();
            }
        })
    }
    unsafe fn verify_survivor(&mut self) {
        // NT paths from GetFinalPathNameByHandle are not DOS paths. GLOBALROOT maps
        // this exact registered NT name; there is no basename or relative-path fallback.
        let mut path: Vec<u16> = "\\\\?\\GLOBALROOT".encode_utf16().collect();
        path.extend(&self.path);
        path.push(0);
        let h = CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return;
        }
        self.proof.identity = identity(h)
            .ok()
            .zip(self.identity.as_ref())
            .is_some_and(|(a, b)| same_file(&a, b));
        if CloseHandle(h) == 0 {
            self.proof.identity = false;
            self.prior_probe_closed = false;
            self.reason = Some("cleanup_uncertain");
        }
    }
    fn observe_resource_use(&mut self) {
        let Some(probe) = self.resource_probe.as_mut() else {
            return;
        };
        // Resource closure, not correlation/schema/ownership interpretation, gates RM.
        let closed = self.proof.started
            && self.proof.stopped
            && self.proof.absent
            && self.proof.completed
            && self.proof.closed
            && self.proof.joined;
        let report = if !closed {
            resource_use::Report::unavailable(resource_use::Reason::TraceUnclosed)
        } else if !self.prior_probe_closed {
            resource_use::Report::unavailable(resource_use::Reason::PriorProbeUnclosed)
        } else if !self.primary_written {
            resource_use::Report::unavailable(resource_use::Reason::PrimaryUnwritten)
        } else if let Some(probe) = probe {
            resource_use::observe(probe)
        } else {
            resource_use::Report::unavailable(resource_use::Reason::RegistrationUnavailable)
        };
        if let Some(line) = report.line(&self.runtime_sha256, closed, self.prior_probe_closed) {
            let _ = io::stderr().lock().write_all(line.as_bytes());
        }
    }
    fn shutdown(&mut self) -> Option<Consumer> {
        let mut consumer = None;
        unsafe {
            if let Some(handle) = self.control.take() {
                let mut stopped = Properties::new();
                let status = ControlTraceW(
                    handle,
                    ptr::null(),
                    &mut stopped.value,
                    EVENT_TRACE_CONTROL_STOP,
                );
                self.proof.stopped = status == ERROR_SUCCESS;
                self.proof.lossless &= status == ERROR_SUCCESS && stopped.lossless();
                self.proof.bounded &= status == ERROR_SUCCESS && stopped.bounded();
                let mut absent = Properties::new();
                self.proof.absent = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    SESSION,
                    &mut absent.value,
                    EVENT_TRACE_CONTROL_QUERY,
                ) == ERROR_WMI_INSTANCE_NOT_FOUND;
            }
            if let Some(reader) = self.reader.take() {
                let completion = self
                    .rx
                    .as_ref()
                    .and_then(|rx| rx.recv_timeout(Duration::from_secs(10)).ok());
                let close = CloseTrace(reader);
                self.proof.closed = close == ERROR_SUCCESS;
                if let Some((code, mut c)) = completion {
                    self.proof.completed = code == ERROR_SUCCESS;
                    c.release_after_close(self.proof.closed);
                    consumer = Some(c);
                } else if let Some((_, mut late)) = self
                    .rx
                    .as_ref()
                    .and_then(|rx| rx.recv_timeout(Duration::from_secs(5)).ok())
                {
                    // Late completion cannot earn drain proof. Keep storage if close uncertain.
                    late.release_after_close(self.proof.closed);
                    if close != ERROR_SUCCESS && close != ERROR_CTX_CLOSE_PENDING {
                        std::mem::forget(late);
                    }
                }
            }
            if let Some(worker) = self.worker.take() {
                // A bounded wait on the owned Rust thread handle precedes join. Never wait
                // unboundedly just because ProcessTrace delivered its result channel.
                if WaitForSingleObject(worker.as_raw_handle(), 1000) == WAIT_OBJECT_0 {
                    self.proof.joined = worker.join().is_ok();
                }
            }
        }
        consumer
    }
    fn finish(
        &mut self,
        original: Option<bool>,
        os_code: Option<u32>,
        window: Result<(i64, i64, u64), &'static str>,
    ) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        let consumer = self.shutdown();
        let cleanup = self.proof.stopped
            && self.proof.absent
            && self.proof.completed
            && self.proof.closed
            && self.proof.joined;
        let mut counts = None;
        let mut rejection = None;
        let mut ownership = None;
        let mut metadata = None;
        if let Some(mut c) = consumer {
            rejection = c.state.schema_rejection.map(SchemaRejection::json);
            metadata = c.state.metadata.observation;
            if c.state.error == Some("event_loss") {
                self.proof.lossless = false;
            }
            if self.reason.is_none() {
                self.reason = c.state.error;
            }
            if self.reason.is_none() {
                match window {
                    Err(reason) => self.reason = Some(reason),
                    Ok((a, b, tid)) => {
                        let gate = CaptureGate {
                            drained: cleanup,
                            started: self.proof.started,
                            settings: self.proof.settings,
                            lossless: self.proof.lossless,
                            bounded: self.proof.bounded,
                        };
                        let snapshot = c.state.published.snapshot();
                        if let Some(proof) = admission::prove_if_complete(
                            &mut c.state.admission,
                            snapshot,
                            a,
                            b,
                            gate,
                        ) {
                            match proof {
                                Err(reason) => self.reason = Some(reason.label()),
                                Ok(ends) => {
                                    match model::correlate(
                                        &c.state.starts,
                                        ends.as_slice(),
                                        a,
                                        b,
                                        tid,
                                    ) {
                                        Ok(v) => counts = Some(v),
                                        Err(e) => self.reason = Some(e),
                                    }
                                    if self.reason == Some("correlation_end_multiple") {
                                        ownership = Some(c.state.ownership.report(
                                            &c.state.starts,
                                            ends.as_slice(),
                                            window,
                                            self.reason,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if !self.proof.closed {
                std::mem::forget(c);
            }
        }
        if self.proof.started && !cleanup {
            self.reason = Some("cleanup_uncertain");
        }
        if self.reason.is_none() && !self.proof.lossless {
            self.reason = Some("event_loss");
        }
        if self.reason.is_none() && !self.proof.bounded {
            self.reason = Some("final_bounds_proof_unverified");
        }
        if original == Some(false) && !self.proof.identity && self.reason.is_none() {
            self.reason = Some("identity_unavailable");
        }
        let duration = window.ok().and_then(|(a, b, _)| {
            if b < a || self.frequency <= 0 {
                return None;
            }
            let us = (b as i128 - a as i128) * 1_000_000 / self.frequency as i128;
            (0..=180_000_000).contains(&us).then_some(us as u64)
        });
        if duration.is_none() && self.reason.is_none() {
            self.reason = Some("clock_unavailable");
        }
        let status = if self.reason.is_some() {
            "unavailable"
        } else if original == Some(true) {
            "not_reproduced"
        } else if os_code == Some(32) && counts.as_ref().is_some_and(|c| c.sharing > 0) {
            "observed"
        } else {
            self.reason = Some("status_not_attributed");
            "unavailable"
        };
        let nullable = |x: Option<u64>| x.map_or_else(|| "null".into(), |v| v.to_string());
        let counted = counts.map_or_else(
            || "null".into(),
            |c: Counts| {
                format!(
                    "{{\"attempts\":{},\"successful\":{},\"sharing\":{},\"other\":{}}}",
                    c.attempts, c.successful, c.sharing, c.other
                )
            },
        );
        let ownership = if self.reason != Some("correlation_end_multiple") {
            "null".into()
        } else {
            let observed = if !cleanup || !self.proof.started || !self.proof.settings {
                ownership::Report::Unavailable(OwnershipReason::Teardown)
            } else if !self.proof.lossless {
                ownership::Report::Unavailable(OwnershipReason::EventLoss)
            } else if !self.proof.bounded {
                ownership::Report::Unavailable(OwnershipReason::Budget)
            } else if duration.is_none() {
                ownership::Report::Unavailable(OwnershipReason::Window)
            } else {
                ownership.unwrap_or(ownership::Report::Unavailable(OwnershipReason::Teardown))
            };
            observed.json()
        };
        let record=format!("{{\"schema\":4,\"capture_contract\":\"{}\",\"scope\":\"original_runtime_remove_tree\",\"status\":\"{}\",\"reason\":\"{}\",\"original_ok\":{},\"os_code\":{},\"operation_us\":{},\"runtime_sha256\":\"{}\",\"target_identity_verified\":{},\"session_started\":{},\"settings_verified\":{},\"bounded\":{},\"zero_loss\":{},\"stop_succeeded\":{},\"session_absent\":{},\"consumer_completed\":{},\"consumer_closed\":{},\"worker_joined\":{},\"counts\":{},\"schema_rejection\":{},\"ownership\":{}}}",admission::CAPTURE_CONTRACT,status,self.reason.unwrap_or("none"),original.map_or_else(||"null".into(),|v|v.to_string()),nullable(os_code.map(u64::from)),nullable(duration),self.runtime_sha256,self.proof.identity,self.proof.started,self.proof.settings,self.proof.bounded,self.proof.lossless,self.proof.stopped,self.proof.absent,self.proof.completed,self.proof.closed,self.proof.joined,counted,rejection.unwrap_or_else(||"null".into()),ownership);
        if record.len() <= 4096 {
            self.primary_written =
                writeln!(io::stderr().lock(), "runtime_cleanup_trace={record}").is_ok();
        }
        // Separate metadata never supplies original counts/reasons or cleanup proof.
        let schema = schema_metadata::json(
            metadata,
            cleanup
                && self.proof.started
                && self.proof.settings
                && self.proof.bounded
                && self.proof.lossless
                && duration.is_some(),
            &self.runtime_sha256,
        );
        if schema.len() <= 8192 {
            let _ = writeln!(io::stderr().lock(), "runtime_cleanup_schema={schema}");
        }
    }
}
impl Drop for Trace {
    fn drop(&mut self) {
        self.finish(None, None, Err("operation_not_observed"));
    }
}
unsafe fn qpc() -> Result<i64, &'static str> {
    let mut x = 0;
    if QueryPerformanceCounter(&mut x) == 0 || x <= 0 {
        Err("clock_unavailable")
    } else {
        Ok(x)
    }
}
unsafe fn identity(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, &'static str> {
    let mut x = BY_HANDLE_FILE_INFORMATION::default();
    if GetFileInformationByHandle(handle, &mut x) == 0
        || x.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || x.nNumberOfLinks != 1
    {
        Err("identity_unavailable")
    } else {
        Ok(x)
    }
}
pub(crate) fn same_file(a: &BY_HANDLE_FILE_INFORMATION, b: &BY_HANDLE_FILE_INFORMATION) -> bool {
    a.dwVolumeSerialNumber == b.dwVolumeSerialNumber
        && a.nFileIndexHigh == b.nFileIndexHigh
        && a.nFileIndexLow == b.nFileIndexLow
        && a.nFileSizeHigh == b.nFileSizeHigh
        && a.nFileSizeLow == b.nFileSizeLow
        && a.ftLastWriteTime.dwHighDateTime == b.ftLastWriteTime.dwHighDateTime
        && a.ftLastWriteTime.dwLowDateTime == b.ftLastWriteTime.dwLowDateTime
}
