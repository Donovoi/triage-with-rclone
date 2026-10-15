//! Two fixed snapshots of one owned synthetic file. No original cleanup is run.
use crate::resource_use::{self, Api, Reason, Report};
use crate::resource_use_windows::Probe;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, IntoRawHandle},
    },
    path::PathBuf,
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*};

const PREFIX: &str = "runtime_resource_use_calibration=";
const BODY: &[u8] = b"Synthetic Restart Manager calibration.\n";

struct Comparison {
    held: Report,
    released: Option<Report>,
    handle_closed: bool,
}
fn compare(api: &mut impl Api, close: &mut impl FnMut() -> bool) -> Comparison {
    let held = resource_use::observe(api);
    let handle_closed = close(); // Once, including after an unavailable first query.
    let released = if held.reason == Reason::None && handle_closed {
        Some(resource_use::observe(api))
    } else {
        None
    };
    Comparison {
        held,
        released,
        handle_closed,
    }
}
fn query_closed(report: &Report) -> bool {
    report.pre.is_some_and(|p| p.closed)
        && (report.statuses[0] != Some(0)
            || report.statuses[3] == Some(0) && report.post.is_some_and(|p| p.closed))
}
fn reason(c: &Comparison, cleanup: bool) -> &'static str {
    if !cleanup {
        "cleanup_unverified"
    } else if c.held.reason != Reason::None {
        "held_query_unavailable"
    } else if !c.held.counts.is_some_and(|n| n.total == 1 && n.caller) {
        "caller_not_observed"
    } else if c.released.as_ref().is_none_or(|r| r.reason != Reason::None) {
        "released_query_unavailable"
    } else if !c
        .released
        .as_ref()
        .and_then(|r| r.counts)
        .is_some_and(|n| n.total == 0 && !n.caller)
    {
        "control_not_empty"
    } else {
        "none"
    }
}
fn phase(r: &Report) -> String {
    let num = |n: Option<u32>| n.map_or_else(|| "null".into(), |v| v.to_string());
    let flag = |b: Option<bool>| b.map_or_else(|| "null".into(), |v| v.to_string());
    format!("{{\"available\":{},\"api\":[{},{},{},{}],\"identity\":[{},{},{},{}],\"total\":{},\"caller\":{}}}",
        r.reason == Reason::None, num(r.statuses[0]),num(r.statuses[1]),num(r.statuses[2]),num(r.statuses[3]),
        flag(r.pre.map(|p|p.matched)),flag(r.pre.map(|p|p.closed)),flag(r.post.map(|p|p.matched)),flag(r.post.map(|p|p.closed)),
        num(r.counts.map(|c|c.total)),flag(r.counts.map(|c|c.caller)))
}

struct Owned {
    root: PathBuf,
    file: PathBuf,
    root_created: bool,
    file_created: bool,
    creator_closed: bool,
    directory: Option<HANDLE>,
    held: Option<HANDLE>,
    root_valid: bool,
    probe: Option<Probe>,
}
impl Owned {
    fn new(root: PathBuf) -> Self {
        Self {
            file: root.join("synthetic.bin"),
            root,
            root_created: false,
            file_created: false,
            creator_closed: false,
            directory: None,
            held: None,
            root_valid: false,
            probe: None,
        }
    }
    fn prepare(&mut self) -> Result<(), ()> {
        fs::create_dir(&self.root).map_err(|_| ())?;
        self.root_created = true;
        let dir = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.root)
            .map_err(|_| ())?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        self.root_valid = unsafe {
            GetFileInformationByHandle(dir.as_raw_handle(), &mut info) != 0
                && GetFileType(dir.as_raw_handle()) == FILE_TYPE_DISK
                && info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
                && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        };
        self.directory = Some(dir.into_raw_handle());
        if !self.root_valid {
            return Err(());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE) // Deliberately excludes DELETE.
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.file)
            .map_err(|_| ())?;
        self.file_created = true;
        let written = file.write_all(BODY).and_then(|()| file.flush()).is_ok();
        let mut identity = BY_HANDLE_FILE_INFORMATION::default();
        let valid = unsafe {
            GetFileInformationByHandle(file.as_raw_handle(), &mut identity) != 0
                && GetFileType(file.as_raw_handle()) == FILE_TYPE_DISK
                && identity.dwFileAttributes
                    & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                    == 0
                && identity.nNumberOfLinks == 1
                && identity.nFileSizeHigh == 0
                && identity.nFileSizeLow as usize == BODY.len()
        };
        // Close the writer before capturing the stable last-write stamp. The
        // retained calibration handle is read-only and independently identity checked.
        self.creator_closed = unsafe { CloseHandle(file.into_raw_handle()) != 0 };
        if !written || !valid || !self.creator_closed {
            return Err(());
        }
        let mut held = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.file)
            .map_err(|_| ())?;
        let mut current = BY_HANDLE_FILE_INFORMATION::default();
        let same = unsafe {
            GetFileInformationByHandle(held.as_raw_handle(), &mut current) != 0
                && GetFileType(held.as_raw_handle()) == FILE_TYPE_DISK
                && current.dwFileAttributes
                    & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                    == 0
                && current.nNumberOfLinks == 1
                && current.dwVolumeSerialNumber == identity.dwVolumeSerialNumber
                && current.nFileIndexHigh == identity.nFileIndexHigh
                && current.nFileIndexLow == identity.nFileIndexLow
                && current.nFileSizeHigh == 0
                && current.nFileSizeLow as usize == BODY.len()
        };
        let mut content = [0u8; BODY.len()];
        let content_ok = held.read_exact(&mut content).is_ok() && content == BODY;
        if same && content_ok {
            self.probe = unsafe { Probe::capture(&held, current) };
        }
        self.held = Some(held.into_raw_handle()); // Explicit checked CloseHandle; no hidden Drop retry.
        if self.probe.is_none() {
            return Err(());
        }
        Ok(())
    }
    fn close_held(&mut self) -> bool {
        self.held
            .take()
            .is_none_or(|handle| unsafe { CloseHandle(handle) != 0 })
    }
    fn cleanup(&mut self, file_closed: bool, queries_closed: bool) -> Cleanup {
        // This last identity probe happens after both snapshots, never across GetList.
        let verified = if self.creator_closed && file_closed && queries_closed {
            self.probe.as_mut().map(|api| api.probe())
        } else {
            None
        };
        let identity_closed = verified.is_some_and(|p| p.matched && p.closed);
        let file_removed = self.file_created
            && self.root_valid
            && identity_closed
            && fs::remove_file(&self.file).is_ok();
        let directory_closed = self
            .directory
            .take()
            .is_none_or(|h| unsafe { CloseHandle(h) != 0 });
        let directory_removed = self.root_created
            && self.root_valid
            && directory_closed
            && (!self.file_created || file_removed)
            && queries_closed
            && file_closed
            && fs::remove_dir(&self.root).is_ok(); // Empty directory only; never recursive.
        Cleanup {
            identity_closed,
            file_removed,
            directory_closed,
            directory_removed,
        }
    }
}
struct Cleanup {
    identity_closed: bool,
    file_removed: bool,
    directory_closed: bool,
    directory_removed: bool,
}
impl Cleanup {
    fn complete(&self) -> bool {
        self.identity_closed && self.file_removed && self.directory_closed && self.directory_removed
    }
}
fn authorized() -> bool {
    cfg!(target_arch = "aarch64")
        && [
            ("GITHUB_ACTIONS", "true"),
            ("RUNNER_ENVIRONMENT", "github-hosted"),
            ("RUNNER_OS", "Windows"),
            ("RUNNER_ARCH", "ARM64"),
            ("TRIAGE_RM_CALIBRATION", "1"),
        ]
        .iter()
        .all(|(key, value)| std::env::var(key).as_deref() == Ok(*value))
}
fn root_path() -> Option<PathBuf> {
    let root = PathBuf::from(std::env::var_os("TRIAGE_RM_CALIBRATION_ROOT")?);
    let temp = PathBuf::from(std::env::var_os("RUNNER_TEMP")?);
    let name = root
        .file_name()?
        .to_str()?
        .strip_prefix("rm-calibration-")?;
    let dos = root.to_str()?;
    let bytes = dos.as_bytes();
    if dos.encode_utf16().count() > 240
        || bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || &bytes[1..3] != b":\\"
        || dos[3..].split('\\').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with(['.', ' '])
                || part
                    .chars()
                    .any(|c| c <= '\u{1f}' || "<>:\"/|?*".contains(c))
        })
    {
        return None;
    }
    if !root.is_absolute()
        || !temp.is_absolute()
        || root.parent() != Some(temp.as_path())
        || name.len() != 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    Some(root)
}
fn run() -> (String, bool) {
    let mut setup = false;
    let mut creator_closed = false;
    let mut comparison = None;
    let mut closed = false;
    let mut cleanup = Cleanup {
        identity_closed: false,
        file_removed: false,
        directory_closed: false,
        directory_removed: false,
    };
    let mut failure = "environment";
    if authorized() {
        failure = "setup";
        if let Some(root) = root_path() {
            let mut owned = Owned::new(root);
            setup = owned.prepare().is_ok();
            creator_closed = owned.creator_closed;
            if setup {
                let mut api = owned.probe.take().expect("calibration_probe");
                let value = compare(&mut api, &mut || owned.close_held());
                closed = value.handle_closed;
                let quiescent =
                    query_closed(&value.held) && value.released.as_ref().is_none_or(query_closed);
                owned.probe = Some(api);
                cleanup = owned.cleanup(closed, quiescent);
                failure = reason(&value, cleanup.complete() && quiescent && closed);
                comparison = Some(value);
            } else {
                closed = owned.close_held();
                cleanup = owned.cleanup(closed, true);
            }
        }
    }
    let passed = failure == "none";
    let held = comparison
        .as_ref()
        .map_or_else(|| "null".into(), |c| phase(&c.held));
    let released = comparison
        .as_ref()
        .and_then(|c| c.released.as_ref())
        .map_or_else(|| "null".into(), phase);
    let line = format!("{PREFIX}{{\"schema\":1,\"scope\":\"synthetic_rm_calibration\",\"causal_owner\":false,\"runtime_executed\":false,\"hard_deadline\":false,\"setup\":{setup},\"creator_closed\":{creator_closed},\"held\":{held},\"released\":{released},\"handle_closed\":{closed},\"identity_closed\":{},\"file_removed\":{},\"directory_closed\":{},\"directory_removed\":{},\"cleanup_complete\":{},\"reason\":\"{failure}\",\"passed\":{passed}}}\n", cleanup.identity_closed, cleanup.file_removed, cleanup.directory_closed, cleanup.directory_removed, cleanup.complete() && creator_closed && closed && comparison.as_ref().is_some_and(|c| query_closed(&c.held) && c.released.as_ref().is_none_or(query_closed)));
    (line, passed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_use::{Counts, Probe as Check, Query};
    use std::{cell::RefCell, rc::Rc};
    struct Fake {
        calls: Rc<RefCell<Vec<&'static str>>>,
        phase: usize,
        counts: [Counts; 2],
        end: u32,
    }
    impl Api for Fake {
        fn probe(&mut self) -> Check {
            self.calls.borrow_mut().push("probe");
            Check {
                matched: true,
                closed: true,
            }
        }
        fn start(&mut self) -> u32 {
            self.calls.borrow_mut().push("start");
            0
        }
        fn register(&mut self) -> u32 {
            self.calls.borrow_mut().push("register");
            0
        }
        fn list(&mut self) -> Query {
            self.calls.borrow_mut().push("list");
            Query {
                status: 0,
                counts: Ok(self.counts[self.phase]),
            }
        }
        fn end(&mut self) -> u32 {
            self.calls.borrow_mut().push("end");
            self.phase += 1;
            self.end
        }
    }
    fn fake() -> Fake {
        Fake {
            calls: Rc::new(RefCell::new(vec![])),
            phase: 0,
            counts: [
                Counts {
                    total: 1,
                    caller: true,
                    types: [1, 0, 0, 0, 0, 0, 0],
                },
                Counts::default(),
            ],
            end: 0,
        }
    }
    #[test]
    fn pure_two_queries_and_close_once() {
        let mut f = fake();
        let calls = Rc::clone(&f.calls);
        let mut closes = 0;
        let c = compare(&mut f, &mut || {
            closes += 1;
            calls.borrow_mut().push("close");
            true
        });
        assert_eq!(closes, 1);
        assert_eq!(f.phase, 2);
        assert_eq!(reason(&c, true), "none");
        assert_eq!(
            *f.calls.borrow(),
            [
                "probe", "start", "register", "list", "end", "probe", "close", "probe", "start",
                "register", "list", "end", "probe"
            ]
        );
        assert_eq!(reason(&c, false), "cleanup_unverified");
    }
    #[test]
    fn pure_unsupported_caller_or_control_never_passes() {
        for before in [true, false] {
            let mut f = fake();
            if before {
                f.counts[0] = Counts::default()
            } else {
                f.counts[1] = f.counts[0]
            }
            let c = compare(&mut f, &mut || true);
            assert_ne!(reason(&c, true), "none");
            assert_eq!(f.phase, 2);
        }
    }
    #[test]
    fn pure_failed_close_or_end_blocks_second_query() {
        for end in [0, 5] {
            let mut f = fake();
            f.end = end;
            let mut closes = 0;
            let c = compare(&mut f, &mut || {
                closes += 1;
                end != 0
            });
            assert_eq!(closes, 1);
            assert!(c.released.is_none());
            assert_eq!(f.phase, 1);
            assert!(!c.handle_closed || !query_closed(&c.held));
        }
    }
    #[test]
    #[ignore = "explicit hosted ARM64 calibration only"]
    fn hosted_held_file_then_closed() {
        let (line, passed) = run();
        let written = line.len() <= 1024 && io::stderr().lock().write_all(line.as_bytes()).is_ok();
        assert!(written && passed, "rm_calibration_unavailable");
    }
}
