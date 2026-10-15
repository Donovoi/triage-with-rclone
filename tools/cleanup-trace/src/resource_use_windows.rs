//! Windows boundary, called only after the original failure and observer closure.
use crate::resource_use::{Api, Counts, Probe as Check, Query, Reason, CAPACITY};
use std::{fs::File, os::windows::io::AsRawHandle, ptr};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{
        RestartManager::*,
        Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes},
    },
};

// SDK layout on Windows x64/ARM64. Only the fixed-size array is passed to RM.
const _: () = assert!(std::mem::size_of::<RM_PROCESS_INFO>() == 668);

pub struct Probe {
    path: Vec<u16>,
    identity: BY_HANDLE_FILE_INFORMATION,
    caller: RM_UNIQUE_PROCESS,
    session: u32,
}
impl Probe {
    /// Uses only the already-owned extraction handle; stores no file/process handle.
    pub unsafe fn capture(file: &File, identity: BY_HANDLE_FILE_INFORMATION) -> Option<Self> {
        let mut raw = [0u16; 264];
        let n = GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            raw.as_mut_ptr(),
            raw.len() as u32,
            VOLUME_NAME_DOS,
        );
        if n == 0 || n as usize >= raw.len() {
            return None;
        }
        let path = dos_path(&raw[..n as usize])?;
        let mut caller = RM_UNIQUE_PROCESS {
            dwProcessId: GetCurrentProcessId(),
            ..Default::default()
        };
        let (mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        if caller.dwProcessId == 0
            || GetProcessTimes(
                GetCurrentProcess(),
                &mut caller.ProcessStartTime,
                &mut exit,
                &mut kernel,
                &mut user,
            ) == 0
            || time(caller.ProcessStartTime) == 0
        {
            return None;
        }
        Some(Self {
            path,
            identity,
            caller,
            session: 0,
        })
    }
}
// RM takes a full filename. Restrict to a regular local DOS path below MAX_PATH.
// Strip only the documented extended local-drive prefix; never GLOBALROOT/UNC.
fn dos_path(raw: &[u16]) -> Option<Vec<u16>> {
    let name = String::from_utf16(raw).ok()?;
    let value = name.strip_prefix("\\\\?\\")?;
    let bytes = value.as_bytes();
    if raw.len() > 263
        || value.encode_utf16().count() > 259
        || bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || &bytes[1..3] != b":\\"
        || value[3..].split('\\').any(|p| {
            p.is_empty()
                || p == "."
                || p == ".."
                || p.ends_with(['.', ' '])
                || p.chars().any(|c| c <= '\u{1f}' || "<>:\"/|?*".contains(c))
        })
    {
        return None;
    }
    let mut path: Vec<u16> = value.encode_utf16().collect();
    path.push(0);
    Some(path)
}
fn time(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}
fn same_process(a: RM_UNIQUE_PROCESS, b: RM_UNIQUE_PROCESS) -> bool {
    a.dwProcessId == b.dwProcessId && time(a.ProcessStartTime) == time(b.ProcessStartTime)
}
fn summarize(rows: &[RM_PROCESS_INFO], caller: RM_UNIQUE_PROCESS) -> Result<Counts, Reason> {
    let mut counts = Counts::default();
    for (index, row) in rows.iter().enumerate() {
        if row.Process.dwProcessId == 0
            || time(row.Process.ProcessStartTime) == 0
            || row.AppStatus & !255 != 0
            || !matches!(row.bRestartable, 0 | 1)
            || rows[..index]
                .iter()
                .any(|old| same_process(old.Process, row.Process))
        {
            return Err(Reason::Shape);
        }
        let bucket = match row.ApplicationType {
            0..=5 => row.ApplicationType as usize,
            1000 => 6,
            _ => return Err(Reason::Shape),
        };
        counts.total += 1;
        counts.types[bucket] += 1;
        counts.caller |= same_process(row.Process, caller);
    }
    Ok(counts)
}
impl Api for Probe {
    fn probe(&mut self) -> Check {
        unsafe {
            let handle = CreateFileW(
                self.path.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Check {
                    matched: false,
                    closed: true,
                };
            }
            let mut now = BY_HANDLE_FILE_INFORMATION::default();
            let matched = GetFileInformationByHandle(handle, &mut now) != 0
                && now.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                    == 0
                && now.nNumberOfLinks == 1
                && crate::native::same_file(&now, &self.identity);
            let closed = CloseHandle(handle) != 0;
            Check { matched, closed }
        }
    }
    fn start(&mut self) -> u32 {
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        let status = unsafe { RmStartSession(&mut self.session, 0, key.as_mut_ptr()) };
        key.fill(0);
        status
    }
    fn register(&mut self) -> u32 {
        let file = self.path.as_ptr();
        unsafe { RmRegisterResources(self.session, 1, &file, 0, ptr::null(), 0, ptr::null()) }
    }
    fn list(&mut self) -> Query {
        let mut rows = [RM_PROCESS_INFO::default(); CAPACITY];
        let (mut needed, mut filled, mut reboot) = (0, CAPACITY as u32, 0);
        let status = unsafe {
            RmGetList(
                self.session,
                &mut needed,
                &mut filled,
                rows.as_mut_ptr(),
                &mut reboot,
            )
        };
        let counts =
            if status == 0 && filled <= CAPACITY as u32 && needed == filled && reboot & !31 == 0 {
                summarize(&rows[..filled as usize], self.caller)
            } else {
                Err(Reason::Shape)
            };
        rows.fill(RM_PROCESS_INFO::default());
        Query { status, counts }
    }
    fn end(&mut self) -> u32 {
        unsafe { RmEndSession(self.session) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dos_name_is_closed_and_bounded() {
        for value in [
            "C:\\x.exe",
            "\\\\?\\UNC\\server\\x",
            "\\\\?\\GLOBALROOT\\x",
            "\\\\?\\C:\\..\\x",
            "\\\\?\\C:\\x:stream",
            "\\\\?\\C:\\x.\\y",
            "\\\\?\\C:\\x\0",
        ] {
            assert!(dos_path(&value.encode_utf16().collect::<Vec<_>>()).is_none());
        }
        assert_eq!(
            dos_path(
                &"\\\\?\\C:\\private\\rclone.exe"
                    .encode_utf16()
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            "C:\\private\\rclone.exe\0"
                .encode_utf16()
                .collect::<Vec<_>>()
        );
        assert!(dos_path(&[0xd800]).is_none());
        assert!(dos_path(
            &format!("\\\\?\\C:\\{}", "x".repeat(260))
                .encode_utf16()
                .collect::<Vec<_>>()
        )
        .is_none());
    }
    #[test]
    fn caller_requires_pid_and_creation_identity() {
        let caller = RM_UNIQUE_PROCESS {
            dwProcessId: 7,
            ProcessStartTime: FILETIME {
                dwLowDateTime: 9,
                dwHighDateTime: 0,
            },
        };
        let mut row = RM_PROCESS_INFO {
            Process: caller,
            ApplicationType: RmConsole,
            ..Default::default()
        };
        assert!(summarize(&[row], caller).unwrap().caller);
        row.Process.ProcessStartTime.dwLowDateTime += 1;
        assert!(!summarize(&[row], caller).unwrap().caller);
        assert!(summarize(&[row, row], caller).is_err());
        row.ApplicationType = 999;
        assert!(summarize(&[row], caller).is_err());
        row.ApplicationType = RmConsole;
        row.bRestartable = 2;
        assert!(summarize(&[row], caller).is_err());
    }
}
