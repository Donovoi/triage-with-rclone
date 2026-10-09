//! Creation-time privacy for application-owned artifacts.
//!
//! Existing ancestors are never re-owned or chmodded. Windows ownership comes
//! from TokenUser explicitly, not the process token's default owner. Returned
//! files retain the verified handle; callers must write through that handle.
//! These helpers do not govern files subsequently created/replaced by rclone.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use tempfile::NamedTempFile;

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[derive(Clone, Copy, Debug)]
enum CleanupStage {
    Target,
    OpenRoot,
    Identity,
    Security,
    RemoveTree,
}

impl CleanupStage {
    fn name(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::OpenRoot => "open_root",
            Self::Identity => "identity",
            Self::Security => "security",
            Self::RemoveTree => "remove_tree",
        }
    }
}

/// Closed, path-free runtime cleanup observation. Display is compact ASCII JSON.
#[derive(Clone, Copy, Debug)]
pub struct CleanupDiagnostic {
    stage: CleanupStage,
    kind: &'static str,
    os_code: Option<i32>,
    residue: Option<CleanupResidue>,
}

/// A bounded observation after failed removal, never a cleanup/holder verdict.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct CleanupResidue {
    root: &'static str,
    executable: &'static str,
    other_files: Option<u8>,
    other_directories: Option<u8>,
    other_reparse_points: Option<u8>,
    other_entries: Option<u8>,
    complete: bool,
}

impl CleanupResidue {
    fn unavailable() -> Self {
        Self {
            root: "unavailable",
            executable: "unavailable",
            other_files: None,
            other_directories: None,
            other_reparse_points: None,
            other_entries: None,
            complete: false,
        }
    }
}

impl std::fmt::Display for CleanupResidue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&serde_json::to_string(self).map_err(|_| std::fmt::Error)?)
    }
}

impl CleanupDiagnostic {
    /// Ownership was already lost/refused; there is no safe cleanup retry.
    pub fn ownership_unavailable() -> Self {
        Self {
            stage: CleanupStage::Identity,
            kind: "other",
            os_code: None,
            residue: None,
        }
    }

    pub fn residue(&self) -> Option<CleanupResidue> {
        self.residue
    }
}

impl std::fmt::Display for CleanupDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\"stage\":\"{}\",\"kind\":\"{}\",\"os_code\":",
            self.stage.name(),
            self.kind
        )?;
        match self.os_code {
            Some(code) => write!(f, "{code}"),
            None => f.write_str("null"),
        }?;
        f.write_str("}")
    }
}

#[derive(Debug)]
struct CleanupFailure {
    stage: CleanupStage,
    source: io::Error,
    residue: Option<CleanupResidue>,
}

impl std::fmt::Display for CleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Private directory cleanup failed at {}",
            self.stage.name()
        )
    }
}

impl std::error::Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn cleanup_failure(stage: CleanupStage, source: io::Error) -> io::Error {
    io::Error::new(
        source.kind(),
        CleanupFailure {
            stage,
            source,
            residue: None,
        },
    )
}

/// Classify only errors produced by the identity-checked cleanup path.
pub fn cleanup_diagnostic(error: &io::Error) -> Option<CleanupDiagnostic> {
    let failure = error.get_ref()?.downcast_ref::<CleanupFailure>()?;
    let kind = match failure.source.kind() {
        io::ErrorKind::NotFound => "not_found",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::AlreadyExists => "already_exists",
        io::ErrorKind::InvalidInput => "invalid_input",
        io::ErrorKind::Unsupported => "unsupported",
        io::ErrorKind::Interrupted => "interrupted",
        _ => "other",
    };
    Some(CleanupDiagnostic {
        stage: failure.stage,
        kind,
        os_code: failure
            .source
            .raw_os_error()
            .filter(|code| (0..=65535).contains(code)),
        residue: failure.residue,
    })
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    // Check the original spelling before Windows absolute-path normalization
    // can discard a trailing dot/space or resolve a drive-relative path.
    for component in path.components() {
        if let Component::Normal(name) = component {
            platform::validate_name(name)?;
        }
    }
    #[cfg(windows)]
    if path.components().any(|c| matches!(c, Component::Prefix(_))) && !path.is_absolute() {
        return Err(refused("Drive-relative artifact path is ambiguous"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(refused("Parent traversal is not an owned artifact path"));
    }
    std::path::absolute(path)
}

// Pin each existing ancestor before descending. In particular, canonicalization
// must not silently accept a junction/symlink in the user-supplied path.
fn directory(path: &Path) -> io::Result<(PathBuf, Vec<File>)> {
    let path = absolute(path)?;
    let mut current = PathBuf::new();
    let mut pins = Vec::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::CurDir) {
            continue;
        }
        pins.push(platform::open_directory(&current)?);
    }
    Ok((fs::canonicalize(path)?, pins))
}

fn target(path: &Path) -> io::Result<(PathBuf, Vec<File>)> {
    let path = absolute(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| refused("Artifact needs a file name"))?;
    platform::validate_name(name)?;
    let (parent, pins) = directory(
        path.parent()
            .ok_or_else(|| refused("Artifact needs a parent"))?,
    )?;
    Ok((parent.join(name), pins))
}

/// Exclusively create one private directory; existing paths are not changed.
pub fn create_dir(path: impl AsRef<Path>) -> io::Result<()> {
    let (path, _parents) = target(path.as_ref())?;
    platform::create_dir(&path)
}

/// Create missing components privately, validating but never altering ancestors.
pub fn create_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    create_dir_all_inner(path.as_ref(), |_| Ok(()))
}

fn create_dir_all_inner(
    path: &Path,
    mut before_create: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let path = absolute(path)?;
    let mut current = PathBuf::new();
    let mut pins = Vec::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::CurDir) {
            continue;
        }
        match platform::open_directory(&current) {
            Ok(pin) => pins.push(pin),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = current
                    .file_name()
                    .ok_or_else(|| refused("Missing filesystem root"))?;
                platform::validate_name(name)?;
                before_create(&current)?;
                match platform::create_dir(&current) {
                    Ok(()) => pins.push(platform::open_directory(&current)?),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        // Another acquisition worker may have created this missing
                        // component. Only a verified private directory can win;
                        // never accept or repair a file, reparse point or broad ACL.
                        let pin = platform::open_directory(&current)?;
                        platform::verify_private(&pin, true)?;
                        pins.push(pin);
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Verify an explicitly application-owned directory without changing it.
/// Unlike create_dir_all, this requires private security on the final directory.
/// System/temp/user-selected ancestor directories are only pinned and type-checked.
pub fn verify_directory(path: impl AsRef<Path>) -> io::Result<()> {
    let (_, pins) = directory(path.as_ref())?;
    let leaf = pins
        .last()
        .ok_or_else(|| refused("Directory has no filesystem identity"))?;
    platform::verify_private(leaf, true)
}

/// Create a read/write file exclusively with private creation-time security.
/// Windows permits delete-sharing for tempfile publication, but not other writers.
pub fn create_new(path: impl AsRef<Path>) -> io::Result<File> {
    let (path, _parents) = target(path.as_ref())?;
    platform::create_new(&path)
}

/// Open an existing private file read/write without truncation or owner repair.
/// Truncate/seek only on this returned handle after successful verification.
pub fn open_private(path: impl AsRef<Path>) -> io::Result<File> {
    let (path, _parents) = target(path.as_ref())?;
    platform::open_file(&path, true, true)
}

/// Create or open a verified private log with kernel append semantics.
/// No existing bytes are truncated, and existing security is never repaired.
pub fn open_append(path: impl AsRef<Path>) -> io::Result<File> {
    let (path, _parents) = target(path.as_ref())?;
    platform::open_append(&path)
}

/// Pin a regular single-link incoming file against writes/deletion on Windows.
/// Its owner may differ from TokenUser (for example, a child-created download).
/// This pins the leaf; publication callers must separately pin parent identities.
pub fn open_stable_read(path: impl AsRef<Path>) -> io::Result<File> {
    let (path, _parents) = target(path.as_ref())?;
    platform::open_file(&path, false, false)
}

fn validate_affix(value: &str) -> io::Result<()> {
    if value
        .chars()
        .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
    {
        return Err(refused("Invalid temporary artifact name"));
    }
    Ok(())
}

pub fn tempfile_in(dir: impl AsRef<Path>, prefix: &str, suffix: &str) -> io::Result<NamedTempFile> {
    validate_affix(prefix)?;
    validate_affix(suffix)?;
    let (dir, _parents) = directory(dir.as_ref())?;
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .make_in(dir, |path| create_new(path))
}

/// Replace an application-owned artifact only after its replacement is complete.
/// The destination must be absent or an already-private regular single-link file.
/// This is an authorized replacement, unlike evidence publication's no-clobber path.
/// Existing destinations require the caller to own an exclusive-writer namespace:
/// Windows path replacement is not a target-handle compare-and-swap. Identity is
/// rechecked immediately before replacing, but a malicious same-user/SYSTEM writer
/// is outside this contract. Initially absent destinations are always no-clobber.
pub fn persist(temp: NamedTempFile, path: &Path) -> io::Result<File> {
    persist_inner(temp, path, || Ok(()))
}

fn persist_inner(
    temp: NamedTempFile,
    path: &Path,
    before_commit: impl FnOnce() -> io::Result<()>,
) -> io::Result<File> {
    let (path, _parents) = target(path)?;
    let staged = fs::canonicalize(temp.path())?;
    if staged.parent() != path.parent() {
        return Err(refused(
            "Atomic replacement requires the same parent directory",
        ));
    }
    platform::verify_file(temp.as_file(), &staged, true)?;
    let previous = match open_private(&path) {
        Ok(file) => Some(platform::identity(&file)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    temp.as_file().sync_all()?;
    before_commit()?;
    if let Some(previous) = previous {
        let file = open_private(&path)?;
        if platform::identity(&file)? != previous {
            return Err(refused("Replacement target identity changed"));
        }
        drop(file);
        temp.persist(path).map_err(|error| error.error)
    } else {
        temp.persist_noclobber(path).map_err(|error| error.error)
    }
}

pub fn write(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> io::Result<()> {
    let (path, _parents) = target(path.as_ref())?;
    let mut temp = tempfile_in(path.parent().unwrap(), ".triage-write-", ".tmp")?;
    temp.write_all(bytes.as_ref())?;
    persist(temp, &path)?;
    Ok(())
}

/// A directory created by these primitives, with identity-checked cleanup.
/// Explicit `close` reports cleanup errors; Drop is only a best-effort fallback.
#[derive(Debug)]
pub struct PrivateTempDir {
    path: Option<PathBuf>,
    identity: (u64, u64),
}

impl PrivateTempDir {
    pub fn path(&self) -> &Path {
        self.path.as_deref().expect("live temporary directory")
    }

    pub fn keep(mut self) -> PathBuf {
        self.path.take().unwrap()
    }

    pub fn close(mut self) -> io::Result<()> {
        let path = self.path.take().unwrap();
        self.remove(&path)
    }

    /// Observe only the exact expected leaf after removal fails. Missing roots
    /// stay unavailable: no new root-absence proof is implied by a failed open.
    pub(crate) fn close_with_residue(mut self, expected_leaf: &OsStr) -> io::Result<()> {
        let path = self.path.take().unwrap();
        self.remove_with(&path, Some(expected_leaf), |path| fs::remove_dir_all(path))
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        self.remove_with(path, None, |path| fs::remove_dir_all(path))
    }

    fn remove_with(
        &self,
        path: &Path,
        expected_leaf: Option<&OsStr>,
        remove: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let (canonical, parents) =
            target(path).map_err(|error| cleanup_failure(CleanupStage::Target, error))?;
        let pin = platform::open_directory(&canonical)
            .map_err(|error| cleanup_failure(CleanupStage::OpenRoot, error))?;
        let identity = platform::identity(&pin)
            .map_err(|error| cleanup_failure(CleanupStage::Identity, error))?;
        if identity != self.identity {
            return Err(cleanup_failure(
                CleanupStage::Identity,
                refused("Temporary directory identity changed; retained"),
            ));
        }
        platform::verify_private(&pin, true)
            .map_err(|error| cleanup_failure(CleanupStage::Security, error))?;
        // The directory's protected DACL excludes other users. Release its
        // delete-denying handle only for std's non-following recursive removal.
        drop(pin);
        remove(&canonical).map_err(|source| {
            let residue = expected_leaf.map(|leaf| {
                self.observe_residue(&canonical, &parents, leaf)
                    .unwrap_or_else(|_| CleanupResidue::unavailable())
            });
            io::Error::new(
                source.kind(),
                CleanupFailure {
                    stage: CleanupStage::RemoveTree,
                    source,
                    residue,
                },
            )
        })
    }

    #[cfg(not(windows))]
    fn observe_residue(&self, _: &Path, _: &[File], _: &OsStr) -> io::Result<CleanupResidue> {
        Ok(CleanupResidue::unavailable())
    }

    #[cfg(windows)]
    fn observe_residue(
        &self,
        path: &Path,
        parents: &[File],
        leaf: &OsStr,
    ) -> io::Result<CleanupResidue> {
        self.observe_residue_with(path, parents, leaf, || Ok(()))
    }

    #[cfg(windows)]
    fn observe_residue_with(
        &self,
        path: &Path,
        parents: &[File],
        leaf: &OsStr,
        between: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<CleanupResidue> {
        platform::validate_name(leaf)?;
        if Path::new(leaf).file_name() != Some(leaf) {
            return Err(refused("Residue leaf is not one exact name"));
        }
        let verify_parents = || -> io::Result<()> {
            let parent = path
                .parent()
                .ok_or_else(|| refused("Missing residue parent"))?;
            let (canonical, observed) = directory(parent)?;
            if canonical != parent || observed.len() != parents.len() {
                return Err(refused("Residue ancestry changed"));
            }
            for (before, after) in parents.iter().zip(&observed) {
                if platform::identity(before)? != platform::identity(after)? {
                    return Err(refused("Residue ancestry changed"));
                }
            }
            Ok(())
        };
        verify_parents()?;
        let root = platform::open_directory(path)?;
        if platform::identity(&root)? != self.identity {
            return Err(refused("Residue root changed"));
        }
        platform::verify_residue_root(&root, path)?;
        let scan = || -> io::Result<_> {
            let mut entries = std::collections::BTreeMap::new();
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                if entries.len() == 8 {
                    return Err(refused("Residue entry bound"));
                }
                let name = entry.file_name();
                platform::validate_name(&name)?;
                let (pin, stamp) = platform::residue_entry(&path.join(&name))?;
                if entries.insert(name, (pin, stamp)).is_some() {
                    return Err(refused("Residue entry repeated"));
                }
            }
            Ok(entries)
        };
        // No content is read. Release first-pass child pins so a changed entry
        // is detected by identity, then hold second-pass pins through rechecks.
        let before: std::collections::BTreeMap<_, _> = scan()?
            .into_iter()
            .map(|(name, (_pin, stamp))| (name, stamp))
            .collect();
        between()?;
        let after = scan()?;
        if before.len() != after.len()
            || before
                .iter()
                .any(|(name, stamp)| after.get(name).map(|(_, value)| value) != Some(stamp))
        {
            return Err(refused("Residue entries changed"));
        }
        for (name, (pin, stamp)) in &after {
            if platform::residue_stamp(pin, &path.join(name))? != *stamp {
                return Err(refused("Residue entry changed"));
            }
        }
        platform::verify_residue_root(&root, path)?;
        if platform::identity(&root)? != self.identity {
            return Err(refused("Residue root changed"));
        }
        verify_parents()?;
        let mut result = CleanupResidue {
            root: "same_private_directory",
            executable: "absent",
            other_files: Some(0),
            other_directories: Some(0),
            other_reparse_points: Some(0),
            other_entries: Some(0),
            complete: true,
        };
        for (name, (_, stamp)) in &after {
            if name == leaf {
                result.executable = stamp.kind;
            } else {
                let count = match stamp.kind {
                    "regular_file" => &mut result.other_files,
                    "directory" => &mut result.other_directories,
                    "reparse_point" => &mut result.other_reparse_points,
                    _ => &mut result.other_entries,
                };
                *count = count.map(|n| n + 1);
            }
        }
        Ok(result)
    }
}

impl AsRef<Path> for PrivateTempDir {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}
impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = self.remove(&path);
        }
    }
}

pub fn tempdir_in(dir: impl AsRef<Path>, prefix: &str) -> io::Result<PrivateTempDir> {
    validate_affix(prefix)?;
    let (dir, _parents) = directory(dir.as_ref())?;
    for _ in 0..128 {
        let path = dir.join(format!("{prefix}{:032x}", rand::random::<u128>()));
        match create_dir(&path) {
            Ok(()) => {
                let pin = platform::open_directory(&path)?;
                return Ok(PrivateTempDir {
                    path: Some(path),
                    identity: platform::identity(&pin)?,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "Temporary directory collision limit",
    ))
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::{c_void, OsStr, OsString};
    use std::os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    };
    use windows::core::{BOOL, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::*;
    use windows::Win32::Security::*;
    use windows::Win32::Storage::FileSystem::*;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn error(error: windows::core::Error) -> io::Error {
        io::Error::from_raw_os_error((error.code().0 as u32 & 0xffff) as i32)
    }
    fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
        let mut value: Vec<_> = value.encode_wide().collect();
        if value.contains(&0) {
            return Err(refused("NUL in artifact path"));
        }
        value.push(0);
        Ok(value)
    }
    fn handle(file: &File) -> HANDLE {
        HANDLE(file.as_raw_handle())
    }
    fn extended(path: &Path) -> io::Result<Vec<u16>> {
        use std::path::Prefix;
        let mut result: Vec<u16> = match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(_) => OsStr::new(r"\\?\").encode_wide().collect(),
                Prefix::UNC(_, _) => {
                    let mut result: Vec<u16> = OsStr::new(r"\\?\UNC\").encode_wide().collect();
                    result.extend(path.as_os_str().encode_wide().skip(2));
                    if result.contains(&0) {
                        return Err(refused("NUL in artifact path"));
                    }
                    result.push(0);
                    return Ok(result);
                }
                Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => {
                    return wide(path.as_os_str())
                }
                _ => return Err(refused("Unsupported Windows artifact namespace")),
            },
            _ => return Err(refused("Windows artifact path is not absolute")),
        };
        result.extend(path.as_os_str().encode_wide());
        if result.contains(&0) {
            return Err(refused("NUL in artifact path"));
        }
        result.push(0);
        Ok(result)
    }
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0)));
                }
            }
        }
    }
    struct Security {
        descriptor: Local,
    }
    impl Security {
        fn new(directory: bool) -> io::Result<Self> {
            unsafe {
                let mut token = HANDLE::default();
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(error)?;
                let _token = OwnedHandle::from_raw_handle(token.0);
                let mut needed = 0;
                let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
                if needed == 0 || needed > 65536 {
                    return Err(refused("Invalid token user size"));
                }
                let mut data = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
                GetTokenInformation(
                    token,
                    TokenUser,
                    Some(data.as_mut_ptr().cast()),
                    needed,
                    &mut needed,
                )
                .map_err(error)?;
                let user = &*data.as_ptr().cast::<TOKEN_USER>();
                let mut sid = PWSTR::null();
                ConvertSidToStringSidW(user.User.Sid, &mut sid).map_err(error)?;
                let _sid = Local(sid.0.cast());
                let sid = sid
                    .to_string()
                    .map_err(|_| refused("Invalid user SID encoding"))?;
                let inheritance = if directory { "OICI" } else { "" };
                let sddl =
                    format!("O:{sid}D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;{sid})");
                let sddl = wide(OsStr::new(&sddl))?;
                let mut descriptor = PSECURITY_DESCRIPTOR::default();
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(sddl.as_ptr()),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    None,
                )
                .map_err(error)?;
                Ok(Self {
                    descriptor: Local(descriptor.0),
                })
            }
        }
        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.descriptor.0,
                bInheritHandle: BOOL(0),
            }
        }
    }

    pub fn validate_name(name: &OsStr) -> io::Result<()> {
        let name: Vec<_> = name.encode_wide().collect();
        if name.is_empty()
            || name.iter().any(|c| *c < 32 || matches!(*c, 58 | 47 | 92))
            || matches!(name.last(), Some(32 | 46))
        {
            return Err(refused("Invalid Windows artifact name"));
        }
        let stem: String = name
            .iter()
            .take_while(|c| **c != 46)
            .map(|c| {
                char::from_u32(u32::from(*c))
                    .unwrap_or('_')
                    .to_ascii_uppercase()
            })
            .collect();
        if matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
        {
            return Err(refused("Windows device name is not an artifact"));
        }
        Ok(())
    }

    fn open(
        path: &Path,
        access: u32,
        sharing: FILE_SHARE_MODE,
        creation: FILE_CREATION_DISPOSITION,
        security: Option<&Security>,
    ) -> io::Result<File> {
        let name = extended(path)?;
        let attributes = security.map(Security::attributes);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                access,
                sharing,
                attributes.as_ref().map(|a| a as *const _),
                creation,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            .map_err(error)?
        };
        Ok(unsafe { File::from_raw_handle(handle.0) })
    }
    fn information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe {
            GetFileInformationByHandle(handle(file), &mut info).map_err(error)?;
        }
        Ok(info)
    }
    pub fn identity(file: &File) -> io::Result<(u64, u64)> {
        let info = information(file)?;
        Ok((
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }
    fn verify(file: &File, path: &Path, directory: bool) -> io::Result<()> {
        let info = information(file)?;
        if unsafe { GetFileType(handle(file)) } != FILE_TYPE_DISK
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != directory
            || (!directory && info.nNumberOfLinks != 1)
        {
            return Err(refused(
                "Artifact type, reparse point, or link count is invalid",
            ));
        }
        if final_path(file)? != fs::canonicalize(path)? {
            return Err(refused("Artifact handle path mismatch"));
        }
        Ok(())
    }

    fn final_path(file: &File) -> io::Result<PathBuf> {
        let mut name = vec![0u16; 32768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle(file),
                &mut name,
                FILE_NAME_NORMALIZED, // VOLUME_NAME_DOS is the zero-valued default.
            )
        } as usize;
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if length >= name.len() {
            return Err(refused("Artifact final path exceeds bound"));
        }
        name.truncate(length);
        Ok(PathBuf::from(OsString::from_wide(&name)))
    }

    pub fn verify_residue_root(file: &File, path: &Path) -> io::Result<()> {
        verify(file, path, true)?;
        verify_private(file, true)
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct ResidueStamp {
        pub kind: &'static str,
        identity: (u64, u64),
        attributes: u32,
        links: u32,
        size: u64,
        created: u64,
        modified: u64,
    }

    pub fn residue_stamp(file: &File, path: &Path) -> io::Result<ResidueStamp> {
        let info = information(file)?;
        // No canonicalize on a child: it could follow a reparse point. The
        // retained handle was opened on the entry itself, never its target.
        if unsafe { GetFileType(handle(file)) } != FILE_TYPE_DISK || final_path(file)? != path {
            return Err(refused("Residue entry handle mismatch"));
        }
        let kind = if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            "reparse_point"
        } else if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
            "directory"
        } else if info.nNumberOfLinks == 1 {
            "regular_file"
        } else {
            "other"
        };
        Ok(ResidueStamp {
            kind,
            identity: identity(file)?,
            attributes: info.dwFileAttributes,
            links: info.nNumberOfLinks,
            size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            created: (u64::from(info.ftCreationTime.dwHighDateTime) << 32)
                | u64::from(info.ftCreationTime.dwLowDateTime),
            modified: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
                | u64::from(info.ftLastWriteTime.dwLowDateTime),
        })
    }

    pub fn residue_entry(path: &Path) -> io::Result<(File, ResidueStamp)> {
        let file = open(
            path,
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            None,
        )?;
        let stamp = residue_stamp(&file, path)?;
        Ok((file, stamp))
    }
    pub fn verify_private(file: &File, directory: bool) -> io::Result<()> {
        unsafe {
            let expected = Security::new(directory)?;
            let mut expected_owner = PSID::default();
            let mut defaulted = BOOL(0);
            GetSecurityDescriptorOwner(
                PSECURITY_DESCRIPTOR(expected.descriptor.0),
                &mut expected_owner,
                &mut defaulted,
            )
            .map_err(error)?;
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            let mut owner = PSID::default();
            let mut acl = std::ptr::null_mut();
            GetSecurityInfo(
                handle(file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut acl),
                None,
                Some(&mut descriptor),
            )
            .ok()
            .map_err(error)?;
            let _descriptor = Local(descriptor.0);
            EqualSid(owner, expected_owner)
                .map_err(|_| refused("Artifact owner is not the current user"))?;
            let mut control = 0u16;
            let mut revision = 0;
            GetSecurityDescriptorControl(descriptor, &mut control, &mut revision).map_err(error)?;
            if control & SE_DACL_PROTECTED.0 == 0
                || acl.is_null()
                || !IsValidAcl(acl).as_bool()
                || (*acl).AceCount != 2
            {
                return Err(refused("Artifact DACL is not the private protected ACL"));
            }
            let mut present = BOOL(0);
            let mut expected_acl = std::ptr::null_mut();
            GetSecurityDescriptorDacl(
                PSECURITY_DESCRIPTOR(expected.descriptor.0),
                &mut present,
                &mut expected_acl,
                &mut defaulted,
            )
            .map_err(error)?;
            let mut matches = [false; 2];
            for i in 0..2 {
                let mut raw = std::ptr::null_mut();
                GetAce(acl, i, &mut raw).map_err(error)?;
                let header = &*raw.cast::<ACE_HEADER>();
                if header.AceType != 0
                    || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() + 4
                {
                    return Err(refused("Artifact ACL contains an unsupported access rule"));
                }
                let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
                let mut found = false;
                for j in 0..2 {
                    let mut expected_raw = std::ptr::null_mut();
                    GetAce(expected_acl, j, &mut expected_raw).map_err(error)?;
                    let expected_ace = &*expected_raw.cast::<ACCESS_ALLOWED_ACE>();
                    if ace.Header.AceType == expected_ace.Header.AceType
                        && ace.Header.AceFlags == expected_ace.Header.AceFlags
                        && ace.Mask == expected_ace.Mask
                        && EqualSid(
                            PSID((&ace.SidStart as *const u32).cast_mut().cast()),
                            PSID((&expected_ace.SidStart as *const u32).cast_mut().cast()),
                        )
                        .is_ok()
                        && !matches[j as usize]
                    {
                        matches[j as usize] = true;
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(refused("Artifact ACL contains an unexpected access rule"));
                }
            }
            Ok(())
        }
    }
    pub fn open_directory(path: &Path) -> io::Result<File> {
        // MS-FSA 2.1.5.1.2.2 excludes metadata-only opens from sharing checks.
        // FILE_LIST_DIRECTORY supplies directory data-read access so omitting
        // FILE_SHARE_DELETE protects this directory from rename/deletion.
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/8c0e3f4f-0729-49f4-a14d-7f7add593819
        let file = open(
            path,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            None,
        )?;
        verify(&file, path, true)?;
        Ok(file)
    }
    pub fn create_dir(path: &Path) -> io::Result<()> {
        let security = Security::new(true)?;
        let name = extended(path)?;
        unsafe {
            CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&security.attributes())).map_err(error)?;
        }
        let file = open_directory(path)?;
        verify_private(&file, true)
    }
    pub fn create_new(path: &Path) -> io::Result<File> {
        let security = Security::new(false)?;
        let file = open(
            path,
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            CREATE_NEW,
            Some(&security),
        )?;
        verify_file(&file, path, true)?;
        Ok(file)
    }
    pub fn open_file(path: &Path, writable: bool, private: bool) -> io::Result<File> {
        let access = GENERIC_READ.0 | if writable { GENERIC_WRITE.0 } else { 0 };
        let file = open(path, access, FILE_SHARE_READ, OPEN_EXISTING, None)?;
        verify_file(&file, path, private)?;
        Ok(file)
    }
    pub fn open_append(path: &Path) -> io::Result<File> {
        let security = Security::new(false)?;
        // Match Rust 1.95 read+append access, including write attributes/EA,
        // while deliberately withholding FILE_WRITE_DATA (arbitrary overwrite).
        // https://github.com/rust-lang/rust/blob/1.95.0/library/std/src/sys/fs/windows.rs#L244-L253
        let access = GENERIC_READ.0 | (FILE_GENERIC_WRITE.0 & !FILE_WRITE_DATA.0);
        let file = match open(path, access, FILE_SHARE_READ, CREATE_NEW, Some(&security)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open(path, access, FILE_SHARE_READ, OPEN_EXISTING, None)?
            }
            Err(error) => return Err(error),
        };
        verify_file(&file, path, true)?;
        Ok(file)
    }
    pub fn verify_file(file: &File, path: &Path, private: bool) -> io::Result<()> {
        verify(file, path, false)?;
        if private {
            verify_private(file, false)?;
        }
        Ok(())
    }

    #[cfg(test)]
    #[test]
    fn created_owner_is_token_user_independently_of_the_default_owner() {
        let root = tempfile::tempdir().unwrap();
        let file = super::create_new(root.path().join("user-owned")).unwrap();
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).unwrap();
            let _token = OwnedHandle::from_raw_handle(token.0);
            let mut needed = 0;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
            assert!((1..65537).contains(&needed));
            let mut data = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
            GetTokenInformation(
                token,
                TokenUser,
                Some(data.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
            .unwrap();
            let user = (*data.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            let mut observed = PSID::default();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            GetSecurityInfo(
                handle(&file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut observed),
                None,
                None,
                None,
                Some(&mut descriptor),
            )
            .ok()
            .unwrap();
            let _descriptor = Local(descriptor.0);
            // Deliberately does not use Security::new or verify_private as the
            // oracle: selecting TokenOwner in both would otherwise self-confirm.
            assert!(
                EqualSid(observed, user).is_ok(),
                "Created owner must be TokenUser"
            );
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    pub fn validate_name(_: &OsStr) -> io::Result<()> {
        Ok(())
    }
    pub fn identity(file: &File) -> io::Result<(u64, u64)> {
        let m = file.metadata()?;
        Ok((m.dev(), m.ino()))
    }
    fn no_link(path: &Path) -> io::Result<fs::Metadata> {
        let m = fs::symlink_metadata(path)?;
        if m.file_type().is_symlink() {
            return Err(refused("Artifact is a symbolic link"));
        }
        Ok(m)
    }
    pub fn open_directory(path: &Path) -> io::Result<File> {
        let m = no_link(path)?;
        if !m.is_dir() {
            return Err(refused("Ancestor is not a directory"));
        }
        let file = File::open(path)?;
        if identity(&file)? != (m.dev(), m.ino()) {
            return Err(refused("Ancestor identity changed"));
        }
        Ok(file)
    }
    pub fn create_dir(path: &Path) -> io::Result<()> {
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    pub fn create_new(path: &Path) -> io::Result<File> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        verify_file(&file, path, true)?;
        Ok(file)
    }
    pub fn open_file(path: &Path, writable: bool, private: bool) -> io::Result<File> {
        no_link(path)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(writable)
            .open(path)?;
        verify_file(&file, path, private)?;
        Ok(file)
    }
    pub fn open_append(path: &Path) -> io::Result<File> {
        let file = match fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                no_link(path)?;
                fs::OpenOptions::new().read(true).append(true).open(path)?
            }
            Err(error) => return Err(error),
        };
        verify_file(&file, path, true)?;
        Ok(file)
    }
    pub fn verify_private(file: &File, directory: bool) -> io::Result<()> {
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode != if directory { 0o700 } else { 0o600 } {
            return Err(refused("Artifact permissions are not private"));
        }
        Ok(())
    }
    pub fn verify_file(file: &File, path: &Path, private: bool) -> io::Result<()> {
        let m = no_link(path)?;
        if !m.is_file() || m.nlink() != 1 || identity(file)? != (m.dev(), m.ino()) {
            return Err(refused("Artifact type, identity or link count is invalid"));
        }
        if private {
            verify_private(file, false)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    #[test]
    fn cleanup_diagnostic_is_closed_bounded_and_never_formats_source_text() {
        for stage in [
            CleanupStage::Target,
            CleanupStage::OpenRoot,
            CleanupStage::Identity,
            CleanupStage::Security,
            CleanupStage::RemoveTree,
        ] {
            for (kind, expected) in [
                (io::ErrorKind::NotFound, "not_found"),
                (io::ErrorKind::PermissionDenied, "permission_denied"),
                (io::ErrorKind::AlreadyExists, "already_exists"),
                (io::ErrorKind::InvalidInput, "invalid_input"),
                (io::ErrorKind::Unsupported, "unsupported"),
                (io::ErrorKind::Interrupted, "interrupted"),
                (io::ErrorKind::TimedOut, "other"),
            ] {
                let error = cleanup_failure(
                    stage,
                    io::Error::new(kind, "private-canary/path\nraw-error"),
                );
                let diagnostic = cleanup_diagnostic(&error).unwrap().to_string();
                assert_eq!(
                    diagnostic,
                    format!(
                        "{{\"stage\":\"{}\",\"kind\":\"{expected}\",\"os_code\":null}}",
                        stage.name()
                    )
                );
                assert!(diagnostic.is_ascii());
                assert!("runtime_cleanup_diagnostic=".len() + diagnostic.len() <= 112);
                assert!(!diagnostic.contains("canary"));
                assert!(!diagnostic.contains('\n'));
            }
        }
        for code in [0, 5, 32, 65535, 65536, -1] {
            let error =
                cleanup_failure(CleanupStage::RemoveTree, io::Error::from_raw_os_error(code));
            let diagnostic = cleanup_diagnostic(&error).unwrap();
            assert_eq!(
                diagnostic.os_code,
                (0..=65535).contains(&code).then_some(code)
            );
            assert!("runtime_cleanup_diagnostic=".len() + diagnostic.to_string().len() <= 112);
        }
        assert!(cleanup_diagnostic(&io::Error::other("unclassified-canary")).is_none());
    }

    #[test]
    fn residue_failure_preserves_original_error_and_never_implies_absence() {
        let source = io::Error::from_raw_os_error(32);
        let error = io::Error::new(
            source.kind(),
            CleanupFailure {
                stage: CleanupStage::RemoveTree,
                source,
                residue: Some(CleanupResidue::unavailable()),
            },
        );
        let diagnostic = cleanup_diagnostic(&error).unwrap();
        assert_eq!(diagnostic.os_code, Some(32));
        assert_eq!(
            diagnostic.to_string(),
            "{\"stage\":\"remove_tree\",\"kind\":\"other\",\"os_code\":32}"
        );
        let value = diagnostic.residue().unwrap().to_string();
        assert_eq!(value, "{\"root\":\"unavailable\",\"executable\":\"unavailable\",\"other_files\":null,\"other_directories\":null,\"other_reparse_points\":null,\"other_entries\":null,\"complete\":false}");
        assert!(value.is_ascii() && value.len() < 320);
        let original = error
            .get_ref()
            .unwrap()
            .downcast_ref::<CleanupFailure>()
            .unwrap();
        assert_eq!(original.source.raw_os_error(), Some(32));
    }

    #[cfg(windows)]
    fn residue_snapshot(
        owned: &PrivateTempDir,
        between: impl FnOnce() -> io::Result<()>,
    ) -> CleanupResidue {
        let (path, parents) = target(owned.path()).unwrap();
        owned
            .observe_residue_with(&path, &parents, OsStr::new("rclone.exe"), between)
            .unwrap_or_else(|_| CleanupResidue::unavailable())
    }

    #[cfg(windows)]
    #[test]
    fn residue_observes_exact_leaf_and_aggregates_other_names_without_contents() {
        let root = tempfile::tempdir().unwrap();
        let owned = tempdir_in(root.path(), "private-canary-").unwrap();
        write(owned.path().join("rclone.exe"), b"synthetic").unwrap();
        write(
            owned.path().join("private-name-canary"),
            b"private-body-canary",
        )
        .unwrap();
        create_dir(owned.path().join("private-directory-canary")).unwrap();
        let observed = residue_snapshot(&owned, || Ok(()));
        assert!(observed.complete);
        assert_eq!(observed.root, "same_private_directory");
        assert_eq!(observed.executable, "regular_file");
        assert_eq!(observed.other_files, Some(1));
        assert_eq!(observed.other_directories, Some(1));
        assert_eq!(observed.other_reparse_points, Some(0));
        assert_eq!(observed.other_entries, Some(0));
        assert!(!observed.to_string().contains("canary"));
        assert!(!observed
            .to_string()
            .contains(root.path().to_string_lossy().as_ref()));
        assert!(observed.to_string().len() < 320);
    }

    #[cfg(windows)]
    #[test]
    fn residue_case_alias_is_an_other_entry_not_the_expected_executable() {
        let root = tempfile::tempdir().unwrap();
        let owned = tempdir_in(root.path(), "runtime-").unwrap();
        write(owned.path().join("RCLONE.EXE"), b"synthetic").unwrap();
        let observed = residue_snapshot(&owned, || Ok(()));
        assert!(observed.complete);
        assert_eq!(observed.executable, "absent");
        assert_eq!(observed.other_files, Some(1));
    }

    #[cfg(windows)]
    #[test]
    fn residue_entry_replacement_with_equal_content_is_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let owned = tempdir_in(root.path(), "runtime-").unwrap();
        let entry = owned.path().join("rclone.exe");
        write(&entry, b"same synthetic bytes").unwrap();
        let moved = root.path().join("prior-entry");
        let observed = residue_snapshot(&owned, || {
            fs::rename(&entry, &moved)?;
            write(&entry, b"same synthetic bytes")
        });
        assert_eq!(
            observed.to_string(),
            CleanupResidue::unavailable().to_string()
        );
        assert_eq!(fs::read(&moved).unwrap(), b"same synthetic bytes");
        assert_eq!(fs::read(&entry).unwrap(), b"same synthetic bytes");
    }

    #[cfg(windows)]
    #[test]
    fn residue_overflow_or_inspection_failure_never_publishes_partial_counts() {
        let root = tempfile::tempdir().unwrap();
        let owned = tempdir_in(root.path(), "runtime-").unwrap();
        for index in 0..8 {
            write(
                owned.path().join(format!("private-canary-{index}")),
                b"synthetic",
            )
            .unwrap();
        }
        assert_eq!(residue_snapshot(&owned, || Ok(())).other_files, Some(8));
        let observed = residue_snapshot(&owned, || Err(io::Error::other("raw-error-canary")));
        assert_eq!(
            observed.to_string(),
            CleanupResidue::unavailable().to_string()
        );
        write(owned.path().join("ninth-entry"), b"synthetic").unwrap();
        let observed = residue_snapshot(&owned, || panic!("overflow must stop before second scan"));
        assert_eq!(
            observed.to_string(),
            CleanupResidue::unavailable().to_string()
        );
    }

    #[cfg(windows)]
    #[test]
    fn residue_partial_deletion_and_missing_root_keep_original_failure() {
        let root = tempfile::tempdir().unwrap();
        for remove_root in [false, true] {
            let mut owned = tempdir_in(root.path(), "runtime-").unwrap();
            let path = owned.path.take().unwrap(); // mirror consuming close: Drop cannot retry
            write(path.join("rclone.exe"), b"synthetic").unwrap();
            let mut attempts = 0;
            let error = owned
                .remove_with(&path, Some(OsStr::new("rclone.exe")), |path| {
                    attempts += 1;
                    fs::remove_file(path.join("rclone.exe"))?;
                    if remove_root {
                        fs::remove_dir(path)?;
                    }
                    Err(io::Error::from_raw_os_error(32))
                })
                .unwrap_err();
            let diagnostic = cleanup_diagnostic(&error).unwrap();
            assert_eq!(diagnostic.os_code, Some(32));
            let observed = diagnostic.residue().unwrap();
            if remove_root {
                assert_eq!(
                    observed.to_string(),
                    CleanupResidue::unavailable().to_string()
                );
            } else {
                assert!(observed.complete);
                assert_eq!(observed.executable, "absent");
                assert_eq!(observed.other_files, Some(0));
            }
            drop(owned);
            assert_eq!(attempts, 1);
            assert_eq!(path.exists(), !remove_root);
        }
    }

    #[cfg(windows)]
    #[test]
    fn residue_replaced_root_is_unavailable_and_drop_preserves_both_roots() {
        let root = tempfile::tempdir().unwrap();
        let mut owned = tempdir_in(root.path(), "runtime-").unwrap();
        let path = owned.path.take().unwrap();
        write(path.join("rclone.exe"), b"original").unwrap();
        let moved = root.path().join("original-root");
        let mut attempts = 0;
        let error = owned
            .remove_with(&path, Some(OsStr::new("rclone.exe")), |path| {
                attempts += 1;
                fs::rename(path, &moved)?;
                create_dir(path)?;
                write(path.join("replacement-canary"), b"unrelated")?;
                Err(io::Error::from_raw_os_error(32))
            })
            .unwrap_err();
        let diagnostic = cleanup_diagnostic(&error).unwrap();
        assert_eq!(diagnostic.os_code, Some(32));
        assert_eq!(
            diagnostic.residue().unwrap().to_string(),
            CleanupResidue::unavailable().to_string()
        );
        drop(owned);
        assert_eq!(attempts, 1);
        assert_eq!(fs::read(moved.join("rclone.exe")).unwrap(), b"original");
        assert_eq!(
            fs::read(path.join("replacement-canary")).unwrap(),
            b"unrelated"
        );
    }

    #[test]
    fn creation_collision_and_replacement_preserve_owned_bytes() {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("case");
        create_dir(&private).unwrap();
        assert!(create_dir(&private).is_err());
        let path = private.join("result");
        let mut file = create_new(&path).unwrap();
        file.write_all(b"old").unwrap();
        platform::verify_file(&file, &path, true).unwrap();
        assert!(create_new(&path).is_err());
        drop(file);
        write(&path, b"new bytes").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new bytes");
        let mut file = open_private(&path).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 9);
        file.set_len(0).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"replacement").unwrap();
    }

    #[test]
    fn temporary_objects_are_private_and_publication_never_clobbers() {
        let root = tempfile::tempdir().unwrap();
        let directory = tempdir_in(root.path(), "private-").unwrap();
        let dir_path = directory.path().to_owned();
        let mut temp = tempfile_in(&dir_path, "result-", ".tmp").unwrap();
        temp.write_all(b"payload").unwrap();
        let path = dir_path.join("published");
        let mut published = temp.persist_noclobber(&path).unwrap();
        platform::verify_file(&published, &path, true).unwrap();
        published.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        published.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"payload");
        drop(published);
        let temp = tempfile_in(&dir_path, "result-", ".tmp").unwrap();
        assert!(temp.persist_noclobber(&path).is_err());
        directory.close().unwrap();
        assert!(!dir_path.exists());
    }

    #[test]
    fn existing_ancestors_are_not_changed_and_hardlinks_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let before = fs::metadata(root.path()).unwrap().permissions();
        create_dir_all(root.path().join("one/two")).unwrap();
        assert_eq!(before, fs::metadata(root.path()).unwrap().permissions());
        let source = root.path().join("source");
        fs::write(&source, b"unchanged").unwrap();
        let alias = root.path().join("alias");
        fs::hard_link(&source, &alias).unwrap();
        assert!(open_stable_read(&alias).is_err());
        assert!(write(&alias, b"must not write").is_err());
        assert_eq!(fs::read(source).unwrap(), b"unchanged");
        assert!(create_dir_all(root.path().join("one/../escape")).is_err());
        assert!(tempfile_in(root.path(), "../escape", "").is_err());
    }

    #[test]
    fn raced_private_directory_creation_is_accepted_without_weakening_exclusive_creation() {
        let root = tempfile::tempdir().unwrap();
        let shared = root.path().join("Archive");
        let descendant = shared.join("nested");
        let mut collisions = 0;
        create_dir_all_inner(&descendant, |path| {
            if path == shared {
                collisions += 1;
                create_dir(path)?;
                write(path.join("competing-worker"), b"preserved")?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(collisions, 1);
        verify_directory(&shared).unwrap();
        verify_directory(&descendant).unwrap();
        assert_eq!(
            fs::read(shared.join("competing-worker")).unwrap(),
            b"preserved"
        );
        assert_eq!(
            create_dir(&shared).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn raced_file_creation_is_rejected_without_changing_its_bytes() {
        let root = tempfile::tempdir().unwrap();
        let shared = root.path().join("Archive");
        let mut attempts = 0;
        let outcome = create_dir_all_inner(&shared.join("nested"), |path| {
            assert_eq!(path, shared);
            attempts += 1;
            write(path, b"competing file")
        });
        assert!(outcome.is_err());
        assert_eq!(attempts, 1);
        assert_eq!(fs::read(&shared).unwrap(), b"competing file");
        assert!(!shared.join("nested").exists());
    }

    #[test]
    fn raced_nonprivate_directory_is_rejected_without_repair_or_descent() {
        let root = tempfile::tempdir().unwrap();
        let private = tempdir_in(root.path(), "private-").unwrap();
        let shared = private.path().join("Archive");
        let mut attempts = 0;
        let outcome = create_dir_all_inner(&shared.join("nested"), |path| {
            assert_eq!(path, shared);
            attempts += 1;
            // Windows inherits an unprotected DACL instead of our explicit
            // descriptor. On Unix, make the fixture nonprivate regardless of umask.
            fs::create_dir(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
            }
            Ok(())
        });
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(attempts, 1);
        assert!(verify_directory(&shared).is_err());
        assert_eq!(fs::read_dir(&shared).unwrap().count(), 0);
        private.close().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn raced_directory_symlink_is_rejected_without_touching_its_target() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        create_dir(&real).unwrap();
        let shared = root.path().join("Archive");
        let mut attempts = 0;
        let outcome = create_dir_all_inner(&shared.join("nested"), |path| {
            assert_eq!(path, shared);
            attempts += 1;
            symlink(&real, path)
        });
        assert!(outcome.is_err());
        assert_eq!(attempts, 1);
        assert!(fs::symlink_metadata(&shared)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn directory_pin_denies_rename_and_delete_until_released() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("pinned");
        let moved = root.path().join("moved");
        create_dir(&path).unwrap();
        let pin = platform::open_directory(&path).unwrap();
        let identity = platform::identity(&pin).unwrap();

        for error in [
            fs::rename(&path, &moved).unwrap_err(),
            fs::remove_dir(&path).unwrap_err(),
        ] {
            assert!(matches!(error.raw_os_error(), Some(5 | 32)));
        }
        assert!(path.is_dir());
        assert!(!moved.exists());
        assert_eq!(platform::identity(&pin).unwrap(), identity);

        drop(pin);
        fs::rename(&path, &moved).unwrap();
        fs::remove_dir(&moved).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn temporary_cleanup_releases_own_pin_and_retains_parent_until_return() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        let moved_parent = root.path().join("moved-parent");
        create_dir(&parent).unwrap();
        let mut owned = tempdir_in(&parent, "owned-").unwrap();
        let path = owned.path.take().unwrap();
        let mut removal_attempts = 0;

        owned
            .remove_with(&path, None, |validated| {
                removal_attempts += 1;
                let error = fs::rename(&parent, &moved_parent).unwrap_err();
                assert!(matches!(error.raw_os_error(), Some(5 | 32)));
                assert!(!moved_parent.exists());
                // Only the exact validated root pin must be released: retaining
                // it here would make this single intended removal fail.
                fs::remove_dir(validated)
            })
            .unwrap();
        assert_eq!(removal_attempts, 1);
        assert!(!path.exists());
        assert!(parent.is_dir());
        drop(owned);
        fs::rename(&parent, &moved_parent).unwrap();
        fs::remove_dir(&moved_parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn stable_incoming_handle_excludes_writer_and_delete_but_not_default_owner() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("child-file");
        fs::write(&path, b"child").unwrap();
        let incoming = open_stable_read(&path).unwrap();
        assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());
        drop(incoming);
        fs::remove_file(path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_append_flushes_and_seeks_cannot_overwrite_or_truncate() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("append.log");
        let mut file = open_append(&path).unwrap();
        file.write_all(b"original\n").unwrap();
        file.sync_all().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"first append\n").unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            file.set_len(0).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(file);
        let mut file = open_append(&path).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"second append\n").unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(
            fs::read(path).unwrap(),
            b"original\nfirst append\nsecond append\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_ancestors_and_leaf_are_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        create_dir(&real).unwrap();
        let link = root.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(create_new(link.join("file")).is_err());
        assert!(create_dir_all(link.join("nested")).is_err());
        let file = real.join("file");
        fs::write(&file, b"old").unwrap();
        let alias = real.join("alias");
        symlink(&file, &alias).unwrap();
        assert!(open_stable_read(&alias).is_err());
        assert!(write(&alias, b"new").is_err());
        assert_eq!(fs::read(file).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn two_append_handles_never_overwrite_the_original_or_each_other() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("append.log");
        let mut first = open_append(&path).unwrap();
        first.write_all(b"original\n").unwrap();
        let mut second = open_append(&path).unwrap();
        first.seek(SeekFrom::Start(0)).unwrap();
        second.seek(SeekFrom::Start(0)).unwrap();
        second.write_all(b"second\n").unwrap();
        first.write_all(b"first\n").unwrap();
        assert_eq!(fs::read(path).unwrap(), b"original\nsecond\nfirst\n");
    }

    #[cfg(windows)]
    #[test]
    fn device_stream_and_alias_names_are_rejected_before_any_creation() {
        let root = tempfile::tempdir().unwrap();
        for name in ["NUL", "COM1.txt", "file:stream", "trailing.", "trailing "] {
            assert!(create_new(root.path().join(name)).is_err());
        }
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn extended_paths_support_private_creation_and_publication() {
        let root = tempfile::tempdir().unwrap();
        let mut parent = root.path().to_owned();
        while parent.as_os_str().len() < 280 {
            parent.push("long-owned-component");
        }
        create_dir_all(&parent).unwrap();
        let path = parent.join("report.txt");
        write(&path, b"long path bytes").unwrap();
        let file = open_private(&path).unwrap();
        platform::verify_file(&file, &path, true).unwrap();
        drop(file);
        assert_eq!(fs::read(path).unwrap(), b"long path bytes");
    }

    #[cfg(windows)]
    #[test]
    fn inherited_existing_file_is_rejected_without_repair_or_truncation() {
        let root = tempfile::tempdir().unwrap();
        let dir = tempdir_in(root.path(), "private-").unwrap();
        let path = dir.path().join("inherited");
        // This creation intentionally omits our explicit descriptor. Even when
        // User==default Owner, the inherited DACL is not explicitly protected.
        fs::write(&path, b"existing evidence").unwrap();
        assert!(open_private(&path).is_err());
        assert!(open_append(&path).is_err());
        assert!(write(&path, b"replacement").is_err());
        assert_eq!(fs::read(path).unwrap(), b"existing evidence");
    }

    #[test]
    fn replacement_requires_same_parent_and_cleanup_rejects_changed_identity() {
        let root = tempfile::tempdir().unwrap();
        let a = tempdir_in(root.path(), "a-").unwrap();
        let b = tempdir_in(root.path(), "b-").unwrap();
        let temp = tempfile_in(a.path(), "new-", ".tmp").unwrap();
        assert!(persist(temp, &b.path().join("result")).is_err());
        assert!(!b.path().join("result").exists());
        let original = a.path().to_owned();
        let moved = root.path().join("moved");
        fs::rename(&original, &moved).unwrap();
        create_dir(&original).unwrap();
        fs::write(original.join("must-remain"), b"replacement identity").unwrap();
        assert!(a.close().is_err());
        assert_eq!(
            fs::read(original.join("must-remain")).unwrap(),
            b"replacement identity"
        );
        assert!(moved.is_dir());
    }

    #[test]
    fn an_initially_absent_destination_cannot_clobber_a_new_competing_file() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("result");
        let mut temp = tempfile_in(root.path(), "replacement-", ".tmp").unwrap();
        temp.write_all(b"our replacement").unwrap();
        let outcome = persist_inner(temp, &target, || fs::write(&target, b"new competing file"));
        assert!(outcome.is_err());
        assert_eq!(fs::read(target).unwrap(), b"new competing file");
    }

    #[test]
    fn an_existing_target_replaced_before_commit_is_not_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("result");
        write(&target, b"original").unwrap();
        let mut temp = tempfile_in(root.path(), "replacement-", ".tmp").unwrap();
        temp.write_all(b"our replacement").unwrap();
        let moved = root.path().join("original");
        let outcome = persist_inner(temp, &target, || {
            fs::rename(&target, &moved)?;
            let mut competing = create_new(&target)?;
            competing.write_all(b"competing private file")
        });
        assert!(outcome.is_err());
        assert_eq!(fs::read(target).unwrap(), b"competing private file");
        assert_eq!(fs::read(moved).unwrap(), b"original");
    }
}
