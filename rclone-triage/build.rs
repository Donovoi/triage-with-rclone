//! Build script for rclone-triage
//!
//! Handles Windows-specific resource embedding:
//! - Application manifest (DPI awareness, Windows 10/11 compatibility)
//! - Version information
//! - Application icon (if available)

fn main() {
    let runtime =
        std::fs::read_to_string("../rclone-version.env").expect("read pinned runtime manifest");
    let target = std::env::var("TARGET").expect("Cargo TARGET must be set");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").expect("Cargo target OS must be set");
    let (hash_key, machine) = if target_os == "windows" {
        let parts: Vec<_> = target.split('-').collect();
        assert!(
            parts.len() >= 4 && parts[2] == "windows",
            "Invalid Windows TARGET"
        );
        match parts[0] {
            "x86_64" => ("RCLONE_EXE_SHA256", 0x8664),
            "i686" => ("RCLONE_WINDOWS_X86_EXE_SHA256", 0x014c),
            "aarch64" => ("RCLONE_WINDOWS_ARM64_EXE_SHA256", 0xaa64),
            _ => panic!("Unsupported Windows runtime architecture"),
        }
    } else {
        // Non-Windows development builds retain the existing x64 Windows asset.
        ("RCLONE_EXE_SHA256", 0x8664)
    };
    let version = runtime_pin(&runtime, "RCLONE_VERSION");
    let expected = runtime_pin(&runtime, hash_key);
    assert!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Invalid runtime SHA256 pin"
    );
    if target_os == "windows" {
        verify_pe_machine("assets/rclone.exe", machine);
    }
    println!("cargo:rustc-env=TRIAGE_RCLONE_VERSION={version}");
    println!("cargo:rustc-env=TRIAGE_RCLONE_EXE_SHA256={expected}");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-changed=../rclone-version.env");
    println!("cargo:rerun-if-changed=assets/rclone.exe");
    // Only run winres on Windows targets
    #[cfg(windows)]
    {
        windows_resources();
    }

    // Always rerun if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");
}

fn runtime_pin<'a>(runtime: &'a str, key: &str) -> &'a str {
    let mut values = runtime
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter_map(|(name, value)| (name == key).then_some(value));
    let value = values
        .next()
        .unwrap_or_else(|| panic!("Missing runtime pin {key}"));
    assert!(values.next().is_none(), "Duplicate runtime pin {key}");
    value
}

fn verify_pe_machine(path: &str, expected: u16) {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).expect("open embedded runtime");
    let mut dos = [0u8; 64];
    file.read_exact(&mut dos).expect("read runtime DOS header");
    assert_eq!(&dos[..2], b"MZ", "Embedded runtime must be PE");
    let offset = u32::from_le_bytes(dos[60..64].try_into().unwrap());
    assert!((64..=4090).contains(&offset), "Invalid runtime PE offset");
    file.seek(SeekFrom::Start(u64::from(offset)))
        .expect("seek runtime PE header");
    let mut pe = [0u8; 6];
    file.read_exact(&mut pe).expect("read runtime PE header");
    assert_eq!(&pe[..4], b"PE\0\0", "Invalid runtime PE signature");
    assert_eq!(
        u16::from_le_bytes([pe[4], pe[5]]),
        expected,
        "Embedded runtime architecture must match Cargo TARGET"
    );
}

#[cfg(windows)]
fn windows_resources() {
    let mut res = winres::WindowsResource::new();
    let major: u64 = std::env::var("CARGO_PKG_VERSION_MAJOR")
        .unwrap()
        .parse()
        .unwrap();
    let minor: u64 = std::env::var("CARGO_PKG_VERSION_MINOR")
        .unwrap()
        .parse()
        .unwrap();
    let patch: u64 = std::env::var("CARGO_PKG_VERSION_PATCH")
        .unwrap()
        .parse()
        .unwrap();
    let packed = (major << 48) | (minor << 32) | (patch << 16);
    let version = format!("{major}.{minor}.{patch}.0");
    res.set_version_info(winres::VersionInfo::PRODUCTVERSION, packed);
    res.set_version_info(winres::VersionInfo::FILEVERSION, packed);
    res.set("FileVersion", &version);
    res.set("ProductVersion", &version);
    res.set_manifest(&WINDOWS_MANIFEST.replace("@VERSION@", &version));
    res.compile().expect("compile Windows resources");
}

#[cfg(windows)]
const WINDOWS_MANIFEST: &str = r#"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="@VERSION@"
    processorArchitecture="*"
    name="RcloneTriage"
    type="win32"
  />
  <description>Forensic Cloud Triage Tool</description>
  
  <!-- Request asInvoker - no admin rights required by default -->
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  
  <!-- Supported deployment targets: Windows 10/11 -->
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10/11 -->
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  
  <!-- DPI awareness - per-monitor DPI aware -->
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">permonitorv2,permonitor</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#;
