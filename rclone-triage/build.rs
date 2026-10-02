//! Build script for rclone-triage
//!
//! Handles Windows-specific resource embedding:
//! - Application manifest (DPI awareness, Windows 10/11 compatibility)
//! - Version information
//! - Application icon (if available)

fn main() {
    let runtime =
        std::fs::read_to_string("../rclone-version.env").expect("read pinned runtime manifest");
    for line in runtime.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if matches!(key, "RCLONE_VERSION" | "RCLONE_EXE_SHA256") {
                println!("cargo:rustc-env=TRIAGE_{key}={value}");
            }
        }
    }
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
