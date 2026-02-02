//! Build script for rclone-triage
//!
//! Handles Windows-specific resource embedding:
//! - Application manifest (DPI awareness, Windows 7+ compatibility)
//! - Version information
//! - Application icon (if available)

fn main() {
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
    use std::io::Write;

    let mut res = winres::WindowsResource::new();

    // Set version info
    res.set_version_info(winres::VersionInfo::PRODUCTVERSION, 0x00010000); // 1.0.0.0
    res.set_version_info(winres::VersionInfo::FILEVERSION, 0x00010000);

    // Set manifest for DPI awareness and Windows 7+ compatibility
    res.set_manifest(WINDOWS_MANIFEST);

    // Compile resources
    if let Err(e) = res.compile() {
        // Don't fail the build, just warn
        let mut stderr = std::io::stderr();
        let _ = writeln!(
            stderr,
            "cargo:warning=Failed to compile Windows resources: {}",
            e
        );
    }
}

#[cfg(windows)]
const WINDOWS_MANIFEST: &str = r#"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.0.0.0"
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
  
  <!-- Windows 7, 8, 8.1, 10, 11 compatibility -->
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 7 -->
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <!-- Windows 8 -->
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <!-- Windows 8.1 -->
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
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
