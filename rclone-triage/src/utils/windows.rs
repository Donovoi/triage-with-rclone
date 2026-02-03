//! Windows UI helpers.

use anyhow::{bail, Result};

/// Check if any process window title contains the provided substring.
pub fn window_exists(title_substring: &str) -> Result<bool> {
    #[cfg(windows)]
    {
        let script = format!(
            "$p=Get-Process | Where-Object {{ $_.MainWindowTitle -like '*{}*' }}; if ($p) {{ '1' }} else {{ '0' }}",
            title_substring.replace('\'', "''")
        );
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()?;
        if !output.status.success() {
            bail!("Failed to query window titles");
        }
        let text = String::from_utf8_lossy(&output.stdout);
        return Ok(text.trim() == "1");
    }

    #[cfg(not(windows))]
    {
        let _ = title_substring;
        bail!("window_exists is only supported on Windows");
    }
}

/// Send a WM_CLOSE to windows whose title contains the substring.
pub fn close_window_by_title(title_substring: &str) -> Result<()> {
    #[cfg(windows)]
    {
        let script = format!(
            r#"
if (-not ([System.Management.Automation.PSTypeName]'WinAPI').Type) {{
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WinAPI {{
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr PostMessage(IntPtr hWnd, UInt32 Msg, IntPtr wParam, IntPtr lParam);
}}
'@
}}
$WM_CLOSE = 0x0010
$processes = Get-Process | Where-Object {{ $_.MainWindowTitle -like '*{title}*' }}
foreach ($p in $processes) {{
  [void][WinAPI]::PostMessage($p.MainWindowHandle, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
}}
"#,
            title = title_substring.replace('\'', "''")
        );
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()?;
        if !output.status.success() {
            bail!("Failed to close window");
        }
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        let _ = title_substring;
        bail!("close_window_by_title is only supported on Windows");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_exists_non_windows() {
        if cfg!(windows) {
            return;
        }
        assert!(window_exists("does-not-matter").is_err());
    }
}
