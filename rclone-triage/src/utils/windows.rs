//! Windows UI helpers.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

#[cfg(windows)]
fn escape_ps_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

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
        Ok(text.trim() == "1")
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
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = title_substring;
        bail!("close_window_by_title is only supported on Windows");
    }
}

/// Open a Windows file picker dialog and return the selected path.
pub fn open_file_dialog(
    title: Option<&str>,
    initial_dir: Option<&Path>,
    filter: Option<&str>,
) -> Result<Option<PathBuf>> {
    #[cfg(windows)]
    {
        let title = escape_ps_single_quoted(title.unwrap_or("Select File"));
        let filter = escape_ps_single_quoted(filter.unwrap_or("All Files (*.*)|*.*"));
        let initial_dir = initial_dir
            .and_then(|p| p.to_str())
            .map(escape_ps_single_quoted);

        let initial_dir_line = if let Some(dir) = initial_dir {
            format!("$dialog.InitialDirectory = '{}'", dir)
        } else {
            String::new()
        };

        let script = format!(
            r#"
Add-Type -AssemblyName PresentationFramework
$dialog = New-Object Microsoft.Win32.OpenFileDialog
$dialog.Title = '{title}'
$dialog.Filter = '{filter}'
{initial_dir_line}
if ($dialog.ShowDialog() -eq $true) {{
  Write-Output $dialog.FileName
}}
"#,
            title = title,
            filter = filter,
            initial_dir_line = initial_dir_line
        );

        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-STA", "-Command", &script])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to open file dialog: {}", stderr.trim());
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let path = text.trim();
        if path.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PathBuf::from(path)))
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (title, initial_dir, filter);
        bail!("open_file_dialog is only supported on Windows");
    }
}

/// Press a button in a window via UI Automation.
pub fn invoke_button_press(process_name: &str, button_name: &str) -> Result<bool> {
    #[cfg(windows)]
    {
        let process_name = escape_ps_single_quoted(process_name);
        let button_name = escape_ps_single_quoted(button_name);
        let script = format!(
            r#"
$processName = '{process_name}'
$buttonName = '{button_name}'

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$process = Get-Process | Where-Object {{ $_.MainWindowTitle -like "*$processName*" }} | Select-Object -First 1
if (-not $process) {{ Write-Output '0'; exit 0 }}

if (-not ([System.Management.Automation.PSTypeName]'Win32Foreground').Type) {{
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Win32Foreground {{
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}}
'@ -ErrorAction SilentlyContinue
}}
[Win32Foreground]::SetForegroundWindow($process.MainWindowHandle) | Out-Null

$root = [System.Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
if (-not $root) {{ Write-Output '0'; exit 0 }}

$cond = New-Object System.Windows.Automation.PropertyCondition(
  [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
  [System.Windows.Automation.ControlType]::Button
)

$buttons = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
$target = $null
foreach ($b in $buttons) {{
  if ($b.Current.Name -like "*$buttonName*") {{ $target = $b; break }}
}}
if (-not $target) {{ Write-Output '0'; exit 0 }}

$invoke = $target.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
if (-not $invoke) {{ Write-Output '0'; exit 0 }}
$invoke.Invoke()
Write-Output '1'
"#,
            process_name = process_name,
            button_name = button_name
        );

        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-STA", "-Command", &script])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to press button: {}", stderr.trim());
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(text.trim() == "1")
    }

    #[cfg(not(windows))]
    {
        let _ = (process_name, button_name);
        bail!("invoke_button_press is only supported on Windows");
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

    #[test]
    fn test_open_file_dialog_non_windows() {
        if cfg!(windows) {
            return;
        }
        assert!(open_file_dialog(None, None, None).is_err());
    }

    #[test]
    fn test_invoke_button_press_non_windows() {
        if cfg!(windows) {
            return;
        }
        assert!(invoke_button_press("process", "button").is_err());
    }
}
