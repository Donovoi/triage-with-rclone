//! Windows UI helpers.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

#[cfg(windows)]
fn escape_ps_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_file_dialog_non_windows() {
        if cfg!(windows) {
            return;
        }
        assert!(open_file_dialog(None, None, None).is_err());
    }
}
