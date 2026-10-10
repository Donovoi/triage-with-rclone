//! Read text only when the user explicitly requests a paste. Never modify the clipboard.

use anyhow::Result;

#[cfg(windows)]
pub(super) fn read_text() -> Result<String> {
    use anyhow::{bail, Context};
    use windows::Win32::Foundation::HGLOBAL;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    };
    use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};

    // CF_UNICODETEXT is the standard, NUL-terminated Windows UTF-16 text format.
    const CF_UNICODETEXT: u32 = 13;
    const MAX_BYTES: usize = 2 * 1024 * 1024;

    struct Clipboard;
    impl Drop for Clipboard {
        fn drop(&mut self) {
            // SAFETY: this guard is created only after OpenClipboard succeeds.
            let _ = unsafe { CloseClipboard() };
        }
    }
    struct LockedText(HGLOBAL);
    impl Drop for LockedText {
        fn drop(&mut self) {
            // SAFETY: this handle was successfully locked and remains owned by Windows.
            let _ = unsafe { GlobalUnlock(self.0) };
        }
    }

    // SAFETY: no owner window is needed for read-only clipboard access. The guards
    // release the memory lock before closing the clipboard on every return path.
    unsafe {
        OpenClipboard(None).context("Clipboard is busy")?;
        let _clipboard = Clipboard;
        IsClipboardFormatAvailable(CF_UNICODETEXT).context("Clipboard has no text")?;
        let handle = HGLOBAL(GetClipboardData(CF_UNICODETEXT)?.0);
        let bytes = GlobalSize(handle);
        if !(2..=MAX_BYTES).contains(&bytes) || !bytes.is_multiple_of(2) {
            bail!("Clipboard text has an unsupported size");
        }
        let pointer = GlobalLock(handle).cast::<u16>();
        if pointer.is_null() {
            bail!("Clipboard text could not be locked");
        }
        let _locked = LockedText(handle);
        // GlobalSize bounds the read; never scan an unbounded foreign string.
        decode_text(std::slice::from_raw_parts(pointer, bytes / 2))
    }
}

#[cfg(not(windows))]
pub(super) fn read_text() -> Result<String> {
    anyhow::bail!("Use the terminal's paste command on this platform")
}

#[cfg(any(windows, test))]
fn decode_text(units: &[u16]) -> Result<String> {
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| anyhow::anyhow!("Clipboard text is not terminated"))?;
    // Reject malformed data instead of silently changing a copied credential.
    Ok(String::from_utf16(&units[..end])?)
}

#[cfg(test)]
mod tests {
    use super::decode_text;

    #[test]
    fn clipboard_decodes_unicode_and_stops_at_the_terminator() {
        let mut units: Vec<u16> = "copied café 🦀".encode_utf16().collect();
        units.extend([0, b'x' as u16]);
        assert_eq!(decode_text(&units).unwrap(), "copied café 🦀");
        assert_eq!(decode_text(&[0]).unwrap(), "");
    }

    #[test]
    fn clipboard_rejects_unterminated_or_invalid_utf16() {
        assert!(decode_text(&[b'x' as u16]).is_err());
        assert!(decode_text(&[0xd800, 0]).is_err());
        assert!(decode_text(&[]).is_err());
    }
}
