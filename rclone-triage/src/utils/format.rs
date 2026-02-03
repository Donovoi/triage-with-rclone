//! Formatting helpers.

/// Format a byte count into a human-readable string (2 decimals).
pub fn format_bytes(bytes: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;
    const PB: f64 = TB * 1024.0;

    if bytes >= PB {
        format!("{:.2} PB", bytes / PB)
    } else if bytes >= TB {
        format!("{:.2} TB", bytes / TB)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes / GB)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes / MB)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes / KB)
    } else {
        format!("{:.2} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0.0), "0.00 B");
        assert_eq!(format_bytes(1024.0), "1.00 KB");
        assert_eq!(format_bytes(1024.0 * 1024.0), "1.00 MB");
    }
}
