//! Time helpers.

/// Sleep for N seconds with an optional callback every 5 seconds.
pub fn sleep_with_countdown<F>(seconds: u64, mut on_tick: Option<F>)
where
    F: FnMut(u64),
{
    let mut remaining = seconds;
    while remaining > 0 {
        if remaining % 5 == 0 {
            if let Some(ref mut cb) = on_tick {
                cb(remaining);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        remaining = remaining.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep_with_countdown_zero() {
        sleep_with_countdown(0, None::<fn(u64)>);
    }
}
