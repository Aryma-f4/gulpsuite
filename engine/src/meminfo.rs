//! How much memory this process is using.
//!
//! Burp shows a memory readout in its status bar. This is the same idea for a native build, read
//! from the operating system rather than from a JVM heap counter.

use std::time::Duration;

/// How long a reading stays fresh. The status bar asks twice a second at most, and `ps` is not free.
pub const REFRESH: Duration = Duration::from_secs(2);

/// The resident set size of this process in bytes, when it can be read.
pub fn rss_bytes() -> Option<u64> {
    if cfg!(target_os = "macos") {
        rss_macos()
    } else if cfg!(target_os = "linux") {
        rss_linux()
    } else {
        None
    }
}

/// macOS has no `/proc`, so `ps` is the way in. It reports kilobytes.
fn rss_macos() -> Option<u64> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let kilobytes: u64 = text.trim().parse().ok()?;
    Some(kilobytes * 1024)
}

/// Linux reports the resident pages in `/proc/self/statm`; the second field is the resident set.
fn rss_linux() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    // The page size is 4096 on every platform Linux runs this on.
    Some(pages * 4096)
}

/// A short human-readable size, the way Burp writes it: `36.2MB`.
pub fn format_size(bytes: u64) -> String {
    const MB: f64 = 1_048_576.0;
    let mb = bytes as f64 / MB;
    if mb >= 1024.0 {
        format!("{:.2}GB", mb / 1024.0)
    } else if mb >= 1.0 {
        format!("{mb:.1}MB")
    } else {
        format!("{:.0}KB", bytes as f64 / 1024.0)
    }
}

/// How much memory the machine has in total, for Burp's "of 2.00GB" readout.
pub fn total_bytes() -> Option<u64> {
    if cfg!(target_os = "macos") {
        let output = std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()?;
        String::from_utf8(output.stdout).ok()?.trim().parse().ok()
    } else if cfg!(target_os = "linux") {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kilobytes: u64 = rest.split_whitespace().next()?.parse().ok()?;
                return Some(kilobytes * 1024);
            }
        }
        None
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reading_is_available_and_plausible() {
        let bytes = rss_bytes().expect("the process can read its own size");
        assert!(bytes > 0);
        // A process cannot be smaller than a page or larger than a few gigabytes.
        assert!(bytes > 4096, "{bytes}");
        assert!(bytes < 64 * 1_048_576_000, "{bytes}");
    }

    #[test]
    fn sizes_are_written_the_way_burp_writes_them() {
        assert_eq!(format_size(36 * 1_048_576 + 200_000), "36.2MB");
        assert_eq!(format_size(2 * 1_048_576 * 1024), "2.00GB");
        assert_eq!(format_size(512 * 1024), "512KB");
    }
}
