//! How much memory this process is using.
//!
//! Gulp shows a memory readout in its status bar. This is the same idea for a native build, read
//! from the operating system rather than from a JVM heap counter.

use std::sync::LazyLock;
use std::time::Duration;

/// How long a reading stays fresh.
pub const REFRESH: Duration = Duration::from_secs(2);

/// The physical memory footprint (on macOS, matching Activity Monitor's "Memory" column)
/// or resident set size (on Linux) of this process in bytes, read in-process without spawning `ps`.
pub fn rss_bytes() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        footprint_macos()
    }
    #[cfg(target_os = "linux")]
    {
        rss_linux()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// Reads `ri_phys_footprint` (and falls back to `ri_resident_size`) directly from the macOS kernel
/// via `proc_pid_rusage` (`RUSAGE_INFO_V0`), avoiding any `fork()`/`exec()` of `/bin/ps` and
/// matching macOS Activity Monitor's "Memory" column.
#[cfg(target_os = "macos")]
fn footprint_macos() -> Option<u64> {
    #[repr(C)]
    struct RusageInfoV0 {
        ri_uuid: [u8; 16],
        ri_user_time: u64,
        ri_system_time: u64,
        ri_pkg_idle_wkups: u64,
        ri_interrupt_wkups: u64,
        ri_pageins: u64,
        ri_wired_size: u64,
        ri_resident_size: u64,
        ri_phys_footprint: u64,
        ri_proc_start_abstime: u64,
        ri_proc_exit_abstime: u64,
    }
    unsafe extern "C" {
        fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut RusageInfoV0) -> i32;
    }
    const RUSAGE_INFO_V0: i32 = 0;
    let mut info = std::mem::MaybeUninit::<RusageInfoV0>::zeroed();
    let rc = unsafe { proc_pid_rusage(std::process::id() as i32, RUSAGE_INFO_V0, info.as_mut_ptr()) };
    if rc == 0 {
        let info = unsafe { info.assume_init() };
        let bytes = if info.ri_phys_footprint > 0 {
            info.ri_phys_footprint
        } else {
            info.ri_resident_size
        };
        if bytes > 0 {
            return Some(bytes);
        }
    }
    None
}

/// Linux reports the resident pages in `/proc/self/statm`; the second field is the resident set.
#[cfg(target_os = "linux")]
fn rss_linux() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

/// A short human-readable size, the way Gulp writes it: `36.2MB`.
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

static TOTAL_RAM_BYTES: LazyLock<Option<u64>> = LazyLock::new(|| {
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
});

/// How much memory the machine has in total, cached once per process lifetime.
pub fn total_bytes() -> Option<u64> {
    *TOTAL_RAM_BYTES
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
    fn sizes_are_written_the_way_gulp_writes_them() {
        assert_eq!(format_size(36 * 1_048_576 + 200_000), "36.2MB");
        assert_eq!(format_size(2 * 1_048_576 * 1024), "2.00GB");
        assert_eq!(format_size(512 * 1024), "512KB");
    }
}
