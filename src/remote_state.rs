//! Per-source runtime state: when tpmnt last brought a disk online from a remote,
//! and how many times *in a row* a reconnect has given up. This is *not*
//! declarative config (the config is desired end-state); it's observed history,
//! so it lives under `var/lib/tpmnt/{remote,connect}/<name>.json` alongside the
//! other runtime state (monitor/forward/schedule).
//!
//! Two consumers:
//!   * the dashboard orders source boxes most-recently-connected first;
//!   * `connect` counts consecutive give-ups so that, after a threshold, the
//!     flapping disk/remote is auto-disabled instead of retried into a storm.
//!
//! Best-effort throughout: a missing/unreadable file just means "never connected,
//! no failures recorded", which is the neutral default.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::paths::Paths;

/// The number of consecutive give-ups (each = one reconnect that exhausted its
/// per-attempt retries) after which a disk/remote is auto-disabled.
pub const GIVEUP_DISABLE_THRESHOLD: u32 = 3;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ConnState {
    /// Unix seconds of the last successful connect (remotes only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_connected: Option<u64>,
    /// Consecutive reconnect give-ups since the last success.
    #[serde(default, skip_serializing_if = "is_zero")]
    giveups: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Wall-clock now in unix seconds (0 if the clock is before the epoch, which
/// can't happen in practice — it keeps this infallible for callers).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read(path: &Path) -> ConnState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn write(path: &Path, state: &ConnState) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(s) = serde_json::to_string(state) {
        let _ = std::fs::write(path, s);
    }
}

// --- remotes ---------------------------------------------------------------

/// Stamp `remote` as connected at `now` and clear its give-up streak.
pub fn record_connected(paths: &Paths, remote: &str, now: u64) {
    let path = paths.remote_state(remote);
    let mut s = read(&path);
    s.last_connected = Some(now);
    s.giveups = 0;
    write(&path, &s);
}

/// The recorded last-connected epoch for `remote`, or `None` if never recorded.
pub fn last_connected(paths: &Paths, remote: &str) -> Option<u64> {
    read(&paths.remote_state(remote)).last_connected
}

/// Record one reconnect give-up for `remote`; returns the new consecutive count.
pub fn note_remote_giveup(paths: &Paths, remote: &str) -> u32 {
    let path = paths.remote_state(remote);
    let mut s = read(&path);
    s.giveups = s.giveups.saturating_add(1);
    write(&path, &s);
    s.giveups
}

/// Clear a remote's give-up streak (e.g. on manual enable).
pub fn reset_remote(paths: &Paths, remote: &str) {
    let path = paths.remote_state(remote);
    let mut s = read(&path);
    s.giveups = 0;
    write(&path, &s);
}

// --- disks -----------------------------------------------------------------

/// Clear a disk's give-up streak on a successful connect.
pub fn record_disk_online(paths: &Paths, disk: &str) {
    reset_disk(paths, disk);
}

/// Record one reconnect give-up for `disk`; returns the new consecutive count.
pub fn note_disk_giveup(paths: &Paths, disk: &str) -> u32 {
    let path = paths.disk_state(disk);
    let mut s = read(&path);
    s.giveups = s.giveups.saturating_add(1);
    write(&path, &s);
    s.giveups
}

/// Clear a disk's give-up streak (on manual enable or a successful connect).
pub fn reset_disk(paths: &Paths, disk: &str) {
    let path = paths.disk_state(disk);
    let mut s = read(&path);
    if s.giveups != 0 {
        s.giveups = 0;
        write(&path, &s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_records_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("tpmnt-rs-test-{}", std::process::id()));
        std::env::set_var("TPMNT_ROOT", &dir);
        let paths = Paths::from_env();

        assert_eq!(last_connected(&paths, "nas"), None);
        record_connected(&paths, "nas", 1_700_000_000);
        assert_eq!(last_connected(&paths, "nas"), Some(1_700_000_000));
        record_connected(&paths, "nas", 1_700_000_500);
        assert_eq!(last_connected(&paths, "nas"), Some(1_700_000_500));

        std::env::remove_var("TPMNT_ROOT");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn giveups_accumulate_and_reset_for_remote_and_disk() {
        let dir = std::env::temp_dir().join(format!("tpmnt-rs-give-{}", std::process::id()));
        std::env::set_var("TPMNT_ROOT", &dir);
        let paths = Paths::from_env();

        assert_eq!(note_remote_giveup(&paths, "nas"), 1);
        assert_eq!(note_remote_giveup(&paths, "nas"), 2);
        assert_eq!(note_remote_giveup(&paths, "nas"), 3);
        // A success clears the streak, and last_connected survives.
        record_connected(&paths, "nas", 42);
        assert_eq!(note_remote_giveup(&paths, "nas"), 1);
        assert_eq!(last_connected(&paths, "nas"), Some(42));

        assert_eq!(note_disk_giveup(&paths, "arc"), 1);
        assert_eq!(note_disk_giveup(&paths, "arc"), 2);
        reset_disk(&paths, "arc");
        assert_eq!(note_disk_giveup(&paths, "arc"), 1);

        std::env::remove_var("TPMNT_ROOT");
        std::fs::remove_dir_all(&dir).ok();
    }
}
