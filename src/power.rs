//! Per-disk power management for the `cold-standby` profile: detect *real* block
//! I/O on the decrypted mapper, and when a disk has been idle past its window,
//! spin the whole backing disk down (unmount -> cryptsetup close -> power off)
//! to stop needless platter wear. `always-on` disks are never touched.
//!
//! Idleness is judged from `/sys/block/<dm>/stat` counters, NOT atime — atime
//! updates would otherwise masquerade as access. Cold-standby disks are also
//! mounted `noatime` (see `reconcile`) to keep the signal clean.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::{Disk, PowerOffMethod, Teardown};
use crate::error::{Code, Error, Result};
use crate::reconcile::{unit_name_for, FileChange};

use crate::cmd::Context;

/// Persisted idle-monitor state for one disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MonitorState {
    /// Last observed read+write completion counter from the mapper.
    counter: u64,
    /// Epoch seconds when `counter` last changed (i.e. last real access).
    last_change: u64,
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve `/dev/mapper/<name>` to its `/sys/block/dm-N/stat` path, if open.
fn mapper_stat_path(mapper_name: &str) -> Option<PathBuf> {
    let dev = format!("/dev/mapper/{mapper_name}");
    let target = std::fs::read_link(&dev).ok()?; // e.g. "../dm-3"
    let dm = target.file_name()?.to_string_lossy().to_string();
    let stat = PathBuf::from(format!("/sys/block/{dm}/stat"));
    stat.exists().then_some(stat)
}

/// Sum of reads-completed + writes-completed from a `/sys/block/*/stat` line.
fn read_io_counter(stat: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(stat).ok()?;
    let f: Vec<u64> = text
        .split_whitespace()
        .filter_map(|t| t.parse().ok())
        .collect();
    // Field 0 = reads completed, field 4 = writes completed.
    Some(*f.first()? + *f.get(4)?)
}

/// Resolve a LUKS container path to its whole backing disk (strip partition).
/// `/dev/sdb1` -> `/dev/sdb`, `/dev/nvme0n1p2` -> `/dev/nvme0n1`, `/dev/loop0`
/// stays `/dev/loop0`. Falls back to the input on anything unexpected.
pub fn physical_device_for(container: &str) -> String {
    let real = std::fs::canonicalize(container)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| container.to_string());
    let base = match real.rsplit('/').next() {
        Some(b) => b,
        None => return real,
    };
    // A partition has /sys/class/block/<base>/partition; its parent dir name is
    // the holder disk (works for sd*, nvme*, mmcblk*).
    let sys = format!("/sys/class/block/{base}");
    if Path::new(&format!("{sys}/partition")).exists() {
        if let Ok(link) = std::fs::read_link(&sys) {
            if let Some(parent) = link.parent().and_then(|p| p.file_name()) {
                return format!("/dev/{}", parent.to_string_lossy());
            }
        }
    }
    real
}

fn sys_flag(phys: &str, attr: &str) -> bool {
    let base = phys.rsplit('/').next().unwrap_or(phys);
    std::fs::read_to_string(format!("/sys/block/{base}/{attr}"))
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn is_rotational(phys: &str) -> bool {
    sys_flag(phys, "queue/rotational")
}
fn is_removable(phys: &str) -> bool {
    sys_flag(phys, "removable")
}

/// Pick the concrete power-down action for `auto`, given the device's traits.
fn resolve_method(method: PowerOffMethod, phys: &str) -> PowerOffMethod {
    match method {
        PowerOffMethod::Auto => {
            if is_removable(phys) {
                PowerOffMethod::PowerOff
            } else if is_rotational(phys) {
                PowerOffMethod::Standby
            } else {
                PowerOffMethod::Auto // sentinel: nothing applicable
            }
        }
        other => other,
    }
}

/// Minimal systemd unit-name escaping for a dm-crypt mapper name (used to build
/// the `systemd-cryptsetup@<inst>.service` instance). Matches `systemd-escape`
/// for the `[A-Za-z0-9:_.-]`-style names cryptsetup uses (`-` -> `\x2d`, etc).
fn systemd_escape(s: &str) -> String {
    let mut out = String::new();
    for (i, b) in s.bytes().enumerate() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || c == '_' || (c == '.' && i != 0) {
            out.push(c);
        } else if c == '/' {
            out.push('-');
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

fn is_mounted(mountpoint: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|s| {
            s.lines()
                .any(|l| l.split_whitespace().nth(1) == Some(mountpoint))
        })
        .unwrap_or(false)
}

/// Whether the disk's mapper is currently open (i.e. the disk is "powered").
pub fn is_powered(disk: &Disk) -> bool {
    Path::new(&format!("/dev/mapper/{}", disk.mapper_name())).exists()
}

/// Spin the whole disk down: unmount -> close mapping -> power off the platters.
/// Every mutating step goes through the Runner so --dry-run/--plan/--debug work.
pub fn spindown(ctx: &Context, disk: &Disk) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let mapper = disk.mapper_name();
    let mapper_dev = format!("/dev/mapper/{mapper}");
    let mp = disk.mountpoint.to_string_lossy().to_string();
    let mut steps: Vec<Value> = Vec::new();

    match disk.teardown {
        Teardown::Direct => {
            // 1. unmount if mounted.
            if is_mounted(&mp) {
                ctx.runner
                    .run(
                        &["umount", &mp],
                        "unmount cold-standby disk before spindown",
                    )?
                    .require("umount")?;
                steps.push(json!({"step": "umount", "target": mp}));
            } else {
                steps.push(json!({"step": "umount", "target": mp, "skipped": "not mounted"}));
            }

            // 2. drop the dm-crypt mapping (back to ciphertext-at-rest).
            if Path::new(&mapper_dev).exists() || dry {
                ctx.runner
                    .run(&["cryptsetup", "close", &mapper], "close LUKS mapping")?
                    .require("cryptsetup close")?;
                steps.push(json!({"step": "cryptsetup-close", "mapper": mapper}));
            } else {
                steps.push(
                    json!({"step": "cryptsetup-close", "mapper": mapper, "skipped": "not open"}),
                );
            }
        }
        Teardown::Systemd => {
            // 1. stop the .mount unit (clean unmount; an automount re-arms).
            let mount_unit = unit_name_for(&disk.mountpoint);
            ctx.runner
                .run(
                    &["systemctl", "stop", &mount_unit],
                    "stop systemd mount unit before spindown",
                )?
                .require("systemctl stop mount")?;
            steps.push(json!({"step": "systemctl-stop-mount", "unit": mount_unit}));

            // 2. stop systemd-cryptsetup@<mapper> so the next access re-opens it
            //    cleanly via TPM2 (raw close would leave the unit stale-active).
            let cs_unit = format!("systemd-cryptsetup@{}.service", systemd_escape(&mapper));
            ctx.runner
                .run(
                    &["systemctl", "stop", &cs_unit],
                    "stop systemd-cryptsetup unit",
                )?
                .require("systemctl stop cryptsetup")?;
            steps.push(json!({"step": "systemctl-stop-cryptsetup", "unit": cs_unit}));
        }
    }

    // 3. power down the backing physical disk.
    let container = disk.device_path();
    let phys = physical_device_for(&container);
    let resolved = resolve_method(disk.power_off_method, &phys);
    let (method_used, skip_reason) = match resolved {
        PowerOffMethod::PowerOff => {
            ctx.runner
                .run(
                    &["udisksctl", "power-off", "-b", &phys],
                    "power off backing disk (udisksctl)",
                )?
                .require("udisksctl power-off")
                .map_err(power_err)?;
            ("power-off", None)
        }
        PowerOffMethod::Standby => {
            ctx.runner
                .run(&["hdparm", "-y", &phys], "spin down backing disk (hdparm -y)")?
                .require("hdparm -y")
                .map_err(power_err)?;
            ("standby", None)
        }
        PowerOffMethod::Sleep => {
            ctx.runner
                .run(&["hdparm", "-Y", &phys], "sleep backing disk (hdparm -Y)")?
                .require("hdparm -Y")
                .map_err(power_err)?;
            ("sleep", None)
        }
        PowerOffMethod::Auto => (
            "none",
            Some(format!(
                "{phys} is neither removable nor rotational (e.g. loop/SSD); unmount+close done, no spindown"
            )),
        ),
    };
    steps.push(json!({
        "step": "power-down",
        "device": phys,
        "method_used": method_used,
        "skip_reason": skip_reason,
    }));

    // Reset monitor state so a re-opened disk starts a fresh idle window.
    if !dry {
        let _ = std::fs::remove_file(ctx.paths.monitor_state(&disk.name));
    }

    Ok(json!({
        "ok": true,
        "action": "power-off",
        "name": disk.name,
        "method_used": method_used,
        "skip_reason": skip_reason,
        "dry_run": dry,
        "steps": steps,
    }))
}

fn power_err(e: Error) -> Error {
    Error::new(Code::EPowerOff, e.message)
        .with_hint("install hdparm/udisksctl, or set power_off_method explicitly")
}

fn load_state(path: &Path) -> Option<MonitorState> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn save_state(path: &Path, state: &MonitorState) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(s) = serde_json::to_string(state) {
        let _ = std::fs::write(path, s);
    }
}

/// One monitor tick: observe real I/O, update idle state, and spin the disk down
/// if it has been idle past its window. Idempotent and safe to call on a repeat.
pub fn monitor_tick(ctx: &Context, disk: &Disk) -> Result<Value> {
    if !disk.is_cold_standby() {
        return Ok(json!({
            "ok": true, "action": "skip", "name": disk.name,
            "reason": "power_profile=always-on",
        }));
    }

    // Nothing to monitor if the mapping isn't open (disk already down).
    let mapper = disk.mapper_name();
    if !Path::new(&format!("/dev/mapper/{mapper}")).exists() {
        return Ok(json!({
            "ok": true, "action": "down", "name": disk.name,
            "reason": "mapper not open; disk already powered down",
        }));
    }

    let timeout = disk.idle_timeout_secs();
    let counter = mapper_stat_path(&mapper).and_then(|p| read_io_counter(&p));
    let counter = match counter {
        Some(c) => c,
        None => {
            return Ok(json!({
                "ok": true, "action": "keep", "name": disk.name,
                "note": "could not read I/O counter; staying up",
            }));
        }
    };

    let state_path = ctx.paths.monitor_state(&disk.name);
    let now = now_epoch();
    let prev = load_state(&state_path);

    let (idle_secs, activity) = match &prev {
        Some(s) if s.counter == counter => (now.saturating_sub(s.last_change), false),
        _ => (0, true), // first observation or counter advanced => real access
    };

    if activity {
        if !ctx.global.effective_dry_run() {
            save_state(
                &state_path,
                &MonitorState {
                    counter,
                    last_change: now,
                },
            );
        }
        return Ok(json!({
            "ok": true, "action": "keep", "name": disk.name,
            "io_counter": counter, "idle_secs": 0, "idle_timeout_secs": timeout,
            "reason": "real access detected",
        }));
    }

    if idle_secs >= timeout {
        let sd = spindown(ctx, disk)?;
        return Ok(json!({
            "ok": true, "action": "power-off", "name": disk.name,
            "io_counter": counter, "idle_secs": idle_secs, "idle_timeout_secs": timeout,
            "spindown": sd,
        }));
    }

    Ok(json!({
        "ok": true, "action": "keep", "name": disk.name,
        "io_counter": counter, "idle_secs": idle_secs, "idle_timeout_secs": timeout,
        "reason": "idle but within window",
    }))
}

/// Reconcile the systemd idle-monitor unit for a disk: write it for
/// cold-standby disks, remove it for always-on. Mirrors `reconcile`'s tagging.
pub fn reconcile_monitor_unit(
    ctx: &Context,
    unit_dir: &Path,
    disk: &Disk,
    dry: bool,
) -> Result<FileChange> {
    let unit_name = format!("tpmnt-monitor-{}.service", disk.name);
    let path = unit_dir.join(&unit_name);

    if !disk.is_cold_standby() {
        // Ensure removed (idempotent).
        let action = if path.exists() {
            if !dry {
                let _ = std::fs::remove_file(&path);
            }
            "remove"
        } else {
            "noop"
        };
        return Ok(FileChange {
            path: path.display().to_string(),
            action,
            line: unit_name,
        });
    }

    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "tpmnt".to_string());
    let cfg = ctx.global.config.display();
    let content = format!(
        "# tpmnt:{name}\n[Unit]\nDescription=tpmnt cold-standby idle power-off for {name}\nAfter=local-fs.target\n\n[Service]\nType=simple\nExecStart={exe} --config {cfg} monitor {name}\nRestart=always\nRestartSec=30\n\n[Install]\nWantedBy=multi-user.target\n",
        name = disk.name,
    );

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let action = if existing.is_empty() {
        "create"
    } else if existing != content {
        "update"
    } else {
        "noop"
    };
    if action != "noop" && !dry {
        std::fs::create_dir_all(unit_dir)
            .map_err(|e| Error::new(Code::EInternal, format!("mkdir unit dir: {e}")))?;
        std::fs::write(&path, &content)
            .map_err(|e| Error::new(Code::EInternal, format!("write monitor unit: {e}")))?;
    }
    Ok(FileChange {
        path: path.display().to_string(),
        action,
        line: unit_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_device_strips_only_real_partitions() {
        // Without sysfs we can't classify, so a whole-device path round-trips.
        assert_eq!(physical_device_for("/dev/loop0"), "/dev/loop0");
    }

    #[test]
    fn io_counter_parses_stat_line() {
        let dir = std::env::temp_dir().join(format!("tpmnt-stat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("stat");
        // reads_completed=10 ... writes_completed=5 ...
        std::fs::write(
            &f,
            "      10        0      200      30        5        0       40       6\n",
        )
        .unwrap();
        assert_eq!(read_io_counter(&f), Some(15));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn systemd_escape_mapper_names() {
        assert_eq!(
            systemd_escape("luks-e7e6fc65-d99a"),
            "luks\\x2de7e6fc65\\x2dd99a"
        );
        assert_eq!(systemd_escape("tpmnt_data"), "tpmnt_data");
    }

    #[test]
    fn auto_method_on_non_rotational_non_removable_is_sentinel() {
        // loop0 is neither removable nor rotational => Auto sentinel (skip).
        assert_eq!(
            resolve_method(PowerOffMethod::Auto, "/dev/loop0"),
            PowerOffMethod::Auto
        );
    }
}
