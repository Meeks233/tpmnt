//! Per-disk power management for the `cold-standby` profile: detect *real* block
//! I/O on the decrypted mapper, and when a disk has been idle past its window,
//! spin the whole backing disk down (unmount -> cryptsetup close -> power off)
//! to stop needless platter wear. `always-on` disks are never touched.
//!
//! Idleness is judged from `/sys/block/<dm>/stat` counters, NOT atime — atime
//! updates would otherwise masquerade as access. Cold-standby disks are also
//! mounted `noatime` (see `reconcile`) to keep the signal clean.

use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::blockdev;
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

/// Read a `/sys/block/<dev>/<attr>` boolean flag. `prefix` is a disk's SSH argv
/// (empty = local): a remote disk's platters live on its host, so its traits and
/// power state must be read/acted on *there*, not against a nonexistent local
/// path. For a whole-disk container the `/dev/sdX` name matches on both ends.
fn sys_flag(ctx: &Context, prefix: &[String], phys: &str, attr: &str) -> bool {
    let base = phys.rsplit('/').next().unwrap_or(phys);
    let path = format!("/sys/block/{base}/{attr}");
    if prefix.is_empty() {
        std::fs::read_to_string(&path)
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
    } else {
        ctx.runner
            .probe_on(prefix, &["cat", &path], "read sysfs device flag")
            .map(|o| o.stdout.trim() == "1")
            .unwrap_or(false)
    }
}

fn is_rotational(ctx: &Context, prefix: &[String], phys: &str) -> bool {
    sys_flag(ctx, prefix, phys, "queue/rotational")
}
fn is_removable(ctx: &Context, prefix: &[String], phys: &str) -> bool {
    sys_flag(ctx, prefix, phys, "removable")
}

/// Pick the concrete power-down action for `auto`, given the device's traits
/// (read on the disk's host, local or remote).
fn resolve_method(
    ctx: &Context,
    prefix: &[String],
    method: PowerOffMethod,
    phys: &str,
) -> PowerOffMethod {
    resolve_method_traits(
        method,
        is_removable(ctx, prefix, phys),
        is_rotational(ctx, prefix, phys),
    )
}

/// The backing disk's whole-device path *and* the SSH prefix to reach it. A
/// local disk strips partitions via sysfs; a remote disk's config `device` is
/// its whole backing disk on the remote host, used verbatim (local sysfs can't
/// see it). Both power tuning and spindown act through this pair.
fn phys_and_prefix(ctx: &Context, disk: &Disk) -> (String, Vec<String>) {
    let container = disk.device_path();
    let prefix = ctx.config.ssh_prefix_for(disk);
    let phys = if prefix.is_empty() {
        physical_device_for(&container)
    } else {
        container
    };
    (phys, prefix)
}

/// Prepend `sudo -n` for a remote host — spinning down/tuning a block device
/// needs root there, and tpmnt's SSH user is unprivileged (matches the
/// `qemu-nbd`/`luksDump` remote convention in blockdev.rs / adopt.rs). Locally
/// tpmnt already runs as root (the monitor unit / `sudo tpmnt`), so no wrapper.
fn priv_argv<'a>(prefix: &[String], argv: &[&'a str]) -> Vec<&'a str> {
    if prefix.is_empty() {
        argv.to_vec()
    } else {
        let mut v = vec!["sudo", "-n"];
        v.extend_from_slice(argv);
        v
    }
}

/// Pure trait-to-action mapping, split out so it is testable without touching
/// `/sys/block` (which is host-specific and non-hermetic under CI).
fn resolve_method_traits(
    method: PowerOffMethod,
    removable: bool,
    rotational: bool,
) -> PowerOffMethod {
    match method {
        PowerOffMethod::Auto => {
            if removable {
                PowerOffMethod::PowerOff
            } else if rotational {
                PowerOffMethod::Standby
            } else {
                PowerOffMethod::Auto // sentinel: nothing applicable
            }
        }
        other => other,
    }
}

/// Make tpmnt the *sole* spindown authority for a freshly-spun-up rotational
/// disk. The dominant HDD wear source is not continuous spinning but frequent
/// cycling — above all the drive's own aggressive APM head-parking, which can
/// burn through the ~300k load-cycle budget in months. So on every spin-up we:
///   * `-B 254` — highest APM: keep the drive responsive with no firmware
///     auto-parking/spindown while it's actually in use this session, and
///   * `-S 0`   — disable the drive's internal standby timer, so tpmnt's own
///     deliberate, well-spaced idle-spindown is the *only* thing that ever
///     stops the platters (no competing timers thrashing the motor).
///
/// These settings reset across a standby cycle, hence re-applying on each open.
///
/// Best-effort: rotational, non-removable disks only, and a drive/bridge that
/// doesn't support APM just fails harmlessly (recorded, never fatal). We never
/// query state with `hdparm -C` — that wakes sleeping drives; the monitor reads
/// in-kernel `/sys/block/*/stat` counters instead.
fn tune_spindown_authority(ctx: &Context, disk: &Disk) -> Value {
    let (phys, prefix) = phys_and_prefix(ctx, disk);
    let dry = ctx.global.effective_dry_run();
    // Only meaningful for spinning disks; SSD/loop have no platters to park, and
    // removable/USB power-off doesn't use ATA APM. Traits read on the disk's host.
    if !dry
        && !should_tune_apm(
            is_rotational(ctx, &prefix, &phys),
            is_removable(ctx, &prefix, &phys),
        )
    {
        return json!({"step": "tune-power", "device": phys, "skipped": "not a fixed rotational disk"});
    }
    match ctx.runner.run_on(
        &prefix,
        &priv_argv(&prefix, &["hdparm", "-B", "254", "-S", "0", &phys]),
        "disable firmware APM parking + standby timer (tpmnt owns spindown)",
    ) {
        Ok(out) if out.ok() => {
            json!({"step": "tune-power", "device": phys, "apm": 254, "standby_timer": "off"})
        }
        Ok(out) => {
            json!({"step": "tune-power", "device": phys, "skipped": "APM unsupported", "stderr": out.stderr.trim()})
        }
        Err(e) => {
            json!({"step": "tune-power", "device": phys, "skipped": "hdparm unavailable", "error": e.message})
        }
    }
}

/// APM tuning applies only to fixed rotational disks: SSD/loop have no platters
/// to park, and removable/USB drives use `udisksctl power-off` (not ATA APM).
/// Split out pure so it's testable without touching host-specific `/sys/block`.
fn should_tune_apm(rotational: bool, removable: bool) -> bool {
    rotational && !removable
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

/// Outcome of an attempt to bring a disk down.
enum SpinOutcome {
    /// Disk powered off; carries the full result JSON.
    Down(Value),
    /// The disk is in use and a *clean* unmount/stop failed. No force (`-f`/`-l`)
    /// was applied, so nothing in flight was interrupted. Carries steps so far.
    Busy(Vec<Value>),
}

/// What `remove`-method power-off recorded so spin-up can bring the disk back:
/// the SCSI host to rescan and (for a remote disk) how to rebuild the ciphertext
/// forward. Persisted only while the disk is removed from its host OS.
#[derive(Debug, Serialize, Deserialize)]
struct ForwardState {
    /// True when the disk lives on a remote host reached over SSH.
    remote: bool,
    /// The backing device on its host (e.g. `/dev/sda`).
    remote_dev: String,
    /// The SCSI host to rescan to re-probe the disk (e.g. `host6`).
    scsi_host: String,
    /// NBD port the remote `qemu-nbd` served on (remote disks only).
    port: u16,
}

/// The `hostN` component of a device's sysfs path — the SCSI host to rescan to
/// bring the device back after `.../device/delete`. Read on the disk's own host.
fn scsi_host_of(ctx: &Context, prefix: &[String], base: &str) -> Option<String> {
    let link = format!("/sys/block/{base}/device");
    let target = if prefix.is_empty() {
        std::fs::read_link(&link)
            .ok()?
            .to_string_lossy()
            .into_owned()
    } else {
        ctx.runner
            .probe_on(
                prefix,
                &["readlink", "-f", &link],
                "resolve device sysfs path",
            )
            .ok()
            .map(|o| o.stdout.trim().to_string())?
    };
    target
        .split('/')
        .find(|c| c.starts_with("host") && c[4..].chars().all(|d| d.is_ascii_digit()))
        .map(String::from)
}

/// Discover the NBD port a remote `qemu-nbd` currently serves `remote_dev` on, by
/// parsing `pgrep -af qemu-nbd`. Needed to rebuild the exact same forward later.
fn nbd_port_for(ctx: &Context, prefix: &[String], remote_dev: &str) -> Option<u16> {
    let out = ctx
        .runner
        .probe_on(prefix, &["pgrep", "-af", "qemu-nbd"], "find qemu-nbd port")
        .ok()?;
    for line in out.stdout.lines() {
        if line.split_whitespace().last() != Some(remote_dev) {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = toks.iter().position(|t| *t == "-p") {
            if let Some(p) = toks.get(i + 1).and_then(|p| p.parse::<u16>().ok()) {
                return Some(p);
            }
        }
    }
    None
}

/// Run `echo <val> > <path>` as root on the disk's host (local or remote). The
/// `>` redirect needs a shell. Locally tpmnt is already root, so `sh -c` runs it
/// directly. Remotely the command is flattened by ssh and re-parsed by the
/// host's login shell, so the inner command is single-quoted to survive that
/// pass — otherwise the login shell (not root's `sh`) would perform the redirect
/// and be denied, and glob metacharacters would be expanded there.
fn sysfs_write(ctx: &Context, prefix: &[String], path: &str, val: &str, why: &str) -> Result<()> {
    let inner = format!("echo {val} > {path}");
    if prefix.is_empty() {
        ctx.runner
            .run(&["sh", "-c", &inner], why)?
            .require("sysfs write")?;
    } else {
        let quoted = format!("'{inner}'");
        ctx.runner
            .run_on(prefix, &["sudo", "-n", "sh", "-c", &quoted], why)?
            .require("sysfs write")?;
    }
    Ok(())
}

/// The `remove` power-off tail: after the mapping is torn down, remove the
/// backing block device from its host OS so the disk fully disappears (a disk
/// manager's "Power Off Disk"), recording how to bring it back. For a remote
/// disk the ciphertext forward is discovered and torn down first, since the
/// device can't be deleted while `qemu-nbd` holds it open.
fn remove_from_os(ctx: &Context, disk: &Disk) -> Result<Value> {
    let (phys, prefix) = phys_and_prefix(ctx, disk);
    let base = phys.rsplit('/').next().unwrap_or(&phys).to_string();
    let remote = !prefix.is_empty();

    let scsi_host = scsi_host_of(ctx, &prefix, &base).ok_or_else(|| {
        Error::new(
            Code::EPowerOff,
            format!(
                "cannot resolve SCSI host for {phys}; refusing to remove (would be unrecoverable)"
            ),
        )
        .with_hint("the disk must sit on a rescannable SCSI/USB host for `remove` power-off")
    })?;

    // For a remote disk, discover + tear the forward down so the delete succeeds.
    let mut port = 0u16;
    if remote {
        let local_dev = local_container(ctx, disk)?;
        port = nbd_port_for(ctx, &prefix, &phys).ok_or_else(|| {
            Error::new(
                Code::ETransport,
                format!("no qemu-nbd found serving {phys}; cannot record forward to rebuild"),
            )
        })?;
        // Spin the platters down explicitly before the device leaves the OS.
        let _ = ctx.runner.run_on(
            &prefix,
            &priv_argv(&prefix, &["hdparm", "-y", &phys]),
            "spin down backing disk before removal",
        );
        blockdev::teardown_forward(
            &ctx.runner,
            &prefix,
            &blockdev::control_path(port),
            &local_dev,
            &phys,
        );
    }

    // Persist how to bring it back BEFORE the point of no return.
    let state = ForwardState {
        remote,
        remote_dev: phys.clone(),
        scsi_host: scsi_host.clone(),
        port,
    };
    let sp = ctx.paths.forward_state(&disk.name);
    if let Some(parent) = sp.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&sp, serde_json::to_string(&state).unwrap_or_default());

    // Remove the block device from its host OS (spins it down via STOP UNIT too).
    sysfs_write(
        ctx,
        &prefix,
        &format!("/sys/block/{base}/device/delete"),
        "1",
        "remove backing disk from host OS (device/delete)",
    )?;

    Ok(json!({
        "step": "power-down",
        "device": phys,
        "method_used": "remove",
        "scsi_host": scsi_host,
        "removed_from_os": true,
    }))
}

/// Reverse `remove_from_os`: rescan the SCSI host to re-probe the disk, wait for
/// it to reappear, and (for a remote disk) rebuild the ciphertext forward so the
/// caller can `cryptsetup open` it again. No-op when no removal is recorded.
fn restore_from_os(ctx: &Context, disk: &Disk) -> Result<Option<Value>> {
    let sp = ctx.paths.forward_state(&disk.name);
    let raw = match std::fs::read_to_string(&sp) {
        Ok(s) => s,
        Err(_) => return Ok(None), // nothing was removed; normal open path
    };
    let state: ForwardState = serde_json::from_str(&raw)
        .map_err(|e| Error::new(Code::EInternal, format!("corrupt forward state: {e}")))?;
    let prefix = ctx.config.ssh_prefix_for(disk);

    // 1. Rescan the host so the kernel re-probes the (spun-down) disk.
    sysfs_write(
        ctx,
        &prefix,
        &format!("/sys/class/scsi_host/{}/scan", state.scsi_host),
        "\"- - -\"",
        "rescan SCSI host to bring the disk back",
    )?;

    // 2. Wait for the backing device to reappear (bounded).
    let check = format!(
        "/sys/block/{}",
        state.remote_dev.rsplit('/').next().unwrap_or("")
    );
    let mut back = false;
    for _ in 0..30 {
        let present = if prefix.is_empty() {
            Path::new(&check).exists()
        } else {
            ctx.runner
                .probe_on(&prefix, &["test", "-e", &check], "await disk re-probe")
                .map(|o| o.ok())
                .unwrap_or(false)
        };
        if present {
            back = true;
            break;
        }
        sleep(Duration::from_millis(500));
    }
    if !back {
        return Err(Error::new(
            Code::EPowerOff,
            format!(
                "disk {} did not reappear after rescanning {}",
                state.remote_dev, state.scsi_host
            ),
        )
        .with_hint(
            "the host may not support software rescan; a physical reconnect may be required",
        ));
    }

    // 3. Rebuild the ciphertext forward for a remote disk.
    if state.remote {
        let remote = blockdev::require_remote(ctx.config.remote_for(disk), &disk.name)?;
        blockdev::attach_nbd_over_ssh(&ctx.runner, remote, &state.remote_dev, state.port)?;
    }

    let _ = std::fs::remove_file(&sp);
    Ok(Some(json!({
        "step": "rescan", "scsi_host": state.scsi_host, "device": state.remote_dev,
        "forward_rebuilt": state.remote,
    })))
}

/// Spin the whole disk down: unmount -> close mapping -> power off the platters.
/// Errors if the disk is busy (a clean unmount is impossible) rather than
/// forcing it — `tpmnt schedule` uses the soft path that defers instead.
pub fn spindown(ctx: &Context, disk: &Disk) -> Result<Value> {
    match spindown_impl(ctx, disk, false)? {
        SpinOutcome::Down(v) => Ok(v),
        SpinOutcome::Busy(_) => Err(Error::new(
            Code::EPowerOff,
            format!("disk '{}' is in use; refusing to force-unmount", disk.name),
        )
        .with_hint("retry once the mountpoint is idle, or stop the processes using it")),
    }
}

/// Shared teardown. When `soft`, a busy clean-unmount returns `Busy` (caller
/// decides whether to wait/defer) instead of failing — so data transfer in
/// flight is never interrupted. Every mutating step goes through the Runner so
/// --dry-run/--plan/--debug work.
fn spindown_impl(ctx: &Context, disk: &Disk, soft: bool) -> Result<SpinOutcome> {
    let dry = ctx.global.effective_dry_run();
    let mapper = disk.mapper_name();
    let mapper_dev = format!("/dev/mapper/{mapper}");
    let mp = disk.mountpoint.to_string_lossy().to_string();
    let mut steps: Vec<Value> = Vec::new();

    match disk.teardown {
        Teardown::Direct => {
            // 1. unmount if mounted (never `-f`/`-l`: a busy fs just fails cleanly).
            if is_mounted(&mp) {
                let out = ctx
                    .runner
                    .run(&["umount", &mp], "unmount disk before spindown")?;
                if !out.ok() {
                    if soft {
                        steps.push(json!({"step": "umount", "target": mp, "busy": true, "stderr": out.stderr.trim()}));
                        return Ok(SpinOutcome::Busy(steps));
                    }
                    out.require("umount")?;
                }
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
            // 1. stop the .mount unit (clean unmount; an automount re-arms). A
            //    busy mount makes the stop job fail -> treat as Busy under soft.
            let mount_unit = unit_name_for(&disk.mountpoint);
            let out = ctx.runner.run(
                &["systemctl", "stop", &mount_unit],
                "stop systemd mount unit before spindown",
            )?;
            if !out.ok() {
                if soft {
                    steps.push(json!({"step": "systemctl-stop-mount", "unit": mount_unit, "busy": true, "stderr": out.stderr.trim()}));
                    return Ok(SpinOutcome::Busy(steps));
                }
                out.require("systemctl stop mount")?;
            }
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

    // 3. power down the backing physical disk (on its host — local or remote).
    let (phys, prefix) = phys_and_prefix(ctx, disk);
    let resolved = resolve_method(ctx, &prefix, disk.power_off_method, &phys);

    // `remove` fully removes the device from its host OS (reversible on spin-up).
    // It owns its own spin-down + forward teardown, so it replaces the methods
    // below rather than composing with them.
    if resolved == PowerOffMethod::Remove {
        let (method_used, skip_reason) = ("remove", None::<String>);
        if dry {
            steps.push(json!({"step": "power-down", "device": phys, "method_used": method_used, "planned": "remove device from host OS + record rescan"}));
        } else {
            steps.push(remove_from_os(ctx, disk)?);
            let _ = std::fs::remove_file(ctx.paths.monitor_state(&disk.name));
        }
        return Ok(SpinOutcome::Down(json!({
            "ok": true, "action": "power-off", "name": disk.name,
            "method_used": method_used, "skip_reason": skip_reason,
            "dry_run": dry, "steps": steps,
        })));
    }

    let (method_used, skip_reason) = match resolved {
        PowerOffMethod::PowerOff => {
            ctx.runner
                .run_on(
                    &prefix,
                    &priv_argv(&prefix, &["udisksctl", "power-off", "-b", &phys]),
                    "power off backing disk (udisksctl)",
                )?
                .require("udisksctl power-off")
                .map_err(power_err)?;
            ("power-off", None)
        }
        PowerOffMethod::Standby => {
            ctx.runner
                .run_on(
                    &prefix,
                    &priv_argv(&prefix, &["hdparm", "-y", &phys]),
                    "spin down backing disk (hdparm -y)",
                )?
                .require("hdparm -y")
                .map_err(power_err)?;
            ("standby", None)
        }
        PowerOffMethod::Sleep => {
            ctx.runner
                .run_on(
                    &prefix,
                    &priv_argv(&prefix, &["hdparm", "-Y", &phys]),
                    "sleep backing disk (hdparm -Y)",
                )?
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
        // Handled above with an early return; kept for match exhaustiveness.
        PowerOffMethod::Remove => unreachable!("remove is handled before this match"),
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

    Ok(SpinOutcome::Down(json!({
        "ok": true,
        "action": "power-off",
        "name": disk.name,
        "method_used": method_used,
        "skip_reason": skip_reason,
        "dry_run": dry,
        "steps": steps,
    })))
}

/// The LOCAL block device to `cryptsetup open` for this disk. A local disk uses
/// its configured container path directly. A remote disk's ciphertext is
/// forwarded here as a `/dev/nbdN`, so the config `device` (which names the disk
/// on its *remote* host, e.g. `/dev/sda`) can't be opened locally — instead we
/// find the already-attached nbd device whose LUKS header UUID matches. This is
/// the spin-up counterpart to spindown's remote `hdparm` power-off: teardown
/// leaves the forward live, so spin-up just re-opens the forwarded ciphertext.
fn local_container(ctx: &Context, disk: &Disk) -> Result<String> {
    if ctx.config.ssh_prefix_for(disk).is_empty() {
        return Ok(disk.device_path());
    }
    for n in 0..16 {
        // Only attached nbd devices report a non-zero size; skip the rest cheaply.
        match std::fs::read_to_string(format!("/sys/block/nbd{n}/size")) {
            Ok(s) if s.trim() != "0" => {}
            _ => continue,
        }
        let dev = format!("/dev/nbd{n}");
        if let Ok(out) = ctx.runner.probe(
            &["cryptsetup", "luksUUID", &dev],
            "identify forwarded NBD device by LUKS UUID",
        ) {
            if out.ok() && out.stdout.trim() == disk.uuid {
                return Ok(dev);
            }
        }
    }
    // Under --plan/--dry-run the forward may legitimately be absent; fall back to
    // the config path so the plan still renders instead of hard-failing.
    if ctx.global.effective_dry_run() {
        return Ok(disk.device_path());
    }
    Err(Error::new(
        Code::ETransport,
        format!(
            "no forwarded NBD device carries '{}' (uuid {}); ciphertext is not attached locally",
            disk.name, disk.uuid
        ),
    )
    .with_hint("re-establish the ciphertext forward (`tpmnt apply`/`adopt`), then retry power-on"))
}

/// Bring a scheduled disk up: open (TPM2 token) + mount, mirroring the disk's
/// teardown mode so the pairing is symmetric. Idempotent — already-open /
/// already-mounted steps are skipped. If the disk was removed from its host OS
/// (the `remove` power-off method), first rescan it back and rebuild its forward.
pub fn spinup(ctx: &Context, disk: &Disk) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let mapper = disk.mapper_name();
    let mapper_dev = format!("/dev/mapper/{mapper}");
    let mp = disk.mountpoint.to_string_lossy().to_string();
    let mut steps: Vec<Value> = Vec::new();

    // Reverse a `remove` power-off: rescan the disk back + rebuild the forward
    // before anything tries to open it. No-op when nothing was removed.
    if !dry {
        if let Some(restore) = restore_from_os(ctx, disk)? {
            steps.push(restore);
        }
    }

    match disk.teardown {
        Teardown::Direct => {
            // The container to open lives *here*: a local disk at its configured
            // path, a remote disk at the local NBD device forwarding its
            // ciphertext (the config `device` names it on the *remote* host).
            let container = local_container(ctx, disk)?;
            if Path::new(&mapper_dev).exists() && !dry {
                steps.push(
                    json!({"step": "cryptsetup-open", "mapper": mapper, "skipped": "already open"}),
                );
            } else {
                // `cryptsetup open` auto-tries enrolled tokens (TPM2) — no prompt.
                ctx.runner
                    .run(
                        &["cryptsetup", "open", &container, &mapper],
                        "open LUKS mapping via TPM2 token",
                    )?
                    .require("cryptsetup open")?;
                steps.push(json!({"step": "cryptsetup-open", "mapper": mapper}));
            }

            if is_mounted(&mp) && !dry {
                steps.push(json!({"step": "mount", "target": mp, "skipped": "already mounted"}));
            } else {
                if !dry {
                    let _ = std::fs::create_dir_all(&disk.mountpoint);
                }
                ctx.runner
                    .run(&["mount", &mp], "mount disk")?
                    .require("mount")?;
                steps.push(json!({"step": "mount", "target": mp}));
            }
        }
        Teardown::Systemd => {
            let cs_unit = format!("systemd-cryptsetup@{}.service", systemd_escape(&mapper));
            ctx.runner
                .run(
                    &["systemctl", "start", &cs_unit],
                    "start systemd-cryptsetup unit (TPM2)",
                )?
                .require("systemctl start cryptsetup")?;
            steps.push(json!({"step": "systemctl-start-cryptsetup", "unit": cs_unit}));

            let mount_unit = unit_name_for(&disk.mountpoint);
            ctx.runner
                .run(
                    &["systemctl", "start", &mount_unit],
                    "start systemd mount unit",
                )?
                .require("systemctl start mount")?;
            steps.push(json!({"step": "systemctl-start-mount", "unit": mount_unit}));
        }
    }

    // Disk is up: claim sole spindown authority + kill aggressive APM parking.
    steps.push(tune_spindown_authority(ctx, disk));

    Ok(json!({
        "ok": true,
        "action": "power-on",
        "name": disk.name,
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

    let first_obs = prev.is_none();
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
        // First time we see this disk open this session: claim sole spindown
        // authority + disable aggressive firmware APM head-parking.
        let tune = first_obs.then(|| tune_spindown_authority(ctx, disk));
        return Ok(json!({
            "ok": true, "action": "keep", "name": disk.name,
            "io_counter": counter, "idle_secs": 0, "idle_timeout_secs": timeout,
            "reason": "real access detected", "tune": tune,
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

/// Persisted state for a disk's scheduled power-off grace period.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ScheduleState {
    /// Epoch when the busy-grace expires (0 = no power-off pending yet).
    off_deadline: u64,
    /// True once we gave up forcing this off-cycle (data-safety deferral). Reset
    /// the moment the disk re-enters its on-window.
    deferred: bool,
}

fn load_sched(path: &Path) -> ScheduleState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_sched(path: &Path, st: &ScheduleState) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(s) = serde_json::to_string(st) {
        let _ = std::fs::write(path, s);
    }
}

/// Resolve a timezone to its current UTC offset (seconds east of UTC). A fixed
/// offset ("+08:00") is parsed directly; a named zone ("Asia/Shanghai") or the
/// system default is resolved via `date +%z` (delegating to the host tzdata,
/// rather than bundling a tz database).
fn resolve_offset_secs(ctx: &Context, tz: Option<&str>) -> Result<i64> {
    if let Some(t) = tz {
        if let Some(o) = crate::config::parse_utc_offset(t) {
            return Ok(o);
        }
    }
    let out = match tz {
        Some(name) => ctx.runner.probe(
            &["env", &format!("TZ={name}"), "date", "+%z"],
            "resolve timezone offset",
        )?,
        None => ctx
            .runner
            .probe(&["date", "+%z"], "resolve local timezone offset")?,
    };
    let z = out.stdout.trim();
    crate::config::parse_utc_offset(z).ok_or_else(|| {
        Error::new(
            Code::EConfig,
            format!("could not resolve timezone offset (date returned '{z}')"),
        )
        .with_hint("use a fixed offset like \"+08:00\" or a valid IANA zone name")
    })
}

/// One schedule tick for a disk: power it up inside its on-window, and down
/// outside it. Power-off is data-safety gated — a busy disk is never force
/// unmounted; instead we wait `grace` (10% of the on-window) for the transfer
/// to finish, then defer (leave the disk up) rather than interrupt it.
/// Idempotent and safe to call repeatedly.
pub fn schedule_tick(ctx: &Context, disk: &Disk, tz_override: Option<&str>) -> Result<Value> {
    let sched = match &disk.schedule {
        Some(s) => s,
        None => {
            return Ok(json!({
                "ok": true, "action": "skip", "name": disk.name,
                "reason": "no schedule configured",
            }));
        }
    };

    let dry = ctx.global.effective_dry_run();
    let tz = tz_override.or(sched.timezone.as_deref());
    let offset = resolve_offset_secs(ctx, tz)?;
    let now = now_epoch();
    let tod = (now as i64 + offset).rem_euclid(86_400) as u32;
    let in_window = sched.contains(tod);
    let powered = is_powered(disk);
    let state_path = ctx.paths.schedule_state(&disk.name);
    let clock = json!({"tod_secs": tod, "offset_secs": offset, "in_window": in_window});

    // -- Inside the on-window: ensure the disk is up; cancel any pending off. ---
    if in_window {
        if !dry {
            let _ = std::fs::remove_file(&state_path);
        }
        if powered {
            return Ok(json!({
                "ok": true, "action": "up", "name": disk.name, "clock": clock,
                "reason": "in window, already powered",
            }));
        }
        let up = spinup(ctx, disk)?;
        return Ok(json!({
            "ok": true, "action": "power-on", "name": disk.name, "clock": clock,
            "spinup": up,
        }));
    }

    // -- Outside the window: bring the disk down, but never break transfers. ----
    if !powered {
        if !dry {
            let _ = std::fs::remove_file(&state_path);
        }
        return Ok(json!({
            "ok": true, "action": "down", "name": disk.name, "clock": clock,
            "reason": "out of window, already powered down",
        }));
    }

    let mut st = load_sched(&state_path);
    if st.deferred {
        // Already gave up forcing this cycle (user kept using it / squatter).
        return Ok(json!({
            "ok": true, "action": "deferred", "name": disk.name, "clock": clock,
            "reason": "in use past grace; not forcing power-off (data-safety)",
        }));
    }

    match spindown_impl(ctx, disk, true)? {
        SpinOutcome::Down(sd) => {
            if !dry {
                let _ = std::fs::remove_file(&state_path);
            }
            Ok(json!({
                "ok": true, "action": "power-off", "name": disk.name, "clock": clock,
                "spindown": sd,
            }))
        }
        SpinOutcome::Busy(steps) => {
            let grace = sched.grace_secs();
            if st.off_deadline == 0 {
                st.off_deadline = now + grace;
            }
            let remaining = st.off_deadline.saturating_sub(now);
            if now >= st.off_deadline {
                st.deferred = true;
                if !dry {
                    save_sched(&state_path, &st);
                }
                Ok(json!({
                    "ok": true, "action": "deferred", "name": disk.name, "clock": clock,
                    "grace_secs": grace, "busy_steps": steps,
                    "reason": "still in use after grace; deferring power-off (data-safety)",
                }))
            } else {
                if !dry {
                    save_sched(&state_path, &st);
                }
                Ok(json!({
                    "ok": true, "action": "grace-wait", "name": disk.name, "clock": clock,
                    "grace_secs": grace, "grace_remaining_secs": remaining, "busy_steps": steps,
                    "reason": "disk busy; waiting for transfer to finish before power-off",
                }))
            }
        }
    }
}

/// Reconcile the systemd scheduler unit for a disk: write it when a schedule is
/// configured, remove it otherwise. Mirrors `reconcile_monitor_unit`.
pub fn reconcile_schedule_unit(
    ctx: &Context,
    unit_dir: &Path,
    disk: &Disk,
    dry: bool,
) -> Result<FileChange> {
    let unit_name = format!("tpmnt-schedule-{}.service", disk.name);
    let path = unit_dir.join(&unit_name);

    if disk.schedule.is_none() {
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
        "# tpmnt:{name}\n[Unit]\nDescription=tpmnt scheduled power on/off for {name}\nAfter=local-fs.target\n\n[Service]\nType=simple\nExecStart={exe} --config {cfg} schedule {name}\nRestart=always\nRestartSec=30\n\n[Install]\nWantedBy=multi-user.target\n",
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
            .map_err(|e| Error::new(Code::EInternal, format!("write schedule unit: {e}")))?;
    }
    Ok(FileChange {
        path: path.display().to_string(),
        action,
        line: unit_name,
    })
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
    fn schedule_state_round_trips() {
        let dir = std::env::temp_dir().join(format!("tpmnt-sched-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("d.json");
        // A missing file loads as the zero default (no pending off).
        assert_eq!(load_sched(&f).off_deadline, 0);
        assert!(!load_sched(&f).deferred);
        save_sched(
            &f,
            &ScheduleState {
                off_deadline: 123,
                deferred: true,
            },
        );
        let st = load_sched(&f);
        assert_eq!(st.off_deadline, 123);
        assert!(st.deferred);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apm_tuning_targets_only_fixed_rotational_disks() {
        // Spinning internal HDD => tune (disable aggressive parking, own spindown).
        assert!(should_tune_apm(true, false));
        // Removable spinning (USB dock) => skip: power-off path, not ATA APM.
        assert!(!should_tune_apm(true, true));
        // SSD / loop (non-rotational) => skip: no platters to park.
        assert!(!should_tune_apm(false, false));
        assert!(!should_tune_apm(false, true));
    }

    #[test]
    fn auto_method_maps_traits_to_action() {
        use PowerOffMethod::*;
        // Neither removable nor rotational (e.g. an SSD/loop) => sentinel: skip.
        assert_eq!(resolve_method_traits(Auto, false, false), Auto);
        // Rotational HDD => spin the platters down.
        assert_eq!(resolve_method_traits(Auto, false, true), Standby);
        // Removable (USB) => cut power; takes precedence over rotational.
        assert_eq!(resolve_method_traits(Auto, true, true), PowerOff);
        // An explicit method is always honored verbatim.
        assert_eq!(resolve_method_traits(Standby, false, false), Standby);
        // `remove` is explicit and never trait-remapped, whatever the device is.
        assert_eq!(resolve_method_traits(Remove, false, true), Remove);
        assert_eq!(resolve_method_traits(Remove, true, true), Remove);
    }
}
