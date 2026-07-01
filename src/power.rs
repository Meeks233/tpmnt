//! Per-disk power management for the `cold-standby` profile: detect *real* block
//! I/O on the decrypted mapper, and when a disk has been idle past its window,
//! spin the platters down to *standby* (mapping kept open; transparent wake on
//! next access) to stop needless platter wear. Directly-attached SATA disks park
//! via ATA STANDBY (`hdparm -y`); USB-bridged disks (whose bridge silently
//! ignores ATA standby) via a SCSI STOP UNIT (`sg_start --stop`). The disk then
//! rests at standby —
//! tpmnt never auto-powers-off, because standby already captures ~all the
//! HDD-lifespan benefit a full power-off would (a wake costs the same start/stop
//! cycle either way) without the physical-reload cost. Full power-off / OS
//! removal is a manual, explicit action (`tpmnt power … --method`). `always-on`
//! disks are never touched.
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
use crate::exec::Runner;
use crate::reconcile::{unit_name_for, FileChange};

use crate::cmd::Context;

/// Persisted idle-monitor state for one disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MonitorState {
    /// Last observed read+write completion counter from the mapper.
    counter: u64,
    /// Epoch seconds when `counter` last changed (i.e. last real access).
    last_change: u64,
    /// True once the platters have been parked at standby (mapping still open).
    /// Cleared on the next real access. Prevents re-issuing `hdparm -y` every tick
    /// while the disk rests at standby.
    #[serde(default)]
    standby: bool,
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

/// Whether the disk sits behind a USB transport (e.g. a USB-SATA bridge like the
/// JMicron JMS567). Read on the disk's host by resolving `/sys/block/<dev>/device`
/// to its full sysfs path and looking for a `usb` component. This matters because
/// USB bridges translate SCSI<->ATA and, crucially, *silently drop* ATA STANDBY
/// IMMEDIATE (`hdparm -y`) — they ACK it and even report `standby` for `hdparm -C`
/// while the motor keeps spinning. Such disks must be parked with a SCSI STOP
/// UNIT instead. Reports `removable=0`, so it is not caught by `is_removable`.
fn is_usb_attached(ctx: &Context, prefix: &[String], phys: &str) -> bool {
    let base = phys.rsplit('/').next().unwrap_or(phys);
    let link = format!("/sys/block/{base}/device");
    let full = if prefix.is_empty() {
        std::fs::canonicalize(&link)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        ctx.runner
            .probe_on(
                prefix,
                &["readlink", "-f", &link],
                "resolve device transport",
            )
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_default()
    };
    full.split('/').any(|c| c == "usb" || c.starts_with("usb"))
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

/// The spin-down command for a disk, honoring its transport. A USB-SATA bridge
/// silently drops ATA STANDBY IMMEDIATE (`hdparm -y`) — it ACKs the command and
/// even reports `standby` for `hdparm -C`, yet never stops the motor — so a
/// USB-attached disk is parked with a SCSI STOP UNIT (`sg_start --stop`), which
/// the bridge honors and which keeps the device present so the next I/O
/// transparently spins it back up. A directly-attached SATA disk uses `hdparm -y`.
/// Returns (argv, why, method-label, tool). `sg_start` ships in sg3_utils — a
/// USB cold-standby disk needs it on its host; without it the park is a no-op the
/// caller records honestly rather than silently claiming success.
fn spindown_argv(usb: bool, phys: &str) -> (Vec<&str>, &'static str, &'static str, &'static str) {
    if usb {
        (
            vec!["sg_start", "--stop", phys],
            "spin down USB-bridged disk (SCSI STOP UNIT; ATA standby is ignored by the bridge)",
            "sg_start --stop",
            "sg_start",
        )
    } else {
        (
            vec!["hdparm", "-y", phys],
            "spin platters down to standby (mapping kept open; wakes on next access)",
            "hdparm -y",
            "hdparm",
        )
    }
}

/// Stage 1 of cold-standby idle handling: spin the platters down to standby but
/// leave the LUKS mapping + mount in place, so the next real access transparently
/// wakes the drive. Directly-attached SATA disks use `hdparm -y` (ATA STANDBY
/// IMMEDIATE); USB-bridged disks use `sg_start --stop` (SCSI STOP UNIT) because
/// the bridge silently ignores ATA standby. Only for fixed rotational disks —
/// SSD/loop have no platters. Best-effort: an unsupported drive/bridge (or a
/// missing tool) fails harmlessly (recorded, never fatal). Acts on the disk's host.
fn enter_standby(ctx: &Context, disk: &Disk) -> Value {
    let (phys, prefix) = phys_and_prefix(ctx, disk);
    let dry = ctx.global.effective_dry_run();
    // Same predicate as APM tuning: only fixed rotational disks have platters to
    // park; SSD/loop disks have nothing to spin down.
    if !dry
        && !should_tune_apm(
            is_rotational(ctx, &prefix, &phys),
            is_removable(ctx, &prefix, &phys),
        )
    {
        return json!({"step": "standby", "device": phys, "skipped": "not a fixed rotational disk"});
    }
    let usb = !dry && is_usb_attached(ctx, &prefix, &phys);
    let (argv, why, method, tool) = spindown_argv(usb, &phys);
    match ctx.runner.run_on(&prefix, &priv_argv(&prefix, &argv), why) {
        Ok(out) if out.ok() => json!({"step": "standby", "device": phys, "method": method}),
        Ok(out) => {
            json!({"step": "standby", "device": phys, "skipped": "standby unsupported", "method": method, "stderr": out.stderr.trim()})
        }
        Err(e) => {
            json!({"step": "standby", "device": phys, "skipped": format!("{tool} unavailable"), "error": e.message})
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

/// What a detach power-off recorded so spin-up can bring the disk back: the SCSI
/// host to rescan and (for a remote disk) how to rebuild the ciphertext forward.
/// Persisted only while the disk is detached from its host OS.
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
    /// True when the disk was truly powered off (`udisksctl power-off`) rather than
    /// just dropped (`device/delete`). A real power-off can take the whole SCSI
    /// host/enclosure off the bus, so spin-up must fall back from a host rescan to
    /// a PCI rescan, and an enclosure that stays dark needs a physical reconnect.
    #[serde(default)]
    powered_off: bool,
}

/// Whether a filesystem path exists on the disk's host (local, or remote via a
/// bounded `test -e` over SSH). Used to probe sysfs before/after a rescan.
fn host_exists(ctx: &Context, prefix: &[String], path: &str) -> bool {
    if prefix.is_empty() {
        Path::new(path).exists()
    } else {
        ctx.runner
            .probe_on(prefix, &["test", "-e", path], "check host path exists")
            .map(|o| o.ok())
            .unwrap_or(false)
    }
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

/// How the backing device is made to "disappear" from its host OS in the
/// forward-aware detach path. Both are reversed identically on spin-up (SCSI host
/// rescan), differing only in whether the drive's power is actually cut.
#[derive(Clone, Copy, PartialEq)]
enum Disappear {
    /// `echo 1 > /sys/block/<dev>/device/delete`: drop the device from the OS.
    /// Spins the platters down (STOP UNIT) but does NOT cut bus/enclosure power —
    /// a USB/dock's LED stays lit.
    Delete,
    /// `udisksctl power-off -b <dev>`: truly power the drive down (and, for
    /// USB/dock enclosures, drop bus power so the LED goes out). Reversible via
    /// the same SCSI rescan.
    PowerOff,
}

impl Disappear {
    fn label(self) -> &'static str {
        match self {
            Disappear::Delete => "remove",
            Disappear::PowerOff => "power-off",
        }
    }
}

/// The forward-aware detach tail shared by the `remove` and (remote) `power-off`
/// methods: after the mapping is torn down, make the backing block device
/// disappear from its host OS — either dropped (`Delete`) or truly powered off
/// (`PowerOff`) — recording how to bring it back. For a remote disk the
/// ciphertext forward is discovered and torn down first, since the device can't
/// be deleted/powered-off while `qemu-nbd` holds it open.
fn detach_from_os(ctx: &Context, disk: &Disk, action: Disappear) -> Result<Value> {
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
        .with_hint("the disk must sit on a rescannable SCSI/USB host to detach + recover it")
    })?;

    // For a remote disk, discover + tear the forward down so the detach succeeds.
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
        powered_off: action == Disappear::PowerOff,
    };
    let sp = ctx.paths.forward_state(&disk.name);
    if let Some(parent) = sp.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&sp, serde_json::to_string(&state).unwrap_or_default());

    // Make the device disappear from its host OS.
    match action {
        Disappear::Delete => {
            // Drop the device (spins it down via STOP UNIT, but keeps bus power).
            sysfs_write(
                ctx,
                &prefix,
                &format!("/sys/block/{base}/device/delete"),
                "1",
                "remove backing disk from host OS (device/delete)",
            )?;
        }
        Disappear::PowerOff => {
            // Truly power the drive/enclosure down (LED off), via udisks.
            ctx.runner
                .run_on(
                    &prefix,
                    &priv_argv(&prefix, &["udisksctl", "power-off", "-b", &phys]),
                    "power off backing disk (udisksctl power-off)",
                )?
                .require("udisksctl power-off")
                .map_err(power_err)?;
        }
    }

    Ok(json!({
        "step": "power-down",
        "device": phys,
        "method_used": action.label(),
        "scsi_host": scsi_host,
        "detached_from_os": true,
    }))
}

/// Whether a recorded removal (`forward/<name>.json`) no longer reflects reality
/// and must be discarded rather than driving a rescan. Stale when the disk's
/// remote/local binding changed since it was written (a remote→local migration
/// leaves the record behind), or when a local disk's backing device is already
/// present again — either way there is nothing to bring back.
fn removal_record_is_stale(
    state: &ForwardState,
    is_remote_now: bool,
    backing_present: bool,
) -> bool {
    state.remote != is_remote_now || (!is_remote_now && backing_present)
}

/// Reverse `detach_from_os`: rescan the SCSI host to re-probe the disk, wait for
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

    // Guard against a stale removal record. The disk's binding may have changed
    // since it was written (e.g. migrated remote→local, leaving the old record
    // behind), or a local disk may simply be back on the bus already. Either way
    // there is nothing to restore, and chasing the recorded rescan target would
    // hang then fail (waiting for a device that never reappears under that name).
    // Discard the record and let the normal open path proceed.
    let is_remote_now = !prefix.is_empty();
    let backing_present = !is_remote_now && Path::new(&disk.device_path()).exists();
    if removal_record_is_stale(&state, is_remote_now, backing_present) {
        let _ = std::fs::remove_file(&sp);
        return Ok(None);
    }

    // 1. Re-probe the disk. `device/delete` leaves the SCSI host in place, so a
    //    host rescan brings it back. A true `udisksctl power-off` can take the
    //    whole host/enclosure off the bus (that's what darkens the LED), so its
    //    host is gone — fall back to a PCI rescan to re-enumerate the controller.
    let host_path = format!("/sys/class/scsi_host/{}", state.scsi_host);
    if host_exists(ctx, &prefix, &host_path) {
        sysfs_write(
            ctx,
            &prefix,
            &format!("{host_path}/scan"),
            "\"- - -\"",
            "rescan SCSI host to bring the disk back",
        )?;
    } else {
        // Host vanished with the powered-off enclosure: re-enumerate the PCI bus.
        sysfs_write(
            ctx,
            &prefix,
            "/sys/bus/pci/rescan",
            "1",
            "rescan PCI bus to re-enumerate a powered-off enclosure",
        )?;
    }

    // 2. Wait for the backing device to reappear (bounded).
    let check = format!(
        "/sys/block/{}",
        state.remote_dev.rsplit('/').next().unwrap_or("")
    );
    let mut back = false;
    for _ in 0..30 {
        if host_exists(ctx, &prefix, &check) {
            back = true;
            break;
        }
        sleep(Duration::from_millis(500));
    }
    if !back {
        let hint = if state.powered_off {
            "the enclosure was fully powered off and did not return on a bus rescan; physically reconnect or re-power it, then run `tpmnt power <name> --on`"
        } else {
            "the host may not support software rescan; a physical reconnect may be required"
        };
        return Err(Error::new(
            Code::EPowerOff,
            format!("disk {} did not reappear after a rescan", state.remote_dev),
        )
        .with_hint(hint));
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
pub fn spindown(
    ctx: &Context,
    disk: &Disk,
    method_override: Option<PowerOffMethod>,
) -> Result<Value> {
    match spindown_impl(ctx, disk, false, method_override)? {
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
fn spindown_impl(
    ctx: &Context,
    disk: &Disk,
    soft: bool,
    method_override: Option<PowerOffMethod>,
) -> Result<SpinOutcome> {
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
    //    A one-shot --method wins over the disk's configured power_off_method.
    let (phys, prefix) = phys_and_prefix(ctx, disk);
    let base_method = method_override.unwrap_or(disk.power_off_method);
    let resolved = resolve_method(ctx, &prefix, base_method, &phys);

    // The forward-aware detach path (device disappears from its host OS, then is
    // rescanned back on spin-up). `remove` drops the device; `power-off` on a
    // REMOTE disk must go here too — the ciphertext forward holds the device open,
    // so it has to be torn down (and rebuilt on spin-up) around the power-off.
    // These own their spin-down + forward teardown, replacing the match below.
    let detach = match resolved {
        PowerOffMethod::Remove => Some(Disappear::Delete),
        PowerOffMethod::PowerOff if !prefix.is_empty() => Some(Disappear::PowerOff),
        _ => None,
    };
    if let Some(action) = detach {
        let method_used = action.label();
        if dry {
            steps.push(json!({"step": "power-down", "device": phys, "method_used": method_used, "planned": "detach device from host OS + record rescan"}));
        } else {
            steps.push(detach_from_os(ctx, disk, action)?);
            let _ = std::fs::remove_file(ctx.paths.monitor_state(&disk.name));
        }
        return Ok(SpinOutcome::Down(json!({
            "ok": true, "action": "power-off", "name": disk.name,
            "method_used": method_used, "skip_reason": null,
            "warning": wake_warning(method_used),
            "dry_run": dry, "steps": steps,
        })));
    }

    let (method_used, skip_reason) = match resolved {
        // Local removable disk: udisks powers it off directly (no forward to tear
        // down; it re-appears on physical replug / udev). Remote power-off is
        // routed through the detach path above.
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
        "warning": wake_warning(method_used),
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
/// Scan the attached NBD devices for the one whose LUKS header UUID is `uuid` —
/// i.e. the `/dev/nbdN` currently forwarding this disk's ciphertext here. `None`
/// when no live forward carries it (not attached, or attached elsewhere). Used
/// both to open a forwarded disk and to decide whether `connect` must (re)build
/// the forward.
pub fn forwarded_local_device(ctx: &Context, uuid: &str) -> Option<String> {
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
            if out.ok() && out.stdout.trim() == uuid {
                return Some(dev);
            }
        }
    }
    None
}

/// Whether an active dm-crypt mapping still has a working backing device.
/// `cryptsetup status` reports a mapping whose underlying device has vanished with
/// `device: (null)`; such a mapping stays "active" but every read fails. Returns
/// true when the mapping looks healthy — or can't be inspected — so a probe hiccup
/// never tears down a good mapping.
fn mapping_is_live(ctx: &Context, mapper: &str) -> bool {
    match ctx.runner.probe(
        &["cryptsetup", "status", mapper],
        "check LUKS mapping backing device",
    ) {
        Ok(out) if out.ok() => !mapping_backing_is_dead(&out.stdout),
        _ => true,
    }
}

/// Parse `cryptsetup status` output: true when the `device:` line reads `(null)`
/// or is empty, i.e. the mapping's backing device is gone (a dead mapping). No
/// `device:` line at all is treated as live (don't destroy what we can't judge).
fn mapping_backing_is_dead(status: &str) -> bool {
    for line in status.lines() {
        if let Some(rest) = line.trim().strip_prefix("device:") {
            let dev = rest.trim();
            return dev.is_empty() || dev == "(null)";
        }
    }
    false
}

fn local_container(ctx: &Context, disk: &Disk) -> Result<String> {
    if ctx.config.ssh_prefix_for(disk).is_empty() {
        return Ok(disk.device_path());
    }
    if let Some(dev) = forwarded_local_device(ctx, &disk.uuid) {
        return Ok(dev);
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
            // A mapper node can exist yet be dead: if its backing device was
            // removed, or the disk re-enumerated to a new /dev node, the dm-crypt
            // target points at a vanished device and every read fails ("can't read
            // superblock"). Detect that and close it so we re-open against the live
            // container instead of mounting a corpse.
            let mut already_open = Path::new(&mapper_dev).exists() && !dry;
            if already_open && !mapping_is_live(ctx, &mapper) {
                ctx.runner
                    .run(
                        &["cryptsetup", "close", &mapper],
                        "close stale LUKS mapping (backing device gone)",
                    )?
                    .require("cryptsetup close")?;
                steps.push(
                    json!({"step": "cryptsetup-close", "mapper": mapper, "reason": "stale-backing"}),
                );
                already_open = false;
            }
            if already_open {
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

/// A caveat surfaced on the spin-down result when the chosen method leaves the
/// disk in a state that `tpmnt power <name> --on` cannot revive by itself —
/// `power-off` cuts enclosure power (LED off) and `sleep` needs a bus reset, so
/// both require a physical reconnect/power-cycle before the disk can wake. The
/// default `standby`/`auto` methods keep the disk softwake-able and warn nothing.
fn wake_warning(method_used: &str) -> Option<&'static str> {
    match method_used {
        "power-off" => Some(
            "fully powered off: the enclosure left the bus (LED off) — waking needs a physical reconnect/power-cycle; `tpmnt power <name> --on` alone cannot revive it",
        ),
        "sleep" => Some(
            "put to SLEEP (hdparm -Y): needs a bus reset / physical reconnect to wake",
        ),
        _ => None,
    }
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

/// What a monitor tick should do, decided purely from the idle timing so the
/// state machine can be unit-tested without a live mapper/sysfs.
///
/// Cold-standby rests an idle disk at *standby* and stops there — it never
/// auto-powers-off. Standby already captures ~all the HDD-lifespan benefit a full
/// power-off would (a wake costs the same one start/stop cycle either way), while
/// a real power-off risks needing a physical reload to wake. So there is no
/// power-off stage here; full power-off is a manual, explicit action.
#[derive(Debug, PartialEq, Eq)]
enum IdleAction {
    /// Real access (or first observation): keep the disk up, reset the idle clock.
    Active,
    /// Idle but still inside the standby window: leave it alone.
    Wait,
    /// Crossed the standby window and not yet parked: spin the platters down now
    /// (mapping stays open for a transparent wake).
    EnterStandby,
    /// Already parked and idle: keep resting at standby (the terminal state).
    HoldStandby,
}

/// Single-stage cold-standby idle decision. Precedence is **activity > standby**,
/// so real I/O always resets the clock; once parked the disk simply rests.
fn decide_idle(
    activity: bool,
    idle_secs: u64,
    standby_to: u64,
    already_standby: bool,
) -> IdleAction {
    if activity {
        return IdleAction::Active;
    }
    if idle_secs >= standby_to {
        return if already_standby {
            IdleAction::HoldStandby
        } else {
            IdleAction::EnterStandby
        };
    }
    IdleAction::Wait
}

/// Handle a tick where the LUKS mapper is closed. A closed mapper is *not*
/// evidence the platters are parked: with `x-systemd.automount` teardown (or
/// before the mount is ever triggered) the dm-crypt mapping is absent while the
/// raw backing disk keeps spinning. So park the physical disk to standby, unless
/// it has been genuinely detached / powered off (device node gone) — that we
/// leave alone, both because there is nothing to park and because probing it
/// could bring it back on the bus. Idempotent: the persisted `standby` flag gates
/// re-issuing `hdparm -y`; a real access reopens the mapper and the open path
/// clears the flag, so the next close re-parks.
fn park_closed_disk(ctx: &Context, disk: &Disk) -> Result<Value> {
    let (phys, prefix) = phys_and_prefix(ctx, disk);

    // Truly detached / powered off: nothing to park, and don't wake it.
    if !host_exists(ctx, &prefix, &phys) {
        return Ok(json!({
            "ok": true, "action": "down", "name": disk.name,
            "reason": "mapper closed and backing device absent; disk already down",
        }));
    }

    // Only fixed rotational disks have platters to park (SSD/loop: nothing to do;
    // removable: parking isn't its power-down path).
    if !should_tune_apm(
        is_rotational(ctx, &prefix, &phys),
        is_removable(ctx, &prefix, &phys),
    ) {
        return Ok(json!({
            "ok": true, "action": "down", "name": disk.name,
            "reason": "mapper closed; backing disk has no platters to park",
        }));
    }

    // Park once per closed stretch: the persisted `standby` flag guards against
    // re-sending `hdparm -y` every tick.
    let state_path = ctx.paths.monitor_state(&disk.name);
    if load_state(&state_path).map(|s| s.standby).unwrap_or(false) {
        return Ok(json!({
            "ok": true, "action": "keep", "name": disk.name,
            "reason": "mapper closed; already resting at standby",
        }));
    }

    let standby = enter_standby(ctx, disk);
    if !ctx.global.effective_dry_run() {
        save_state(
            &state_path,
            &MonitorState {
                counter: 0,
                last_change: now_epoch(),
                standby: true,
            },
        );
    }
    Ok(json!({
        "ok": true, "action": "standby", "name": disk.name,
        "reason": "mapper closed; parked idle backing disk",
        "standby": standby,
    }))
}

/// One monitor tick: observe real I/O, update idle state, and spin the platters
/// down to standby if the disk has been idle past its window (then rest there).
/// Idempotent and safe to call on a repeat.
pub fn monitor_tick(ctx: &Context, disk: &Disk) -> Result<Value> {
    if !disk.is_cold_standby() {
        return Ok(json!({
            "ok": true, "action": "skip", "name": disk.name,
            "reason": "power_profile=always-on",
        }));
    }

    // A closed mapper does NOT mean the platters are parked. With
    // `x-systemd.automount` teardown — or simply before the mount is ever
    // triggered — the dm-crypt mapping is absent while the raw backing disk keeps
    // spinning (closing/never-opening a dm-crypt target issues no ATA STANDBY). So
    // when the mapper is down we still park the physical disk instead of assuming
    // it is already powered down.
    let mapper = disk.mapper_name();
    if !Path::new(&format!("/dev/mapper/{mapper}")).exists() {
        return park_closed_disk(ctx, disk);
    }

    let standby_to = disk.standby_timeout_secs(&ctx.config.defaults);
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
    let already = prev.as_ref().map(|s| s.standby).unwrap_or(false);
    let dry = ctx.global.effective_dry_run();

    match decide_idle(activity, idle_secs, standby_to, already) {
        IdleAction::Active => {
            if !dry {
                // Real access wakes any parked platters: clear the standby flag.
                save_state(
                    &state_path,
                    &MonitorState {
                        counter,
                        last_change: now,
                        standby: false,
                    },
                );
            }
            // First time we see this disk open this session: claim sole spindown
            // authority + disable aggressive firmware APM head-parking.
            let tune = first_obs.then(|| tune_spindown_authority(ctx, disk));
            Ok(json!({
                "ok": true, "action": "keep", "name": disk.name,
                "io_counter": counter, "idle_secs": 0,
                "standby_timeout_secs": standby_to,
                "reason": "real access detected", "tune": tune,
            }))
        }

        // Idle past the standby window -> park the platters, keep the mapping open
        // (transparent wake on next access). Issued once per idle stretch. This is
        // the terminal resting state: tpmnt never auto-escalates to a power-off.
        IdleAction::EnterStandby => {
            let standby = enter_standby(ctx, disk);
            if !dry {
                // Preserve counter/last_change; just mark the platters parked. prev
                // is Some whenever activity is false, so this always persists.
                if let Some(mut s) = prev {
                    s.standby = true;
                    save_state(&state_path, &s);
                }
            }
            Ok(json!({
                "ok": true, "action": "standby", "name": disk.name,
                "io_counter": counter, "idle_secs": idle_secs,
                "standby_timeout_secs": standby_to,
                "standby": standby,
            }))
        }

        IdleAction::HoldStandby => Ok(json!({
            "ok": true, "action": "keep", "name": disk.name,
            "io_counter": counter, "idle_secs": idle_secs,
            "standby_timeout_secs": standby_to,
            "reason": "resting at standby (no auto power-off)",
        })),

        IdleAction::Wait => Ok(json!({
            "ok": true, "action": "keep", "name": disk.name,
            "io_counter": counter, "idle_secs": idle_secs,
            "standby_timeout_secs": standby_to,
            "reason": "idle but within standby window",
        })),
    }
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

    match spindown_impl(ctx, disk, true, None)? {
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

/// Enable and (re)start a generated unit so it actually RUNS — writing the
/// `.service` file alone leaves the daemon inert (the disk keeps spinning because
/// nothing ever checks for idle). `restart` starts a stopped unit and reloads a
/// changed file, covering both first-create and update. Traced+skipped under
/// dry-run like any other mutation.
fn enable_unit_now(runner: &Runner, unit: &str) -> Result<()> {
    runner
        .run(&["systemctl", "daemon-reload"], "reload systemd unit files")?
        .require("systemctl daemon-reload")?;
    runner
        .run(&["systemctl", "enable", unit], "enable unit at boot")?
        .require("systemctl enable")?;
    runner
        .run(&["systemctl", "restart", unit], "start/refresh unit now")?
        .require("systemctl restart")?;
    Ok(())
}

/// Stop + disable a unit before its file is removed. Best-effort: a unit that was
/// never loaded must not fail the reconcile.
fn disable_unit_now(runner: &Runner, unit: &str) {
    let _ = runner.run(
        &["systemctl", "disable", "--now", unit],
        "stop + disable unit",
    );
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
                disable_unit_now(&ctx.runner, &unit_name);
                let _ = std::fs::remove_file(&path);
                let _ = ctx
                    .runner
                    .run(&["systemctl", "daemon-reload"], "reload systemd unit files");
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
        enable_unit_now(&ctx.runner, &unit_name)?;
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
        // Ensure removed (idempotent): stop+disable the running daemon first.
        let action = if path.exists() {
            if !dry {
                disable_unit_now(&ctx.runner, &unit_name);
                let _ = std::fs::remove_file(&path);
                let _ = ctx
                    .runner
                    .run(&["systemctl", "daemon-reload"], "reload systemd unit files");
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
        enable_unit_now(&ctx.runner, &unit_name)?;
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
    fn enabling_a_unit_reloads_enables_and_starts_it() {
        // Writing the .service file is not enough — the daemon must be enabled and
        // started or the disk never spins down. Assert all three commands are issued.
        let r = Runner::new(true, false);
        enable_unit_now(&r, "tpmnt-monitor-arc.service").unwrap();
        let cmds: Vec<Vec<String>> = r.trace.borrow().iter().map(|s| s.argv.clone()).collect();
        assert_eq!(cmds[0], vec!["systemctl", "daemon-reload"]);
        assert_eq!(
            cmds[1],
            vec!["systemctl", "enable", "tpmnt-monitor-arc.service"]
        );
        assert_eq!(
            cmds[2],
            vec!["systemctl", "restart", "tpmnt-monitor-arc.service"]
        );
    }

    #[test]
    fn dead_mapping_detected_from_null_backing_device() {
        // Healthy mapping: a real backing device.
        let live = "/dev/mapper/tpmnt-x is active.\n  type:    LUKS2\n  \
                    cipher:  aes-xts-plain64\n  device:  /dev/sdc\n  sector size:  4096\n";
        assert!(!mapping_backing_is_dead(live));

        // Stale mapping after the backing device vanished / the disk re-enumerated:
        // still "active", but `device:` is (null) — reads fail.
        let dead = "/dev/mapper/tpmnt-x is active.\n  type:    n/a\n  \
                    key location: keyring\n  device:  (null)\n  sector size:  4096\n";
        assert!(mapping_backing_is_dead(dead));

        // No `device:` line at all -> treated as live (don't tear down blindly).
        assert!(!mapping_backing_is_dead("/dev/mapper/tpmnt-x is active.\n"));
    }

    fn removal_state(remote: bool) -> ForwardState {
        ForwardState {
            remote,
            remote_dev: "/dev/sdb".into(),
            scsi_host: "host7".into(),
            port: 10809,
            powered_off: true,
        }
    }

    #[test]
    fn removal_record_stale_when_binding_migrated_remote_to_local() {
        let state = removal_state(true);
        // Record says remote, but the disk is local now (migrated) -> discard it.
        assert!(removal_record_is_stale(&state, false, false));
        // Record says remote and the disk is still remote -> honor it (rescan).
        assert!(!removal_record_is_stale(&state, true, false));
    }

    #[test]
    fn removal_record_stale_when_local_disk_already_present() {
        let state = removal_state(false);
        // Local disk already back on the bus -> nothing to restore.
        assert!(removal_record_is_stale(&state, false, true));
        // Local disk still genuinely absent -> honor the record and rescan.
        assert!(!removal_record_is_stale(&state, false, false));
    }

    #[test]
    fn physical_device_strips_only_real_partitions() {
        // Without sysfs we can't classify, so a whole-device path round-trips.
        assert_eq!(physical_device_for("/dev/loop0"), "/dev/loop0");
    }

    // --- Single-stage cold-standby idle state machine (rest at standby, no ----
    // --- auto power-off; full power-off is a manual, explicit action) ----------

    const STANDBY: u64 = 300; // 5 min

    #[test]
    fn idle_walkthrough_rests_at_standby() {
        use IdleAction::*;
        // Real access always resets, whatever the idle number says.
        assert_eq!(decide_idle(true, 99_999, STANDBY, false), Active);
        assert_eq!(decide_idle(true, 0, STANDBY, true), Active);

        // Idle but inside the standby window (0 <= idle < 5min): leave it alone.
        assert_eq!(decide_idle(false, 0, STANDBY, false), Wait);
        assert_eq!(decide_idle(false, 299, STANDBY, false), Wait);

        // Exactly at the standby threshold, not yet parked: park now.
        assert_eq!(decide_idle(false, 300, STANDBY, false), EnterStandby);
        assert_eq!(decide_idle(false, 900, STANDBY, false), EnterStandby);

        // Already parked: rest at standby indefinitely — never escalates further,
        // no matter how long it stays idle.
        assert_eq!(decide_idle(false, 300, STANDBY, true), HoldStandby);
        assert_eq!(decide_idle(false, 1_800, STANDBY, true), HoldStandby);
        assert_eq!(decide_idle(false, 999_999, STANDBY, true), HoldStandby);
    }

    #[test]
    fn no_action_ever_powers_off() {
        use IdleAction::*;
        // Exhaustively: whatever the timing, the monitor only ever keeps or parks —
        // it must never auto-power-off (that would need a physical reload to wake).
        for &act in &[true, false] {
            for &idle in &[0u64, 1, 300, 1_800, 86_400, u64::MAX] {
                for &parked in &[true, false] {
                    let a = decide_idle(act, idle, STANDBY, parked);
                    assert!(
                        matches!(a, Active | Wait | EnterStandby | HoldStandby),
                        "act={act} idle={idle} parked={parked} -> {a:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn full_lifecycle_transitions_in_order() {
        use IdleAction::*;
        // The sequence the monitor walks a disk through: wait -> park -> rest.
        let s = 60u64;
        let seq = [
            (false, 0, false, Wait),
            (false, 59, false, Wait),
            (false, 61, false, EnterStandby),
            (false, 74, true, HoldStandby),
            (false, 100_000, true, HoldStandby), // still just resting, never off
            (true, 0, true, Active),             // access wakes + resets
        ];
        for (act, idle, parked, want) in seq {
            assert_eq!(
                decide_idle(act, idle, s, parked),
                want,
                "idle={idle} parked={parked}"
            );
        }
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
    fn spindown_picks_scsi_stop_for_usb_disks() {
        // USB-bridged disk: ATA standby is silently dropped by the bridge, so use
        // a SCSI STOP UNIT (sg_start --stop) that the bridge actually honors.
        let (argv, _why, method, tool) = spindown_argv(true, "/dev/sda");
        assert_eq!(argv, vec!["sg_start", "--stop", "/dev/sda"]);
        assert_eq!(method, "sg_start --stop");
        assert_eq!(tool, "sg_start");
        // Directly-attached SATA disk: ATA STANDBY IMMEDIATE works.
        let (argv, _why, method, tool) = spindown_argv(false, "/dev/sdb");
        assert_eq!(argv, vec!["hdparm", "-y", "/dev/sdb"]);
        assert_eq!(method, "hdparm -y");
        assert_eq!(tool, "hdparm");
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
