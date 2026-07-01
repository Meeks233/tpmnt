//! `tpmnt offline <name>` — temporarily detach a disk from the host (or its
//! remote): a grace unmount, then drop the dm-crypt mapping back to
//! ciphertext-at-rest. It **never modifies the data** and leaves the disk's
//! config/crypttab/fstab intact, so it can be brought back later (reboot,
//! `tpmnt recover --open`, or the next scheduled/monitored spinup).
//!
//! A busy mount fails cleanly by default; `--force` lazily detaches it
//! (`umount -l`) so a wedged mount can still be released. Remote disks run the
//! same teardown over SSH, transparently.

use std::path::Path;

use serde_json::{json, Value};

use crate::cli::OfflineArgs;
use crate::config::Disk;
use crate::error::{Code, Error, Result};

use super::Context;

/// Whether `mountpoint` is currently a mount (local check via /proc/mounts).
fn is_mounted(mountpoint: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|s| {
            s.lines()
                .any(|l| l.split_whitespace().nth(1) == Some(mountpoint))
        })
        .unwrap_or(false)
}

pub fn run(ctx: &Context, args: &OfflineArgs) -> Result<Value> {
    let disk = find_disk(ctx, &args.name)?;
    let dry = ctx.global.effective_dry_run();
    let steps = detach(ctx, disk, args.force)?;
    Ok(json!({
        "ok": true,
        "action": "offline",
        "name": disk.name,
        "remote": disk.remote,
        "forced": args.force,
        "dry_run": dry,
        "steps": steps,
        "note": "data untouched; config kept — bring it back with `tpmnt power <name> --on` (or `tpmnt recover --open`, or a reboot)",
    }))
}

/// Look up a configured disk by name.
pub fn find_disk<'a>(ctx: &'a Context, name: &str) -> Result<&'a Disk> {
    ctx.config
        .disks
        .iter()
        .find(|d| d.name == name)
        .ok_or_else(|| {
            Error::new(Code::EConfig, format!("no disk named {name:?} in config"))
                .with_hint("run `tpmnt status` to list configured disks")
        })
}

/// Grace unmount + close the mapping for `disk`, on its host (local or remote).
/// Returns the per-step trace. A busy mount errors unless `force` (lazy detach).
/// Shared by `offline` and `destroy`.
pub fn detach(ctx: &Context, disk: &Disk, force: bool) -> Result<Vec<Value>> {
    let prefix = ctx.config.ssh_prefix_for(disk);
    let local = prefix.is_empty();
    let dry = ctx.global.effective_dry_run();
    let mapper = disk.mapper_name();
    let mapper_dev = format!("/dev/mapper/{mapper}");
    let mp = disk.mountpoint.to_string_lossy().into_owned();
    let mut steps: Vec<Value> = Vec::new();

    // 1. Grace unmount. `-l` (lazy) is the "force" for a busy mount: it detaches
    //    the tree immediately and releases the backing device as users let go.
    //    For a local disk we can see it's not mounted and skip cleanly; for a
    //    remote we attempt and tolerate a "not mounted" stderr.
    let maybe_mounted = !local || dry || is_mounted(&mp);
    if !maybe_mounted {
        steps.push(json!({"step": "umount", "target": mp, "skipped": "not mounted"}));
    } else {
        let umount_argv: Vec<&str> = if force {
            vec!["umount", "-l", &mp]
        } else {
            vec!["umount", &mp]
        };
        let out = ctx
            .runner
            .run_on(&prefix, &umount_argv, "grace unmount disk")?;
        if out.ok() {
            steps.push(json!({"step": "umount", "target": mp, "forced": force}));
        } else {
            let e = out.stderr.to_lowercase();
            if e.contains("not mounted")
                || e.contains("not currently mounted")
                || e.contains("no mount point")
            {
                steps.push(json!({"step": "umount", "target": mp, "skipped": "not mounted"}));
            } else if !force {
                return Err(Error::new(
                    Code::EMountpointBusy,
                    format!("{mp} is busy; refusing to force-unmount"),
                )
                .with_hint("pass --force to lazily detach a busy mount (umount -l)"));
            } else {
                out.require("umount -l")?;
            }
        }
    }

    // 2. Drop the dm-crypt mapping (back to ciphertext at rest). Same local/remote
    //    split: skip cleanly when we can see the mapping isn't open.
    let maybe_open = !local || dry || Path::new(&mapper_dev).exists();
    if !maybe_open {
        steps.push(json!({"step": "cryptsetup-close", "mapper": mapper, "skipped": "not open"}));
        return Ok(steps);
    }
    let out = ctx.runner.run_on(
        &prefix,
        &["cryptsetup", "close", &mapper],
        "close LUKS mapping (ciphertext at rest)",
    )?;
    if out.ok() {
        steps.push(json!({"step": "cryptsetup-close", "mapper": mapper}));
    } else {
        let e = out.stderr.to_lowercase();
        if e.contains("not active") || e.contains("unknown") || e.contains("no such") {
            steps
                .push(json!({"step": "cryptsetup-close", "mapper": mapper, "skipped": "not open"}));
        } else if force {
            // Lazy-unmounted but still held (users haven't let go). Report,
            // don't fail: the fs is detached and will close once released.
            steps.push(json!({
                "step": "cryptsetup-close", "mapper": mapper,
                "deferred": out.stderr.trim(),
                "note": "mapping still held after lazy unmount; closes once the fs is released",
            }));
        } else {
            out.require("cryptsetup close")?;
        }
    }

    Ok(steps)
}
