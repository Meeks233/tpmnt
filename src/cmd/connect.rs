//! `tpmnt connect [name…]` — pull a disk online *on demand*. This is the
//! counterpart to the "don't proactively monitor all remotes" policy: nothing
//! scans the network in the background; the user (or an AI) asks for a disk and
//! tpmnt fetches it.
//!
//! Per target disk the flow is deliberately lazy about the network:
//!   1. Try the **last-known endpoint** first — establish the ciphertext forward
//!      (for a remote disk) and open+mount locally, without probing anyone else.
//!   2. Only if that endpoint fails to answer do we fall back to discovery, and
//!      then as a **single global sweep** (`relocate_sweep`, one `blkid` per
//!      remote) that compares every host's UUIDs at once — never a per-remote
//!      storm — rebind to wherever the disk actually is, and retry.
//!   3. If it is nowhere reachable, reject.
//!
//! Decryption always happens here (TPM2 token); a remote only ever forwards raw
//! ciphertext, matching the project's threat model.

use serde_json::{json, Value};

use crate::blockdev;
use crate::cli::ConnectArgs;
use crate::config::Disk;
use crate::error::{Code, Error, Result};
use crate::power;
use crate::reconcile;

use super::Context;

pub fn run(ctx: &Context, args: &ConnectArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let base = args.local_port;
    let names_opt = if args.names.is_empty() {
        None
    } else {
        Some(args.names.as_slice())
    };
    let selected = |d: &Disk| names_opt.is_none_or(|f| f.iter().any(|n| n == &d.name));

    // Phase 1: lazy relocate (local probe; a global sweep only if a disk we
    // expected here has vanished), then try each target at its last-known spot.
    let (cfg, _report) = super::discover::relocate(ctx, names_opt)?;

    let mut connected = Vec::new();
    let mut failed = Vec::new(); // truly-absent local disks (no endpoint to retry)
    let mut retry = Vec::new(); // remote-pinned disks whose endpoint didn't answer
    let mut port = base;

    for disk in cfg.disks.iter().filter(|d| selected(d)) {
        match bring_online(ctx, disk, port) {
            Ok(v) => connected.push(v),
            Err(e) => {
                // A remote-pinned disk that failed *might* just have moved — defer
                // it to the single sweep. A local disk that's absent is a hard miss.
                if disk.remote.is_some() {
                    retry.push(disk.name.clone());
                } else {
                    failed.push(json!({"name": disk.name, "error": e.to_string()}));
                }
            }
        }
        if disk.remote.is_some() {
            port += 1;
        }
    }

    // Phase 2: the "missing" case — one global sweep to find where the deferred
    // disks actually are, rebind, and retry. Bounded to exactly one sweep.
    let mut relocated = Vec::new();
    let swept = !retry.is_empty();
    if swept {
        let (cfg2, _) = super::discover::relocate_sweep(ctx, Some(&retry))?;
        for name in &retry {
            let disk = match cfg2.disks.iter().find(|d| &d.name == name) {
                Some(d) => d,
                None => continue,
            };
            match bring_online(ctx, disk, port) {
                Ok(v) => {
                    relocated.push(name.clone());
                    connected.push(v);
                }
                Err(e) => failed
                    .push(json!({"name": name, "error": e.to_string(), "after_discovery": true})),
            }
            port += 1;
        }
    }

    let out = json!({
        "ok": failed.is_empty(),
        "action": "connect",
        "dry_run": dry,
        "swept": swept,
        "connected": connected,
        "relocated_by_discovery": relocated,
        "failed": failed,
    });

    // Reject only when nothing at all could be connected; a partial success still
    // returns Ok so the caller sees which disks came up and which didn't.
    if connected.is_empty() && !failed.is_empty() {
        return Err(Error::new(
            Code::ENoDevice,
            format!("none of the requested disk(s) could be connected ({} failed)", failed.len()),
        )
        .with_hint("the disk is not present locally nor on any known remote; check it is powered/plugged in"));
    }
    Ok(out)
}

/// Bring one disk online at its currently-bound location: ensure the ciphertext is
/// reachable here (forward a remote disk if no live forward already carries it),
/// reconcile crypttab/fstab/units so the mount is defined, then open (TPM2) +
/// mount via the shared spin-up path. Idempotent — an already-mounted disk is a
/// no-op.
fn bring_online(ctx: &Context, disk: &Disk, port: u16) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let is_remote = !ctx.config.ssh_prefix_for(disk).is_empty();

    // 1. Establish the ciphertext forward for a remote disk if one isn't already
    //    live. This is the single request to the last-known endpoint; if the
    //    remote is down it fails here and the caller defers to the sweep.
    if is_remote && !dry && power::forwarded_local_device(ctx, &disk.uuid).is_none() {
        let remote = blockdev::require_remote(ctx.config.remote_for(disk), &disk.name)?;
        blockdev::attach_nbd_over_ssh(&ctx.runner, remote, &disk.device_path(), port)?;
    }

    // 2. Make sure the mount is defined (idempotent; no-op if already applied).
    reconcile::reconcile_disk(
        &ctx.paths.crypttab(),
        &ctx.paths.fstab(),
        &ctx.paths.systemd_unit_dir(),
        disk,
        ctx.config.defaults.mount_backend,
        dry,
    )?;
    if disk.transport.is_some() {
        super::ensure_nbd_hidden(ctx, dry)?;
    }

    // 3. Open + mount (reuses the field-tested spin-up path).
    let mut result = power::spinup(ctx, disk)?;
    result["name"] = json!(disk.name);
    result["location"] = json!(if is_remote { "remote" } else { "local" });
    Ok(result)
}

/// Human rendering: one line per connected/failed disk.
pub fn render(value: &Value) -> String {
    let mut out = String::new();
    let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
    out.push_str(if dry {
        "connect (dry-run):\n"
    } else {
        "connect:\n"
    });

    if let Some(c) = value.get("connected").and_then(|v| v.as_array()) {
        for d in c {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let loc = d.get("location").and_then(|v| v.as_str()).unwrap_or("?");
            out.push_str(&format!("  ✓ {name}: connected ({loc})\n"));
        }
    }
    if let Some(reloc) = value
        .get("relocated_by_discovery")
        .and_then(|v| v.as_array())
    {
        if !reloc.is_empty() {
            let names: Vec<&str> = reloc.iter().filter_map(|v| v.as_str()).collect();
            out.push_str(&format!(
                "  (found via discovery sweep: {})\n",
                names.join(", ")
            ));
        }
    }
    if let Some(f) = value.get("failed").and_then(|v| v.as_array()) {
        for d in f {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let err = d
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unreachable");
            out.push_str(&format!("  ✗ {name}: {err}\n"));
        }
    }
    if value
        .get("connected")
        .and_then(|v| v.as_array())
        .is_none_or(|a| a.is_empty())
        && value
            .get("failed")
            .and_then(|v| v.as_array())
            .is_none_or(|a| a.is_empty())
    {
        out.push_str("  (no disks selected)\n");
    }
    out
}
