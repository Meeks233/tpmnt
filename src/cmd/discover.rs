//! `tpmnt discover [name…]` — reconcile each disk's *location*. Finds where every
//! configured disk physically lives now (by LUKS UUID) and rebinds the config so
//! it stays reachable and locally-decrypted regardless of a move between this host
//! and any remote. Idempotent: a disk that hasn't moved is a no-op.
//!
//! This runs automatically at the start of `apply`, so ordinary use never has to
//! think about it — the whole point is that the user doesn't know or care where a
//! disk sits. It's exposed as a standalone command for visibility and for forcing
//! a re-scan on demand.

use serde_json::{json, Value};

use crate::cli::DiscoverArgs;
use crate::config::Config;
use crate::discover;
use crate::error::Result;

use super::Context;

/// Locate every (or the named) disk and rebind the config to match. Returns the
/// updated config (whether or not it was persisted) and a per-disk move report.
/// The config is saved only when something moved and we're not in dry-run.
///
/// Shared with `apply`, which calls this first so a moved disk is transparently
/// re-pointed before crypttab/fstab/units are reconciled.
pub fn relocate(ctx: &Context, names: Option<&[String]>) -> Result<(Config, Vec<Value>)> {
    relocate_inner(ctx, names, false)
}

/// Like `relocate`, but *forces* the single global remote sweep even when no disk
/// looks locally-missing. `connect` uses this on retry: a disk pinned to a remote
/// that just failed to answer at its last-known endpoint needs the sweep to find
/// where it actually moved (the "missing → ask everyone once" path).
pub fn relocate_sweep(ctx: &Context, names: Option<&[String]>) -> Result<(Config, Vec<Value>)> {
    relocate_inner(ctx, names, true)
}

/// Locate + rebind using the batched inventory. One `blkid` inventories this host;
/// the network is touched only when it must be — either a disk we expected here
/// has vanished, or `force_sweep` is set — and then as a *single* sweep (one probe
/// per remote), never per-disk-per-remote. When no sweep runs, disks pinned to a
/// remote keep their last-known binding untouched ("don't monitor all remotes").
fn relocate_inner(
    ctx: &Context,
    names: Option<&[String]>,
    force_sweep: bool,
) -> Result<(Config, Vec<Value>)> {
    let dry = ctx.global.effective_dry_run();
    // Only enabled remotes are ever probed — a disabled remote is skipped so the
    // discovery sweep never reaches out to it (part of avoiding reconnect storms).
    let remotes: Vec<crate::config::Remote> = ctx
        .config
        .remotes
        .iter()
        .filter(|r| r.enabled)
        .cloned()
        .collect();
    let mut cfg = ctx.config.clone();

    // A disabled disk is dormant: never relocated or probed for.
    let selected = |disk: &crate::config::Disk| -> bool {
        disk.enabled && names.is_none_or(|f| f.iter().any(|n| n == &disk.name))
    };

    // One local probe covers the common case (a disk sits where the config says).
    let local = discover::local_inventory(&ctx.runner);

    // Only a disk we expected *here* but that isn't present, and that isn't pinned
    // to a remote, justifies touching the network — that's a genuine "missing".
    let has_missing = cfg.disks.iter().any(|d| {
        selected(d)
            && !d.uuid.trim().is_empty()
            && !local.contains_key(d.uuid.trim())
            && d.remote.is_none()
    });
    let remote_inv = if force_sweep || has_missing {
        Some(discover::remote_inventory(&ctx.runner, &remotes))
    } else {
        None
    };

    let mut report = Vec::new();
    let mut dirty = false;
    for disk in cfg.disks.iter_mut() {
        if !selected(disk) {
            continue;
        }
        let from = binding_of(disk);
        let loc = discover::resolve(&local, remote_inv.as_deref(), disk);
        let moved = discover::rebind(disk, &loc);
        if moved {
            dirty = true;
        }
        report.push(json!({
            "name": disk.name,
            "found": loc.found(),
            "location": loc,
            "moved": moved,
            "from": from,
            "to": binding_of(disk),
        }));
    }

    if dirty && !dry {
        cfg.save(&ctx.global.config)?;
    }
    Ok((cfg, report))
}

/// A compact snapshot of a disk's current location binding, for the move report.
fn binding_of(disk: &crate::config::Disk) -> Value {
    json!({
        "remote": disk.remote,
        "device": disk.device_path(),
        "transport": disk.transport.map(|t| t.as_str()),
    })
}

pub fn run(ctx: &Context, args: &DiscoverArgs) -> Result<Value> {
    let names = if args.names.is_empty() {
        None
    } else {
        Some(args.names.as_slice())
    };
    let (_cfg, report) = relocate(ctx, names)?;
    let moved = report
        .iter()
        .filter(|r| r.get("moved").and_then(|v| v.as_bool()) == Some(true))
        .count();
    Ok(json!({
        "ok": true,
        "dry_run": ctx.global.effective_dry_run(),
        "moved_count": moved,
        "disks": report,
    }))
}

/// Human rendering: one line per disk, highlighting the ones that moved.
pub fn render(value: &Value) -> String {
    let mut out = String::new();
    let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
    out.push_str(if dry {
        "discover (dry-run):\n"
    } else {
        "discover:\n"
    });
    if let Some(disks) = value.get("disks").and_then(|v| v.as_array()) {
        if disks.is_empty() {
            out.push_str("  (no disks configured)\n");
        }
        for d in disks {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let found = d.get("found").and_then(|v| v.as_bool()) == Some(true);
            let moved = d.get("moved").and_then(|v| v.as_bool()) == Some(true);
            let loc = d.get("location");
            let place = match loc.and_then(|l| l.get("where")).and_then(|v| v.as_str()) {
                Some("local") => "here (local)".to_string(),
                Some("remote") => {
                    let r = loc
                        .and_then(|l| l.get("remote"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    format!("remote {r}")
                }
                _ => "not found (unplugged?)".to_string(),
            };
            let tag = if moved {
                " ← moved, rebound"
            } else if found {
                ""
            } else {
                " (binding kept)"
            };
            out.push_str(&format!("  {name}: {place}{tag}\n"));
        }
    }
    let moved = value
        .get("moved_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    out.push_str(&format!("  {moved} disk(s) rebound\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_summarizes_moved_and_stationary() {
        let v = json!({
            "dry_run": false,
            "moved_count": 1,
            "disks": [
                { "name": "arc", "found": true, "moved": true,
                  "location": { "where": "local" } },
                { "name": "far", "found": true, "moved": false,
                  "location": { "where": "remote", "remote": "nas" } },
                { "name": "gone", "found": false, "moved": false,
                  "location": { "where": "absent" } },
            ]
        });
        let out = render(&v);
        assert!(out.contains("arc: here (local) ← moved, rebound"));
        assert!(out.contains("far: remote nas"));
        assert!(out.contains("gone: not found"));
        assert!(out.contains("1 disk(s) rebound"));
    }
}
