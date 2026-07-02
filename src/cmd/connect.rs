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
//!
//! `--remote <name>` is a third selection mode alongside "all disks" and "named
//! disks": it targets one remote and brings up exactly the configured disks that
//! are physically present on it *right now*. A single read-only inventory of that
//! one remote decides membership, so a disk that used to live there but has since
//! been pulled is quietly skipped rather than treated as a failure.

use serde_json::{json, Value};

use crate::blockdev;
use crate::cli::ConnectArgs;
use crate::config::Disk;
use crate::discover::Location;
use crate::error::{Code, Error, Result};
use crate::power;
use crate::reconcile;
use crate::remote_state::GIVEUP_DISABLE_THRESHOLD;

use super::Context;

/// How many times a single reconnect retries `bring_online` before giving up.
/// A storm-avoidance cap: after this it stops (and the give-up is counted toward
/// auto-disabling a persistently-failing disk/remote).
const RECONNECT_RETRIES: u32 = 3;

/// Is this remote-bearing disk's remote enabled? Local disks are always "enabled"
/// at the remote layer.
fn remote_enabled(ctx: &Context, disk: &Disk) -> bool {
    match &disk.remote {
        Some(r) => ctx
            .config
            .remotes
            .iter()
            .find(|x| &x.name == r)
            .map(|x| x.enabled)
            .unwrap_or(true),
        None => true,
    }
}

/// A disk is actionable by `up` only when it is enabled and its remote (if any) is
/// enabled — the persistent disable states are honored here.
fn actionable(ctx: &Context, disk: &Disk) -> bool {
    disk.enabled && remote_enabled(ctx, disk)
}

/// One reconnect: retry `bring_online` up to `RECONNECT_RETRIES` times, returning
/// the first success or the last error. The bounded retry is the "single reconnect
/// tries N times then stops" rule that prevents a per-disk storm.
fn reconnect(ctx: &Context, disk: &Disk, port: u16) -> Result<Value> {
    let mut last: Option<Error> = None;
    for _ in 0..RECONNECT_RETRIES {
        match bring_online(ctx, disk, port) {
            Ok(v) => return Ok(v),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| Error::new(Code::ENoDevice, "reconnect failed".to_string())))
}

/// Record that a disk's reconnect gave up; when the consecutive count reaches the
/// threshold, auto-disable the disk (flip `enabled=false` + tear it down) so it
/// stops being retried into a storm. Returns an auto-disable marker for the JSON.
fn note_disk_failure(ctx: &Context, disk: &Disk, dry: bool) -> Value {
    if dry {
        return json!({ "auto_disabled": false, "dry_run": true });
    }
    let n = crate::remote_state::note_disk_giveup(&ctx.paths, &disk.name);
    if n >= GIVEUP_DISABLE_THRESHOLD {
        let _ = super::toggle::set_enabled(ctx, std::slice::from_ref(&disk.name), false, dry);
        let _ = super::toggle::deactivate(ctx, disk, true, dry);
        json!({ "auto_disabled": true, "giveups": n })
    } else {
        json!({ "auto_disabled": false, "giveups": n })
    }
}

pub fn run(ctx: &Context, args: &ConnectArgs) -> Result<Value> {
    if let Some(remote) = &args.remote {
        return run_remote(ctx, args, remote);
    }
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
    let mut skipped = Vec::new(); // disabled disks / disks on disabled remotes
    let mut port = base;

    for disk in cfg.disks.iter().filter(|d| selected(d)) {
        // Honor the persistent disable states: a disabled disk (or a disk on a
        // disabled remote) is skipped, not connected. `enable` reverses it.
        if !actionable(ctx, disk) {
            let reason = if !disk.enabled {
                "disk disabled"
            } else {
                "remote disabled"
            };
            skipped.push(json!({ "name": disk.name, "reason": reason }));
            continue;
        }
        match reconnect(ctx, disk, port) {
            Ok(v) => {
                on_success(ctx, disk, dry);
                connected.push(v);
            }
            Err(e) => {
                // A remote-pinned disk that failed *might* just have moved — defer
                // it to the single sweep. A local disk that's absent is a hard miss
                // and counts as a give-up right away.
                if disk.remote.is_some() {
                    retry.push(disk.name.clone());
                } else {
                    let auto = note_disk_failure(ctx, disk, dry);
                    failed.push(
                        json!({"name": disk.name, "error": e.to_string(), "auto_disable": auto}),
                    );
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
            match reconnect(ctx, disk, port) {
                Ok(v) => {
                    on_success(ctx, disk, dry);
                    relocated.push(name.clone());
                    connected.push(v);
                }
                Err(e) => {
                    let auto = note_disk_failure(ctx, disk, dry);
                    failed.push(json!({
                        "name": name, "error": e.to_string(),
                        "after_discovery": true, "auto_disable": auto,
                    }));
                }
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
        "skipped": skipped,
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

/// `tpmnt connect --remote <name>` — bring up the disks that live on one remote.
///
/// The membership is decided by reality, not by the config's last-known layout:
/// we probe *this one* remote's block inventory once (the same read-only `blkid`
/// the discovery sweep uses, scoped so it never fans out to the other remotes),
/// then bring up exactly the configured disks whose LUKS UUID is present there
/// now. A disk that was pinned to this remote but has since been removed (the "b"
/// in "was abc, now acd → bring up ac") is reported as `absent`, not failed.
///
/// Positional `names`, when given, further restrict the action to that subset of
/// the remote's disks.
fn run_remote(ctx: &Context, args: &ConnectArgs, remote_name: &str) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();

    let remote = ctx
        .config
        .remotes
        .iter()
        .find(|r| r.name == remote_name)
        .ok_or_else(|| {
            Error::new(
                Code::EConfig,
                format!("no [[remote]] named {remote_name:?}"),
            )
            .with_hint("run `tpmnt remote` to list configured remotes")
        })?;

    // Optional positional filter: restrict to these disk names within the remote.
    let names_opt = if args.names.is_empty() {
        None
    } else {
        Some(args.names.as_slice())
    };
    let named = |d: &Disk| names_opt.is_none_or(|f| f.iter().any(|n| n == &d.name));

    // The configured, *enabled* disks tpmnt believes live on this remote (and pass
    // the filter). Disabled disks are skipped even when their remote is targeted.
    let want: Vec<String> = ctx
        .config
        .disks
        .iter()
        .filter(|d| d.remote.as_deref() == Some(remote_name) && d.enabled && named(d))
        .map(|d| d.name.clone())
        .collect();
    if want.is_empty() {
        return Err(Error::new(
            Code::EConfig,
            format!("no enabled disks live on remote {remote_name:?}"),
        )
        .with_hint(
            "`tpmnt remote` lists the disks on each remote; `tpmnt enable` re-enables one",
        ));
    }

    // One inventory of this single remote decides who's actually present now.
    let uuids = crate::discover::remote_inventory(&ctx.runner, std::slice::from_ref(remote))
        .into_iter()
        .next()
        .map(|(_, u)| u)
        .unwrap_or_default();

    // Mutate a clone so a disk whose path shifted on the remote (sda↔sdb) gets
    // rebound and persisted, mirroring the discovery path.
    let mut cfg = ctx.config.clone();
    let mut connected = Vec::new();
    let mut absent = Vec::new(); // configured here but gone from the remote now
    let mut failed = Vec::new();
    let mut dirty = false;
    let mut port = args.local_port;

    for disk in cfg
        .disks
        .iter_mut()
        .filter(|d| want.iter().any(|n| n == &d.name))
    {
        match uuids.get(disk.uuid.trim()) {
            Some(device) => {
                if crate::discover::rebind(
                    disk,
                    &Location::Remote {
                        remote: remote_name.to_string(),
                        device: device.clone(),
                    },
                ) {
                    dirty = true;
                }
                match reconnect(ctx, disk, port) {
                    Ok(v) => {
                        on_success(ctx, disk, dry);
                        connected.push(v);
                    }
                    Err(e) => failed.push(json!({"name": disk.name, "error": e.to_string()})),
                }
                port += 1;
            }
            None => absent.push(disk.name.clone()),
        }
    }

    if dirty && !dry {
        cfg.save(&ctx.global.config)?;
    }

    // Remote-level auto-disable: if nothing on the remote could be brought up (all
    // wanted disks failed or were absent — i.e. the remote didn't usefully answer),
    // count a give-up; after the threshold, disable the remote so `up` stops probing
    // it into a storm. Any success above already reset the streak via on_success.
    let mut remote_auto = Value::Null;
    if connected.is_empty() && !dry {
        let n = crate::remote_state::note_remote_giveup(&ctx.paths, remote_name);
        if n >= GIVEUP_DISABLE_THRESHOLD {
            let _ = super::remote::set_remote_enabled(ctx, remote_name, false);
            remote_auto = json!({ "auto_disabled": true, "giveups": n });
        } else {
            remote_auto = json!({ "auto_disabled": false, "giveups": n });
        }
    }

    let out = json!({
        "ok": failed.is_empty(),
        "action": "connect",
        "remote": remote_name,
        "dry_run": dry,
        "connected": connected,
        "absent": absent,
        "failed": failed,
        "remote_auto_disable": remote_auto,
    });

    // Only a genuine bring-up error is fatal; an all-absent remote is a soft no-op.
    if connected.is_empty() && !failed.is_empty() {
        return Err(Error::new(
            Code::ENoDevice,
            format!(
                "none of the disk(s) on remote {remote_name:?} could be connected ({} failed)",
                failed.len()
            ),
        )
        .with_hint("check the remote is reachable and the disks are powered/plugged in"));
    }
    Ok(out)
}

/// Record that we just connected a disk living on `remote` (if any), so the
/// dashboard can order its source boxes most-recently-connected first. Local
/// disks (`None`) and dry-runs record nothing.
fn stamp_connected(ctx: &Context, remote: Option<&str>, dry: bool) {
    if dry {
        return;
    }
    if let Some(name) = remote {
        crate::remote_state::record_connected(&ctx.paths, name, crate::remote_state::now_secs());
    }
}

/// On a successful connect: stamp the remote's last-connected time and clear both
/// the remote's and the disk's reconnect give-up streaks (a success resets the
/// auto-disable counter).
fn on_success(ctx: &Context, disk: &Disk, dry: bool) {
    stamp_connected(ctx, disk.remote.as_deref(), dry);
    if !dry {
        crate::remote_state::record_disk_online(&ctx.paths, &disk.name);
    }
}

/// Bring one disk online at its currently-bound location: ensure the ciphertext is
/// reachable here (forward a remote disk if no live forward already carries it),
/// reconcile crypttab/fstab/units so the mount is defined, then open (TPM2) +
/// mount via the shared spin-up path. Idempotent — an already-mounted disk is a
/// no-op. Shared with `enable`, which re-activates a disk it just re-enabled.
pub(crate) fn bring_online(ctx: &Context, disk: &Disk, port: u16) -> Result<Value> {
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
    let remote = value.get("remote").and_then(|v| v.as_str());
    out.push_str(&match (dry, remote) {
        (true, Some(r)) => format!("connect (dry-run, remote {r}):\n"),
        (true, None) => "connect (dry-run):\n".to_string(),
        (false, Some(r)) => format!("connect (remote {r}):\n"),
        (false, None) => "connect:\n".to_string(),
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
    if let Some(a) = value.get("absent").and_then(|v| v.as_array()) {
        if !a.is_empty() {
            let names: Vec<&str> = a.iter().filter_map(|v| v.as_str()).collect();
            out.push_str(&format!(
                "  (not on the remote now, skipped: {})\n",
                names.join(", ")
            ));
        }
    }
    if let Some(sk) = value.get("skipped").and_then(|v| v.as_array()) {
        for d in sk {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let reason = d
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("skipped");
            out.push_str(&format!("  ⊘ {name}: skipped ({reason})\n"));
        }
    }
    if let Some(f) = value.get("failed").and_then(|v| v.as_array()) {
        for d in f {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let err = d
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unreachable");
            let auto = d
                .get("auto_disable")
                .and_then(|a| a.get("auto_disabled"))
                .and_then(|v| v.as_bool())
                == Some(true);
            let tag = if auto {
                "  → auto-disabled after repeated failures"
            } else {
                ""
            };
            out.push_str(&format!("  ✗ {name}: {err}{tag}\n"));
        }
    }
    if value
        .get("remote_auto_disable")
        .and_then(|a| a.get("auto_disabled"))
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        let r = value.get("remote").and_then(|v| v.as_str()).unwrap_or("?");
        out.push_str(&format!(
            "  ⊘ remote {r} auto-disabled after repeated failures\n"
        ));
    }
    let empty = |key: &str| {
        value
            .get(key)
            .and_then(|v| v.as_array())
            .is_none_or(|a| a.is_empty())
    };
    if empty("connected") && empty("failed") && empty("absent") && empty("skipped") {
        out.push_str("  (no disks selected)\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_remote_target_shows_connected_and_skipped() {
        // The "was abc, now acd" case: a and c came up on the remote, b is gone.
        let v = json!({
            "ok": true,
            "action": "connect",
            "remote": "nas",
            "dry_run": false,
            "connected": [
                { "name": "a", "location": "remote" },
                { "name": "c", "location": "remote" },
            ],
            "absent": ["b"],
            "failed": [],
        });
        let out = render(&v);
        assert!(out.starts_with("connect (remote nas):\n"));
        assert!(out.contains("✓ a: connected (remote)"));
        assert!(out.contains("✓ c: connected (remote)"));
        assert!(out.contains("not on the remote now, skipped: b"));
        assert!(!out.contains("no disks selected"));
    }

    #[test]
    fn render_shows_disabled_skips_and_auto_disable() {
        let v = json!({
            "action": "connect",
            "dry_run": false,
            "connected": [],
            "skipped": [{ "name": "arc", "reason": "disk disabled" }],
            "failed": [{
                "name": "far", "error": "unreachable",
                "auto_disable": { "auto_disabled": true, "giveups": 3 },
            }],
        });
        let out = render(&v);
        assert!(out.contains("⊘ arc: skipped (disk disabled)"));
        assert!(out.contains("✗ far: unreachable  → auto-disabled after repeated failures"));
        assert!(!out.contains("no disks selected"));
    }

    #[test]
    fn render_reports_remote_auto_disable() {
        let v = json!({
            "action": "connect",
            "remote": "nas",
            "dry_run": false,
            "connected": [],
            "absent": [],
            "failed": [],
            "remote_auto_disable": { "auto_disabled": true, "giveups": 3 },
        });
        let out = render(&v);
        assert!(out.contains("remote nas auto-disabled after repeated failures"));
    }
}
