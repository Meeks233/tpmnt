//! `tpmnt enable` / `tpmnt disable` — flip a disk's persistent management state
//! (the `enabled` flag in the config), and act on it now.
//!
//!  * **disable** keeps the config entry and the key bundle, but tears the disk
//!    down *and* removes its crypttab/fstab/units so it never auto-unlocks at
//!    boot. It's the dormant middle state between "managed & active" and the
//!    irreversible `destroy`/`detach`.
//!  * **enable** flips the flag back on and brings the disk online (reconcile +
//!    open + mount), reusing the same `connect` spin-up path.
//!
//! Both accept explicit names or, with none, an interactive multi-select.

use serde_json::{json, Value};

use crate::cli::ToggleArgs;
use crate::config::{Config, Disk};
use crate::error::{Code, Error, Result};
use crate::reconcile;

use super::offline::{detach, find_disk};
use super::Context;

pub fn enable(ctx: &Context, args: &ToggleArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let interactive = crate::tui::interactive(ctx.global.non_interactive);

    // Interactive list offers the disks that are currently disabled.
    let targets = resolve_targets(ctx, &args.names, interactive, |d| !d.enabled, "enable")?;
    if targets.is_empty() {
        return Ok(note("enable", dry, "nothing selected"));
    }
    let disks: Vec<Disk> = targets
        .iter()
        .map(|n| find_disk(ctx, n).cloned())
        .collect::<Result<_>>()?;

    set_enabled(ctx, &targets, true, dry)?;
    // A re-enabled disk starts its reconnect budget fresh.
    if !dry {
        for n in &targets {
            crate::remote_state::reset_disk(&ctx.paths, n);
        }
    }

    // Bring each online now (reconciles crypttab/fstab/units + opens + mounts).
    let mut results = Vec::new();
    let mut port = args_local_port();
    for disk in &disks {
        match super::connect::bring_online(ctx, disk, port) {
            Ok(mut v) => {
                v["enabled"] = json!(true);
                results.push(v);
            }
            Err(e) => results.push(json!({
                "name": disk.name, "enabled": true, "online_error": e.to_string(),
            })),
        }
        if disk.remote.is_some() {
            port += 1;
        }
    }
    Ok(json!({
        "ok": true, "action": "enable", "dry_run": dry, "enabled": results,
    }))
}

pub fn disable(ctx: &Context, args: &ToggleArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let interactive = crate::tui::interactive(ctx.global.non_interactive);

    // Interactive list offers the disks that are currently enabled.
    let targets = resolve_targets(ctx, &args.names, interactive, |d| d.enabled, "disable")?;
    if targets.is_empty() {
        return Ok(note("disable", dry, "nothing selected"));
    }
    let disks: Vec<Disk> = targets
        .iter()
        .map(|n| find_disk(ctx, n).cloned())
        .collect::<Result<_>>()?;

    set_enabled(ctx, &targets, false, dry)?;

    let mut results = Vec::new();
    for disk in &disks {
        let steps = deactivate(ctx, disk, args.force, dry)?;
        results.push(json!({ "name": disk.name, "steps": steps }));
    }
    Ok(json!({
        "ok": true, "action": "disable", "dry_run": dry, "disabled": results,
    }))
}

/// Tear a disk down and strip its auto-unlock footprint (crypttab/fstab/units),
/// keeping its config entry + key bundle. The dormant half of `disable`; also the
/// per-disk action when three failed reconnects auto-disable a disk.
pub(crate) fn deactivate(ctx: &Context, disk: &Disk, force: bool, dry: bool) -> Result<Vec<Value>> {
    let mut steps = detach(ctx, disk, force)?;

    let ct = reconcile::remove_tagged_line(&ctx.paths.crypttab(), &disk.name, dry)?;
    let ft = reconcile::remove_tagged_line(&ctx.paths.fstab(), &disk.name, dry)?;
    steps.push(json!({ "crypttab": ct, "fstab": ft }));

    let unit_dir = ctx.paths.systemd_unit_dir();
    let units = [
        reconcile::unit_name_for(&disk.mountpoint),
        format!("tpmnt-monitor-{}.service", disk.name),
        format!("tpmnt-schedule-{}.service", disk.name),
    ];
    for unit in &units {
        let path = unit_dir.join(unit);
        if path.exists() {
            let _ = ctx.runner.run(
                &["systemctl", "disable", "--now", unit],
                "stop+disable unit while disabling disk",
            );
            if !dry {
                let _ = std::fs::remove_file(&path);
            }
            steps.push(json!({ "unit": unit, "action": "removed" }));
        }
    }
    Ok(steps)
}

/// A base NBD port for enable's remote spin-ups (distinct from connect's block).
fn args_local_port() -> u16 {
    21817
}

/// Resolve target disk names: explicit CLI names, or an interactive multi-select
/// (its list is filtered by `candidate`, e.g. only-disabled for `enable`).
fn resolve_targets(
    ctx: &Context,
    names: &[String],
    interactive: bool,
    candidate: impl Fn(&Disk) -> bool,
    verb: &str,
) -> Result<Vec<String>> {
    if !names.is_empty() {
        return Ok(names.to_vec());
    }
    if !interactive {
        return Err(
            Error::new(Code::EConfig, format!("no disk named to {verb}")).with_hint(format!(
                "name the disk(s) to {verb}, or run in an interactive terminal to multi-select"
            )),
        );
    }
    let items: Vec<crate::tui::Item> = ctx
        .config
        .disks
        .iter()
        .filter(|d| candidate(d))
        .map(|d| {
            let where_ = d
                .remote
                .as_deref()
                .map(|r| format!("remote {r}"))
                .unwrap_or_else(|| "local".to_string());
            crate::tui::Item::new(
                d.name.clone(),
                format!("{}  [{}]", d.mountpoint.display(), where_),
            )
        })
        .collect();
    if items.is_empty() {
        return Ok(Vec::new());
    }
    // The filtered candidate names, indexed to match the shown list.
    let candidates: Vec<String> = ctx
        .config
        .disks
        .iter()
        .filter(|d| candidate(d))
        .map(|d| d.name.clone())
        .collect();
    let chosen = crate::tui::multiselect(&format!("Select disk(s) to {verb}:"), &items)?;
    Ok(chosen.into_iter().map(|i| candidates[i].clone()).collect())
}

/// Persist `enabled = val` for `names` in the on-disk config (validates each).
/// Shared with `connect`, which flips a disk to disabled after repeated
/// reconnect give-ups.
pub(crate) fn set_enabled(ctx: &Context, names: &[String], val: bool, dry: bool) -> Result<()> {
    // Validate every name against the in-memory config first.
    for n in names {
        find_disk(ctx, n)?;
    }
    if dry {
        return Ok(());
    }
    let path = &ctx.global.config;
    let mut cfg = Config::load(path)?;
    let mut changed = false;
    for d in cfg.disks.iter_mut() {
        if names.iter().any(|n| n == &d.name) && d.enabled != val {
            d.enabled = val;
            changed = true;
        }
    }
    if changed {
        cfg.save(path)?;
    }
    Ok(())
}

fn note(action: &str, dry: bool, note: &str) -> Value {
    json!({ "ok": true, "action": action, "dry_run": dry, "note": note })
}

/// Human rendering for enable/disable.
pub fn render(value: &Value) -> String {
    let action = value.get("action").and_then(|v| v.as_str()).unwrap_or("?");
    let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
    let mut out = String::new();
    out.push_str(&format!(
        "{action}{}:\n",
        if dry { " (dry-run)" } else { "" }
    ));

    if let Some(n) = value.get("note").and_then(|v| v.as_str()) {
        out.push_str(&format!("  ({n})\n"));
        return out;
    }
    let key = if action == "enable" {
        "enabled"
    } else {
        "disabled"
    };
    if let Some(items) = value.get(key).and_then(|v| v.as_array()) {
        for d in items {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            if action == "enable" {
                if let Some(err) = d.get("online_error").and_then(|v| v.as_str()) {
                    out.push_str(&format!(
                        "  ⚠ {name}: enabled, but not online yet ({err})\n"
                    ));
                } else {
                    out.push_str(&format!("  ✓ {name}: enabled and online\n"));
                }
            } else {
                out.push_str(&format!(
                    "  ✓ {name}: disabled (dormant; data + keys kept)\n"
                ));
            }
        }
    }
    out
}
