//! `tpmnt destroy <name>` — permanently stop managing a disk. Requires explicit
//! confirmation (`--yes`), even for automated/AI callers. After confirmation it
//! detaches the disk (grace unmount + close) and purges **all local footprint**:
//! config entry, crypttab/fstab lines, systemd units, sealed/escrow key bundles,
//! header backup, and monitor/schedule state.
//!
//! It deliberately does **not** format or wipe the device: LUKS ciphertext is
//! safe at rest, so the data is simply left encrypted and unreadable. Reformat
//! later if you actually need the raw space back. NOTE: removing the local key
//! bundle makes the data unrecoverable unless an offline `--escrow` copy exists.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::cli::DestroyArgs;
use crate::config::Config;
use crate::error::{Code, Error, Result};
use crate::reconcile;

use super::offline::{detach, find_disk};
use super::Context;

pub fn run(ctx: &Context, args: &DestroyArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let interactive = crate::tui::interactive(ctx.global.non_interactive);

    // Resolve the target disk names: explicit on the CLI, or an interactive
    // multi-select when none were named.
    let targets = resolve_targets(ctx, &args.names, interactive)?;
    if targets.is_empty() {
        return Ok(json!({
            "ok": true, "action": "destroy", "dry_run": dry,
            "destroyed": [], "note": "nothing selected",
        }));
    }

    // Validate every name up front (fail before touching anything).
    let disks: Vec<_> = targets
        .iter()
        .map(|n| find_disk(ctx, n).cloned())
        .collect::<Result<Vec<_>>>()?;

    // Confirmation gate — required even for AI/automation. Satisfied by --yes, or
    // an explicit interactive y/N (the multi-select alone isn't taken as consent).
    let confirmed = ctx.global.yes
        || (interactive
            && crate::tui::confirm(&format!(
                "Permanently remove tpmnt's local management of {} disk(s): {}? \
                 (data stays encrypted, NOT wiped) [y/N] ",
                disks.len(),
                targets.join(", "),
            ))?);
    if !confirmed {
        return Err(Error::new(
            Code::EConfirmationRequired,
            format!(
                "destroy permanently removes tpmnt's local management of {} disk(s) \
                 (config, crypttab/fstab, units, key bundles)",
                disks.len()
            ),
        )
        .with_hint(
            "re-run with --yes to confirm; the device is NOT formatted, data stays encrypted",
        ));
    }

    let mut destroyed = Vec::new();
    for disk in &disks {
        destroyed.push(destroy_one(ctx, disk, args.force, dry)?);
    }
    Ok(json!({
        "ok": true,
        "action": "destroy",
        "dry_run": dry,
        "formatted": false,
        "destroyed": destroyed,
    }))
}

/// Turn CLI names (or, when none given, an interactive multi-select) into the
/// list of disk names to destroy. A non-interactive run with no names is an
/// error; an interactive run with no disks configured yields an empty list.
fn resolve_targets(ctx: &Context, names: &[String], interactive: bool) -> Result<Vec<String>> {
    if !names.is_empty() {
        return Ok(names.to_vec());
    }
    if !interactive {
        return Err(
            Error::new(Code::EConfig, "no disk named to destroy".to_string()).with_hint(
                "name the disk(s) to destroy, or run in an interactive terminal to multi-select",
            ),
        );
    }
    let items: Vec<crate::tui::Item> = ctx
        .config
        .disks
        .iter()
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
    let chosen = crate::tui::multiselect(
        "Select disk(s) to destroy — removes tpmnt management only; data stays encrypted:",
        &items,
    )?;
    Ok(chosen
        .into_iter()
        .map(|i| ctx.config.disks[i].name.clone())
        .collect())
}

/// Purge every local artifact for a single disk (detach + files + crypttab/fstab
/// + mountpoint + config entry). Returns a per-disk result object.
fn destroy_one(ctx: &Context, disk: &crate::config::Disk, force: bool, dry: bool) -> Result<Value> {
    // Warn if we're about to delete the only copy of the key.
    let dir = &ctx.config.defaults.key_backup;
    let has_offline_escrow = ["age", "asc", "enc"]
        .iter()
        .any(|ext| dir.join(format!("{}.{ext}", disk.name)).exists());
    let mut warnings: Vec<String> = Vec::new();
    if !has_offline_escrow {
        warnings.push(
            "no offline escrow (age/gpg) found; deleting the local key makes this disk's data \
             unrecoverable. This is expected for a disk you're retiring."
                .into(),
        );
    }

    // 1. Detach (grace unmount + close) on the disk's host.
    let steps = detach(ctx, disk, force)?;

    // 2. Purge every local artifact tied to this disk (units, key bundles,
    //    crypttab/fstab, mountpoint, config entry).
    let mut result = purge_local_footprint(ctx, disk, dry)?;
    result["detach_steps"] = json!(steps);
    result["warnings"] = json!(warnings);
    Ok(result)
}

/// Remove every local artifact tied to `disk`: systemd units, all key bundles
/// (sealed, plaintext, escrow), the header backup, monitor/schedule state, the
/// crypttab/fstab lines, the (empty) mountpoint dir, and the `[[disk]]` config
/// entry. Shared by `destroy` (retire the disk) and `detach` (hand it to manual
/// mode) — neither touches the LUKS data itself. Returns a per-disk result object.
pub(crate) fn purge_local_footprint(
    ctx: &Context,
    disk: &crate::config::Disk,
    dry: bool,
) -> Result<Value> {
    let dir = &ctx.config.defaults.key_backup;
    let mut purged: Vec<Value> = Vec::new();

    // Stop+disable and remove systemd units.
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
                "stop+disable disk unit before removal",
            );
        }
        purged.push(remove_file(&path, dry));
    }

    // Key bundles (sealed + plaintext + escrow copies).
    for ext in ["cred", "json", "age", "asc", "enc"] {
        purged.push(remove_file(&dir.join(format!("{}.{ext}", disk.name)), dry));
    }

    // Header backup + monitor/schedule state.
    purged.push(remove_file(&ctx.paths.header_backup(&disk.uuid), dry));
    purged.push(remove_file(&ctx.paths.monitor_state(&disk.name), dry));
    purged.push(remove_file(&ctx.paths.schedule_state(&disk.name), dry));

    let crypttab = reconcile::remove_tagged_line(&ctx.paths.crypttab(), &disk.name, dry)?;
    let fstab = reconcile::remove_tagged_line(&ctx.paths.fstab(), &disk.name, dry)?;
    let mp_removed = remove_empty_dir(&disk.mountpoint, dry);
    let config_removed = remove_from_config(ctx, &disk.name, dry)?;

    Ok(json!({
        "name": disk.name,
        "remote": disk.remote,
        "purged": purged,
        "crypttab": crypttab,
        "fstab": fstab,
        "mountpoint_removed": mp_removed,
        "config_removed": config_removed,
    }))
}

/// Human rendering: one line per destroyed disk, plus any key-loss warnings.
pub fn render(value: &Value) -> String {
    let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
    let mut out = String::new();
    out.push_str(if dry {
        "destroy (dry-run):\n"
    } else {
        "destroy:\n"
    });
    match value.get("destroyed").and_then(|v| v.as_array()) {
        Some(ds) if !ds.is_empty() => {
            for d in ds {
                let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let cfg = d
                    .get("config_removed")
                    .and_then(|c| c.get("action"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                out.push_str(&format!(
                    "  ✓ {name}: local management removed (config {cfg}, data left encrypted)\n"
                ));
                if let Some(ws) = d.get("warnings").and_then(|v| v.as_array()) {
                    for w in ws.iter().filter_map(|v| v.as_str()) {
                        out.push_str(&format!("      ⚠ {w}\n"));
                    }
                }
            }
        }
        _ => {
            let note = value
                .get("note")
                .and_then(|v| v.as_str())
                .unwrap_or("nothing destroyed");
            out.push_str(&format!("  ({note})\n"));
        }
    }
    out
}

/// Remove a file, reporting the action. A missing file is a noop.
fn remove_file(path: &Path, dry: bool) -> Value {
    let action = if path.exists() {
        if !dry {
            let _ = std::fs::remove_file(path);
        }
        "remove"
    } else {
        "noop"
    };
    json!({ "path": path.display().to_string(), "action": action })
}

/// Remove `dir` only if it exists and is empty (best-effort).
fn remove_empty_dir(dir: &Path, dry: bool) -> Value {
    let empty = dir
        .read_dir()
        .map(|mut it| it.next().is_none())
        .unwrap_or(false);
    let action = if dir.exists() && empty {
        if !dry {
            let _ = std::fs::remove_dir(dir);
        }
        "remove"
    } else if dir.exists() {
        "kept-nonempty"
    } else {
        "noop"
    };
    json!({ "path": dir.display().to_string(), "action": action })
}

/// Drop the disk's `[[disk]]` entry from the config on disk.
fn remove_from_config(ctx: &Context, name: &str, dry: bool) -> Result<Value> {
    let path: &PathBuf = &ctx.global.config;
    let mut cfg = Config::load(path)?;
    let before = cfg.disks.len();
    cfg.disks.retain(|d| d.name != name);
    let removed = cfg.disks.len() != before;
    if removed && !dry {
        std::fs::write(path, cfg.to_toml()).map_err(|e| {
            Error::new(
                Code::EConfig,
                format!("write config {}: {e}", path.display()),
            )
        })?;
    }
    Ok(json!({
        "path": path.display().to_string(),
        "action": if removed { "remove" } else { "noop" },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_file_dry_run_reports_but_keeps_file() {
        let dir = std::env::temp_dir().join(format!("tpmnt-destroy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.cred");
        std::fs::write(&f, b"secret").unwrap();

        let v = remove_file(&f, true);
        assert_eq!(v["action"], "remove");
        assert!(f.exists(), "dry-run must not delete");

        let v = remove_file(&f, false);
        assert_eq!(v["action"], "remove");
        assert!(!f.exists(), "real run deletes");

        // A missing file is a noop.
        assert_eq!(remove_file(&f, false)["action"], "noop");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_empty_dir_keeps_nonempty() {
        let dir = std::env::temp_dir().join(format!("tpmnt-destroy-mp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("keep"), b"data").unwrap();
        assert_eq!(remove_empty_dir(&dir, false)["action"], "kept-nonempty");
        assert!(dir.exists());

        std::fs::remove_file(dir.join("keep")).unwrap();
        assert_eq!(remove_empty_dir(&dir, false)["action"], "remove");
        assert!(!dir.exists());
    }
}
