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
    let disk = find_disk(ctx, &args.name)?.clone();
    let dry = ctx.global.effective_dry_run();

    // Confirmation gate — required even for AI/automation.
    if !ctx.global.yes {
        return Err(Error::new(
            Code::EConfirmationRequired,
            format!(
                "destroy permanently removes tpmnt's local management of {:?} \
                 (config, crypttab/fstab, units, key bundles)",
                disk.name
            ),
        )
        .with_hint(
            "re-run with --yes to confirm; the device is NOT formatted, data stays encrypted",
        ));
    }

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
    let steps = detach(ctx, &disk, args.force)?;

    // 2. Purge every local artifact tied to this disk.
    let mut purged: Vec<Value> = Vec::new();

    // 2a. Stop+disable and remove systemd units.
    let unit_dir = ctx.paths.systemd_unit_dir();
    let mount_unit = reconcile::unit_name_for(&disk.mountpoint);
    let units = [
        mount_unit,
        format!("tpmnt-monitor-{}.service", disk.name),
        format!("tpmnt-schedule-{}.service", disk.name),
    ];
    for unit in &units {
        let path = unit_dir.join(unit);
        if path.exists() {
            // Best-effort stop+disable so systemd stops restarting it.
            let _ = ctx.runner.run(
                &["systemctl", "disable", "--now", unit],
                "stop+disable disk unit before removal",
            );
        }
        purged.push(remove_file(&path, dry));
    }

    // 2b. Key bundles (sealed + plaintext + escrow copies).
    for ext in ["cred", "json", "age", "asc", "enc"] {
        purged.push(remove_file(&dir.join(format!("{}.{ext}", disk.name)), dry));
    }

    // 2c. Header backup + monitor/schedule state.
    purged.push(remove_file(&ctx.paths.header_backup(&disk.uuid), dry));
    purged.push(remove_file(&ctx.paths.monitor_state(&disk.name), dry));
    purged.push(remove_file(&ctx.paths.schedule_state(&disk.name), dry));

    // 2d. crypttab / fstab tagged lines.
    let crypttab = reconcile::remove_tagged_line(&ctx.paths.crypttab(), &disk.name, dry)?;
    let fstab = reconcile::remove_tagged_line(&ctx.paths.fstab(), &disk.name, dry)?;

    // 2e. The mountpoint dir, if now empty.
    let mp_removed = remove_empty_dir(&disk.mountpoint, dry);

    // 2f. The [[disk]] entry in the config.
    let config_removed = remove_from_config(ctx, &disk.name, dry)?;

    Ok(json!({
        "ok": true,
        "action": "destroy",
        "name": disk.name,
        "remote": disk.remote,
        "dry_run": dry,
        "formatted": false,
        "detach_steps": steps,
        "purged": purged,
        "crypttab": crypttab,
        "fstab": fstab,
        "mountpoint_removed": mp_removed,
        "config_removed": config_removed,
        "warnings": warnings,
    }))
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
