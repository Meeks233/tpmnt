//! `tpmnt rename <old> <new>` — change a disk's logical (mount) name.
//!
//! The logical name drives the dm-crypt mapper (`tpmnt-<name>`), the default
//! mountpoint (`/mnt/<name>`), the crypttab/fstab markers, and the sealed key
//! bundle filename. A rename re-points all of them declaratively.
//!
//! If the disk is currently mounted, the switch is done LIVE without tearing down
//! a remote ciphertext forward: unmount the old path, `dmsetup rename` the open
//! mapping in place (the crypt target and any NBD backing are untouched), then
//! remount at the new path. Never modifies the data.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::cli::RenameArgs;
use crate::error::{err, Code, Error, Result};
use crate::keystore;
use crate::reconcile;

use super::Context;

/// Whether `mountpoint` is currently a mount (local /proc/mounts check).
fn is_mounted(mountpoint: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|s| {
            s.lines()
                .any(|l| l.split_whitespace().nth(1) == Some(mountpoint))
        })
        .unwrap_or(false)
}

pub fn run(ctx: &Context, args: &RenameArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();

    if args.new == args.old {
        return err(Code::EConfig, "new name is the same as the old name");
    }
    if !is_valid_name(&args.new) {
        return Err(
            Error::new(Code::EConfig, format!("invalid disk name {:?}", args.new))
                .with_hint("use letters, digits, '-' or '_' (it becomes tpmnt-<name>)"),
        );
    }

    let mut cfg = ctx.config.clone();
    let idx = cfg
        .disks
        .iter()
        .position(|d| d.name == args.old)
        .ok_or_else(|| {
            Error::new(Code::EConfig, format!("no disk named {:?}", args.old))
                .with_hint("run `tpmnt status` to list configured disks")
        })?;
    if cfg.disks.iter().any(|d| d.name == args.new) {
        return err(
            Code::EConfig,
            format!("a disk named {:?} already exists", args.new),
        );
    }

    let old = cfg.disks[idx].clone();
    let old_mapper = old.mapper_name();
    let old_mp = old.mountpoint.clone();

    // Compute the renamed disk. The mapper follows the name unless it was pinned
    // to a custom value; a DEFAULT mountpoint (/mnt/<old>) moves to /mnt/<new>,
    // while a custom mountpoint is preserved.
    let mut new = old.clone();
    new.name = args.new.clone();
    let default_mp = PathBuf::from(format!("/mnt/{}", args.old));
    if old.mountpoint == default_mp {
        new.mountpoint = PathBuf::from(format!("/mnt/{}", args.new));
    }
    let new_mapper = new.mapper_name();
    let new_mp = new.mountpoint.clone();

    let old_mp_str = old_mp.to_string_lossy().into_owned();
    let mapper_renames = old_mapper != new_mapper;
    let mut steps: Vec<Value> = Vec::new();

    // 1. If the old mapping is open, do the live switch. Unmount first so the
    //    mapper isn't held, rename it in place, then (if it was mounted) remount
    //    at the new path with steady-state options.
    let mapper_dev = format!("/dev/mapper/{old_mapper}");
    let mapper_open = dry || Path::new(&mapper_dev).exists();
    let was_mounted = dry || is_mounted(&old_mp_str);

    if mapper_open {
        if was_mounted {
            let umount: Vec<&str> = if args.force {
                vec!["umount", "-l", &old_mp_str]
            } else {
                vec!["umount", &old_mp_str]
            };
            let out = ctx.runner.run(&umount, "unmount before rename")?;
            if !out.ok() {
                let e = out.stderr.to_lowercase();
                if e.contains("not mounted") || e.contains("no mount point") {
                    steps.push(json!({"step": "umount", "skipped": "not mounted"}));
                } else if !args.force {
                    return Err(Error::new(
                        Code::EMountpointBusy,
                        format!("{old_mp_str} is busy; refusing to unmount"),
                    )
                    .with_hint("pass --force to lazily detach a busy mount (umount -l)"));
                } else {
                    out.require("umount -l")?;
                }
            } else {
                steps.push(json!({"step": "umount", "target": old_mp_str}));
            }
        }
        if mapper_renames {
            // dmsetup rename moves the mapping node without closing it, so a
            // remote NBD ciphertext forward stays live underneath.
            ctx.runner
                .run(
                    &["dmsetup", "rename", &old_mapper, &new_mapper],
                    "rename the open dm-crypt mapping in place",
                )?
                .require("dmsetup rename")?;
            steps.push(json!({"step": "dmsetup-rename", "from": old_mapper, "to": new_mapper}));
        }
    }

    // 2. Reconcile the declarative files under the new name and drop the old
    //    tagged lines. (write the new lines first, then remove the old marker.)
    reconcile::reconcile_disk(
        &ctx.paths.crypttab(),
        &ctx.paths.fstab(),
        &ctx.paths.systemd_unit_dir(),
        &new,
        cfg.defaults.mount_backend,
        dry,
    )?;
    reconcile::remove_tagged_line(&ctx.paths.crypttab(), &args.old, dry)?;
    reconcile::remove_tagged_line(&ctx.paths.fstab(), &args.old, dry)?;
    if old_mp != new_mp {
        // A moved mountpoint leaves a stale systemd unit under the old name.
        let old_unit = ctx
            .paths
            .systemd_unit_dir()
            .join(reconcile::unit_name_for(&old_mp));
        if !dry {
            let _ = std::fs::remove_file(&old_unit);
        }
    }

    // 3. Re-seal the key bundle under the new name. The sealed blob is bound to
    //    the disk name as AAD, so a file rename alone would fail to decrypt; we
    //    unseal with the old name and re-seal with the new one, updating the
    //    name/mapper/mountpoint fields inside the bundle for consistency.
    let dir = &cfg.defaults.key_backup;
    let sealed_old = keystore::sealed_path(dir, &args.old);
    let plain_old = dir.join(format!("{}.json", args.old));
    if sealed_old.exists() && !dry {
        let bundle_json = keystore::unseal(&ctx.runner, &sealed_old, &args.old)?;
        let updated = rewrite_bundle(&bundle_json, &new)?;
        keystore::seal(&ctx.runner, dir, &args.new, updated.as_bytes(), dry)?;
        std::fs::remove_file(&sealed_old).ok();
        steps.push(json!({"step": "reseal-bundle", "kind": "sealed"}));
    } else if plain_old.exists() && !dry {
        let bundle_json = std::fs::read_to_string(&plain_old)
            .map_err(|e| Error::new(Code::EEscrowFailed, format!("read bundle: {e}")))?;
        let updated = rewrite_bundle(&bundle_json, &new)?;
        let plain_new = dir.join(format!("{}.json", args.new));
        std::fs::write(&plain_new, updated)
            .map_err(|e| Error::new(Code::EEscrowFailed, format!("write bundle: {e}")))?;
        std::fs::remove_file(&plain_old).ok();
        steps.push(json!({"step": "reseal-bundle", "kind": "plaintext"}));
    }

    // 4. Persist the renamed disk, ensure the new mountpoint dir exists, and
    //    remount there if it had been mounted.
    cfg.disks[idx] = new.clone();
    if !dry {
        cfg.save(&ctx.global.config)?;
        std::fs::create_dir_all(&new_mp).ok();
    }
    let mut remounted = false;
    if mapper_open && was_mounted {
        let new_mp_str = new_mp.to_string_lossy().into_owned();
        let opts = reconcile::mount_options(&new);
        let new_mapper_dev = format!("/dev/mapper/{new_mapper}");
        ctx.runner
            .run(
                &["mount", "-o", &opts, &new_mapper_dev, &new_mp_str],
                "remount at the new path",
            )?
            .require("mount")?;
        steps.push(json!({"step": "mount", "target": new_mp_str}));
        remounted = true;
    }

    Ok(json!({
        "ok": true,
        "action": "rename",
        "dry_run": dry,
        "old": args.old,
        "new": args.new,
        "mapper": { "from": old_mapper, "to": new_mapper },
        "mountpoint": { "from": old_mp, "to": new_mp },
        "was_mounted": mapper_open && was_mounted,
        "remounted": remounted,
        "steps": steps,
    }))
}

/// Update the name/mapper/mountpoint fields inside a key bundle JSON to match the
/// renamed disk (the secrets are carried over unchanged).
fn rewrite_bundle(bundle_json: &str, new: &crate::config::Disk) -> Result<String> {
    let mut bundle: Value = serde_json::from_str(bundle_json)
        .map_err(|e| Error::new(Code::EInternal, format!("parse key bundle: {e}")))?;
    if let Some(obj) = bundle.as_object_mut() {
        obj.insert("name".into(), json!(new.name));
        obj.insert("mapper".into(), json!(new.mapper_name()));
        obj.insert("mountpoint".into(), json!(new.mountpoint));
    }
    Ok(serde_json::to_string_pretty(&bundle).unwrap())
}

/// A logical name safe to embed in a mapper name and file markers.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Human rendering for `rename`.
pub fn render(value: &Value) -> String {
    let mut out = String::new();
    let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
    let old = value.get("old").and_then(|v| v.as_str()).unwrap_or("?");
    let new = value.get("new").and_then(|v| v.as_str()).unwrap_or("?");
    out.push_str(&format!(
        "rename{}: {old} → {new}\n",
        if dry { " (dry-run)" } else { "" }
    ));
    if let Some(mp) = value.get("mountpoint") {
        let from = mp.get("from").and_then(|v| v.as_str()).unwrap_or("?");
        let to = mp.get("to").and_then(|v| v.as_str()).unwrap_or("?");
        if from != to {
            out.push_str(&format!("  mountpoint: {from} → {to}\n"));
        }
    }
    if value.get("remounted").and_then(|v| v.as_bool()) == Some(true) {
        out.push_str("  remounted live under the new name\n");
    } else if value.get("was_mounted").and_then(|v| v.as_bool()) == Some(true) {
        out.push_str("  was mounted; live-switched\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(is_valid_name("mycache"));
        assert!(is_valid_name("old-disk_2"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("bad name"));
        assert!(!is_valid_name("slash/name"));
    }

    #[test]
    fn rewrite_bundle_updates_identity_keeps_secrets() {
        let d = crate::config::Disk {
            name: "new".into(),
            uuid: "u".into(),
            device: None,
            mapper: None,
            mountpoint: PathBuf::from("/mnt/new"),
            fstype: "btrfs".into(),
            pcrs: vec![],
            with_pin: false,
            power_profile: crate::config::PowerProfile::ColdStandby,
            idle_timeout: "5min".into(),
            power_off_method: crate::config::PowerOffMethod::Auto,
            teardown: crate::config::Teardown::Direct,
            schedule: None,
            remote: None,
            transport: None,
        };
        let src = json!({
            "name": "old", "mapper": "tpmnt-old", "mountpoint": "/mnt/old",
            "passphrase": "secret-pass", "recovery_key": "rk-123",
        })
        .to_string();
        let out = rewrite_bundle(&src, &d).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["name"], "new");
        assert_eq!(v["mapper"], "tpmnt-new");
        assert_eq!(v["mountpoint"], "/mnt/new");
        // Secrets carried over untouched.
        assert_eq!(v["passphrase"], "secret-pass");
        assert_eq!(v["recovery_key"], "rk-123");
    }

    #[test]
    fn render_shows_mount_move() {
        let v = json!({
            "dry_run": false, "old": "a", "new": "b",
            "mountpoint": { "from": "/mnt/a", "to": "/mnt/b" },
            "was_mounted": true, "remounted": true,
        });
        let out = render(&v);
        assert!(out.contains("a → b"));
        assert!(out.contains("/mnt/a → /mnt/b"));
        assert!(out.contains("remounted live"));
    }
}
