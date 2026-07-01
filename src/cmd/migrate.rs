//! `tpmnt migrate` — on a NEW machine, re-enroll the LOCAL TPM for every
//! configured disk (TPM secrets are machine-bound and cannot move), then
//! recreate crypttab/fstab/units. Each disk is unlocked via its portable
//! passphrase/recovery keyslot ($PASSWORD).

use serde_json::{json, Value};

use crate::cli::MigrateArgs;
use crate::error::Result;
use crate::{luks, pin, reconcile, vault};

use super::Context;

pub fn run(ctx: &Context, args: &MigrateArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let mut out = Vec::new();

    // Load the unified PIN vault once, if present: a single PIN then unlocks every
    // disk's passphrase for re-enrollment (and doubles as NEWPIN for PIN disks),
    // instead of demanding a per-disk $PASSWORD. When absent, each disk falls back
    // to $PASSWORD exactly as before.
    let dir = &ctx.config.defaults.key_backup;
    let vault_doc = if vault::vault_path(dir).exists() {
        let pin = pin::resolve(args.pin_file.as_deref(), ctx.global.non_interactive)?;
        std::env::set_var("TPMNT_PIN", &pin);
        Some(vault::load(&ctx.runner, dir, &pin)?)
    } else {
        None
    };

    // Auto-discovery first: a disk physically moved to THIS machine is still bound
    // to its old location in the config, so re-locate every disk by UUID and rebind
    // (local↔remote) before re-enrolling — otherwise `device_path()` points at a
    // stale remote path and the disk we just plugged in is missed. Mirrors `apply`.
    let (cfg, _moved) = super::discover::relocate(ctx, None)?;

    for disk in &cfg.disks {
        let device = disk.device_path();

        // Only disks reachable *here* can be re-enrolled against the local TPM. A
        // disk still living on a remote (or currently unplugged) is skipped, not
        // fatal — migration is commonly of just the subset you physically moved.
        // Crucially, the device path must resolve to a LUKS2 container whose own
        // UUID matches this disk's: a stale config `device` (left behind when a
        // disk moved) can now point at a *different* disk, and force-re-enrolling
        // that one would wipe the wrong TPM slot. The UUID is the identity; a
        // mismatch means "not here", so skip.
        match luks::inspect(&ctx.runner, &device) {
            Ok(info) if info.is_luks2 && info.uuid.as_deref() == Some(disk.uuid.as_str()) => {}
            Ok(info) if info.is_luks2 => {
                out.push(json!({"name": disk.name, "device": device,
                    "skipped": format!("identity mismatch: {device} holds UUID {} not {}",
                        info.uuid.as_deref().unwrap_or("?"), disk.uuid)}));
                continue;
            }
            Ok(_) => {
                out.push(json!({"name": disk.name, "device": device, "skipped": "not LUKS2 here"}));
                continue;
            }
            Err(e) => {
                out.push(json!({"name": disk.name, "device": device,
                    "skipped": format!("not reachable here: {}", e.message)}));
                continue;
            }
        }

        // Re-enroll the local TPM using the portable passphrase keyslot, sourced
        // from the vault when available, else $PASSWORD. `force` wipes any stale
        // TPM2 slot first: a disk migrated from another host carries *that* host's
        // TPM2 token, which cannot unlock here — without the wipe the existing
        // foreign token short-circuits enrollment to a no-op and the disk never
        // gains a working local token (so it can never auto-unlock on this machine).
        let enroll =
            super::enroll::enroll_device(ctx, &device, &disk.pcrs, disk.with_pin, true, || {
                if let Some(v) = &vault_doc {
                    if let Some(p) = vault::get(v, &disk.name)
                        .and_then(|b| b.get("passphrase"))
                        .and_then(|x| x.as_str())
                    {
                        return Ok(p.to_string());
                    }
                }
                std::env::var("PASSWORD").map_err(|_| {
                    crate::error::Error::new(
                        crate::error::Code::ENoPassphrase,
                        format!(
                        "migrate needs {}'s passphrase: add it to the PIN vault or set $PASSWORD",
                        disk.name
                    ),
                    )
                })
            })?;

        let changes = reconcile::reconcile_disk(
            &ctx.paths.crypttab(),
            &ctx.paths.fstab(),
            &ctx.paths.systemd_unit_dir(),
            disk,
            ctx.config.defaults.mount_backend,
            dry,
        )?;
        if !dry {
            let _ = std::fs::create_dir_all(&disk.mountpoint);
        }

        out.push(json!({
            "name": disk.name,
            "device": device,
            "enroll": enroll,
            "changes": changes,
        }));
    }

    Ok(json!({
        "ok": true,
        "dry_run": dry,
        "note": "TPM2 secrets are machine-bound; this re-enrolled the LOCAL TPM. \
                 The portable trust root is each disk's passphrase/recovery keyslot.",
        "disks": out,
    }))
}
