//! `tpmnt migrate` — on a NEW machine, re-enroll the LOCAL TPM for every
//! configured disk (TPM secrets are machine-bound and cannot move), then
//! recreate crypttab/fstab/units. Each disk is unlocked via its portable
//! passphrase/recovery keyslot ($PASSWORD).

use serde_json::{json, Value};

use crate::cli::MigrateArgs;
use crate::error::Result;
use crate::{pin, reconcile, vault};

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

    for disk in &ctx.config.disks {
        let device = disk.device_path();

        // Re-enroll the local TPM using the portable passphrase keyslot, sourced
        // from the vault when available, else $PASSWORD.
        let enroll =
            super::enroll::enroll_device(ctx, &device, &disk.pcrs, disk.with_pin, false, || {
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
