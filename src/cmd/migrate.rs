//! `tpmnt migrate` — on a NEW machine, re-enroll the LOCAL TPM for every
//! configured disk (TPM secrets are machine-bound and cannot move), then
//! recreate crypttab/fstab/units. Each disk is unlocked via its portable
//! passphrase/recovery keyslot ($PASSWORD).

use serde_json::{json, Value};

use crate::error::Result;
use crate::reconcile;

use super::Context;

pub fn run(ctx: &Context) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let mut out = Vec::new();

    for disk in &ctx.config.disks {
        let device = disk.device_path();

        // Re-enroll the local TPM using the portable passphrase keyslot.
        let enroll = super::enroll::enroll_device(ctx, &device, &disk.pcrs, disk.with_pin, || {
            std::env::var("PASSWORD").map_err(|_| {
                crate::error::Error::new(
                    crate::error::Code::ENoPassphrase,
                    format!(
                        "migrate needs the portable passphrase for {} via $PASSWORD",
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
