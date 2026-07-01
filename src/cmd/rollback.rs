//! `tpmnt rollback <device>` — restore the backed-up LUKS2 header and revert
//! the crypttab/fstab/unit edits tpmnt made for the disk(s) on that device.

use serde_json::{json, Value};

use crate::cli::RollbackArgs;
use crate::error::{Code, Error, Result};
use crate::luks;
use crate::reconcile;

use super::Context;

pub fn run(ctx: &Context, args: &RollbackArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let info = luks::inspect(&ctx.runner, &args.device)?;
    let uuid = info.uuid.clone().ok_or_else(|| {
        Error::new(
            Code::ENotLuks2,
            format!("{} is not a LUKS device", args.device),
        )
    })?;

    let backup = ctx.paths.header_backup(&uuid);
    if !backup.exists() {
        return Err(Error::new(
            Code::ENoBackup,
            format!(
                "no header backup for {} at {}",
                args.device,
                backup.display()
            ),
        )
        .with_hint("rollback can only restore headers tpmnt previously backed up"));
    }

    // Safety: back up the CURRENT on-disk header before restoring over it, so the
    // rollback itself is reversible (restore the wrong backup? the live header is
    // saved at <backup>.pre-restore). Overwrites any prior pre-restore snapshot.
    let pre_restore = std::path::PathBuf::from(format!("{}.pre-restore", backup.display()));
    luks::header_backup_force(&ctx.runner, &args.device, &pre_restore)?;

    // Restore the header.
    ctx.runner
        .run(
            &[
                "cryptsetup",
                "luksHeaderRestore",
                &args.device,
                "--header-backup-file",
                &backup.to_string_lossy(),
                "-q",
            ],
            "restore LUKS2 header from backup",
        )?
        .require("luksHeaderRestore")?;

    // Revert config edits for any disk matching this UUID.
    let mut reverted = Vec::new();
    for disk in ctx.config.disks.iter().filter(|d| d.uuid == uuid) {
        let c = reconcile::remove_tagged_line(&ctx.paths.crypttab(), &disk.name, dry)?;
        let f = reconcile::remove_tagged_line(&ctx.paths.fstab(), &disk.name, dry)?;
        reverted.push(json!({ "name": disk.name, "crypttab": c, "fstab": f }));
    }

    Ok(json!({
        "ok": true,
        "dry_run": dry,
        "device": args.device,
        "uuid": uuid,
        "header_restored_from": backup.display().to_string(),
        "prior_header_saved_to": pre_restore.display().to_string(),
        "reverted": reverted,
    }))
}
