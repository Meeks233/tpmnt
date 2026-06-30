//! `tpmnt apply` — idempotently reconcile the local system to the config:
//! ensure each disk has a TPM2 token, then write crypttab + the mount backend.

use serde_json::{json, Value};

use crate::error::Result;
use crate::luks;
use crate::power;
use crate::reconcile;

use super::Context;

pub fn run(ctx: &Context) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let mut disks_out = Vec::new();

    // Root-disk warning for Debian/Ubuntu initramfs-tools.
    if ctx.env.initramfs_warns_for_root() {
        eprintln!(
            "warning: initramfs-tools ignores tpm2-device for ROOT disks; \
             data disks unlock post-boot via crypttab regardless. Use dracut for root."
        );
    }

    for disk in &ctx.config.disks {
        let device = disk.device_path();
        let mut disk_warnings: Vec<String> = Vec::new();
        let mut token_action = "unchanged";

        // Ensure a TPM2 token if the device is reachable.
        match luks::inspect(&ctx.runner, &device) {
            Ok(info) if info.is_luks2 => {
                if !info.has_tpm2_token() {
                    // Try to enroll using $PASSWORD if available; otherwise warn.
                    let has_pw = std::env::var("PASSWORD")
                        .map(|p| !p.is_empty())
                        .unwrap_or(false);
                    if has_pw {
                        super::enroll::enroll_device(
                            ctx,
                            &device,
                            &disk.pcrs,
                            disk.with_pin,
                            || Ok(std::env::var("PASSWORD").unwrap_or_default()),
                        )?;
                        token_action = "enrolled";
                    } else {
                        disk_warnings.push(
                            "no TPM2 token and no $PASSWORD available; run `tpmnt enroll` first"
                                .to_string(),
                        );
                    }
                }
            }
            Ok(_) => disk_warnings.push(format!("{device} is not LUKS2; skipping enrollment")),
            Err(e) => disk_warnings.push(format!("cannot inspect {device}: {e}")),
        }

        // Reconcile crypttab + mount backend.
        let changes = reconcile::reconcile_disk(
            &ctx.paths.crypttab(),
            &ctx.paths.fstab(),
            &ctx.paths.systemd_unit_dir(),
            disk,
            ctx.config.defaults.mount_backend,
            dry,
        )?;

        // Reconcile the cold-standby idle-monitor unit (written for cold-standby,
        // removed for always-on).
        let monitor_change =
            power::reconcile_monitor_unit(ctx, &ctx.paths.systemd_unit_dir(), disk, dry)?;

        // Reconcile the schedule unit (written when a [disk.schedule] is set).
        let schedule_change =
            power::reconcile_schedule_unit(ctx, &ctx.paths.systemd_unit_dir(), disk, dry)?;

        // Ensure the mountpoint directory exists (not a mount; just the dir).
        if !dry {
            let _ = std::fs::create_dir_all(&disk.mountpoint);
        }

        for w in &disk_warnings {
            eprintln!("warning [{}]: {w}", disk.name);
        }

        disks_out.push(json!({
            "name": disk.name,
            "device": device,
            "mountpoint": disk.mountpoint,
            "token": token_action,
            "power_profile": disk.power_profile,
            "idle_timeout_secs": disk.idle_timeout_secs(),
            "monitor_unit": monitor_change,
            "schedule_unit": schedule_change,
            "changes": changes,
            "warnings": disk_warnings,
        }));
    }

    Ok(json!({
        "ok": true,
        "dry_run": dry,
        "mount_backend": ctx.config.defaults.mount_backend,
        "disks": disks_out,
    }))
}
