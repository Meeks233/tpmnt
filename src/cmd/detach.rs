//! `tpmnt detach <name>…` — hand a disk out of tpmnt into **manual mode**.
//!
//! Unlike `destroy` (retire the disk, delete the key so the data is gone) detach
//! *keeps the data usable*: you supply a new passphrase, tpmnt enrolls it as a
//! LUKS keyslot, then wipes its own TPM2 auto-unlock and removes all local
//! management. Afterwards the disk is no longer tpmnt's — you unlock it yourself
//! with that passphrase (optionally TPM2+PIN via `--with-pin`).
//!
//! The crypto is delegated to `systemd-cryptenroll` (never reimplemented): the
//! existing TPM2 token authorizes adding the new passphrase, so no old secret has
//! to be typed. Every step goes through `Runner`, so `--plan`/`--dry-run` show the
//! exact enrollment without touching the header.

use serde_json::{json, Value};

use crate::blockdev;
use crate::cli::DetachArgs;
use crate::config::Disk;
use crate::error::{Code, Error, Result};
use crate::power;

use super::offline::{detach as offline_detach, find_disk};
use super::Context;

pub fn run(ctx: &Context, args: &DetachArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let interactive = crate::tui::interactive(ctx.global.non_interactive);

    let targets = resolve_targets(ctx, &args.names, interactive)?;
    if targets.is_empty() {
        return Ok(json!({
            "ok": true, "action": "detach", "dry_run": dry,
            "detached": [], "note": "nothing selected",
        }));
    }
    let disks: Vec<Disk> = targets
        .iter()
        .map(|n| find_disk(ctx, n).cloned())
        .collect::<Result<_>>()?;

    // Confirmation — detach rewrites keyslots. --yes or an interactive y/N.
    let confirmed = ctx.global.yes
        || (interactive
            && crate::tui::confirm(&format!(
                "Detach {} disk(s) into manual mode: {} — enroll your passphrase, wipe tpmnt's \
                 TPM2 auto-unlock, drop management. Data is kept. Continue? [y/N] ",
                disks.len(),
                targets.join(", "),
            ))?);
    if !confirmed {
        return Err(Error::new(
            Code::EConfirmationRequired,
            format!("detach rewrites the keyslots of {} disk(s)", disks.len()),
        )
        .with_hint(
            "re-run with --yes to confirm; your data is kept, only the unlock method changes",
        ));
    }

    // The new manual passphrase the user will unlock with (shared across targets).
    let passphrase = resolve_passphrase(ctx, args)?;
    // The PIN for the new TPM2+PIN slot comes from $TPMNT_PIN or a prompt (same
    // source `enroll` uses for a new PIN).
    let pin = if args.with_pin {
        Some(crate::pin::resolve(None, ctx.global.non_interactive)?)
    } else {
        None
    };

    let mut detached = Vec::new();
    let mut port = args.local_port;
    for disk in &disks {
        let v = detach_one(ctx, disk, &passphrase, pin.as_deref(), args, port, dry)?;
        detached.push(v);
        if disk.remote.is_some() {
            port += 1;
        }
    }
    Ok(json!({
        "ok": true, "action": "detach", "dry_run": dry, "detached": detached,
    }))
}

/// Detach a single disk: enroll the user's passphrase, adjust the TPM2 slots per
/// flags, tear the mapping down, and purge tpmnt's local footprint (config, units,
/// key bundles) — leaving the LUKS data intact and unlockable by the passphrase.
fn detach_one(
    ctx: &Context,
    disk: &Disk,
    passphrase: &str,
    pin: Option<&str>,
    args: &DetachArgs,
    port: u16,
    dry: bool,
) -> Result<Value> {
    let op_device = reachable_ciphertext(ctx, disk, port, dry)?;

    let mut steps: Vec<Value> = Vec::new();

    // 1. Enroll the user's new passphrase, authorized by unsealing the existing
    //    TPM2 token (so no old secret has to be typed).
    ctx.runner
        .run_env(
            &argv_ref(&enroll_passphrase_argv(&op_device)),
            &[("NEWPASSWORD", passphrase)],
            "enroll manual passphrase (unlock via existing TPM2)",
        )?
        .require("systemd-cryptenroll --password")?;
    steps.push(json!({ "step": "enroll-passphrase", "slot": "password" }));

    // 2. TPM2 handling. Default: wipe tpmnt's auto-unlock so a manual passphrase is
    //    truly required. --with-pin: replace it with a TPM2+PIN slot (unlocked via
    //    the passphrase we just added). --keep-tpm: leave it as-is.
    if args.with_pin {
        ctx.runner
            .run(&argv_ref(&wipe_tpm2_argv(&op_device)), "wipe old TPM2 slot")?
            .require("systemd-cryptenroll --wipe-slot=tpm2")?;
        let pin = pin.unwrap_or_default();
        ctx.runner
            .run_env(
                &argv_ref(&enroll_tpm2_pin_argv(&op_device)),
                &[("PASSWORD", passphrase), ("NEWPIN", pin)],
                "enroll TPM2+PIN (unlock via the new passphrase)",
            )?
            .require("systemd-cryptenroll --tpm2-with-pin")?;
        steps.push(json!({ "step": "tpm2", "action": "replaced-with-pin" }));
    } else if !args.keep_tpm {
        ctx.runner
            .run(
                &argv_ref(&wipe_tpm2_argv(&op_device)),
                "wipe tpmnt TPM2 auto-unlock",
            )?
            .require("systemd-cryptenroll --wipe-slot=tpm2")?;
        steps.push(json!({ "step": "tpm2", "action": "wiped" }));
    } else {
        steps.push(json!({ "step": "tpm2", "action": "kept" }));
    }

    // 3. Bring the mapping down (grace unmount + close), then purge tpmnt's local
    //    footprint + config entry. The LUKS data and the user's passphrase remain.
    let detach_steps = offline_detach(ctx, disk, args.force)?;
    let mut result = super::destroy::purge_local_footprint(ctx, disk, dry)?;
    result["detach_steps"] = json!(detach_steps);
    result["enroll_steps"] = json!(steps);
    result["unlock"] = json!(if args.with_pin {
        "passphrase + TPM2-PIN"
    } else if args.keep_tpm {
        "passphrase or TPM2 (kept)"
    } else {
        "passphrase only"
    });
    Ok(result)
}

/// Ensure the disk's LUKS *ciphertext* is reachable here so `systemd-cryptenroll`
/// can rewrite the header locally: a local disk is its own device; a remote disk's
/// ciphertext is forwarded over NBD-over-SSH (reusing any live forward).
fn reachable_ciphertext(ctx: &Context, disk: &Disk, port: u16, dry: bool) -> Result<String> {
    let is_remote = !ctx.config.ssh_prefix_for(disk).is_empty();
    if !is_remote {
        return Ok(disk.device_path());
    }
    if power::forwarded_local_device(ctx, &disk.uuid).is_none() && !dry {
        let remote = blockdev::require_remote(ctx.config.remote_for(disk), &disk.name)?;
        blockdev::attach_nbd_over_ssh(&ctx.runner, remote, &disk.device_path(), port)?;
    }
    Ok(power::forwarded_local_device(ctx, &disk.uuid).unwrap_or_else(|| disk.device_path()))
}

// --- cryptenroll argv builders (pure, unit-tested) -------------------------

/// Enroll a new passphrase, unlocking the header via the existing TPM2 token.
/// The passphrase itself is supplied out-of-band via `$NEWPASSWORD`.
fn enroll_passphrase_argv(device: &str) -> Vec<String> {
    vec![
        "systemd-cryptenroll".into(),
        "--unlock-tpm2-device=auto".into(),
        "--password".into(),
        device.to_string(),
    ]
}

/// Wipe every TPM2 keyslot/token (tpmnt's auto-unlock).
fn wipe_tpm2_argv(device: &str) -> Vec<String> {
    vec![
        "systemd-cryptenroll".into(),
        "--wipe-slot=tpm2".into(),
        device.to_string(),
    ]
}

/// Enroll a fresh TPM2+PIN slot, unlocking via the just-added passphrase
/// (`$PASSWORD`); the new PIN comes from `$NEWPIN`.
fn enroll_tpm2_pin_argv(device: &str) -> Vec<String> {
    vec![
        "systemd-cryptenroll".into(),
        "--tpm2-device=auto".into(),
        "--tpm2-pcrs=".into(),
        "--tpm2-with-pin=yes".into(),
        device.to_string(),
    ]
}

fn argv_ref(argv: &[String]) -> Vec<&str> {
    argv.iter().map(|s| s.as_str()).collect()
}

/// Resolve the new manual passphrase: `--passphrase-file`, `--passphrase-stdin`,
/// `$PASSWORD`, then an interactive prompt (rejected under `--non-interactive`).
fn resolve_passphrase(ctx: &Context, args: &DetachArgs) -> Result<String> {
    if let Some(f) = &args.passphrase_file {
        let s = std::fs::read_to_string(f)
            .map_err(|e| Error::new(Code::ENoPassphrase, format!("read {}: {e}", f.display())))?;
        return Ok(s.trim_end_matches('\n').to_string());
    }
    if args.passphrase_stdin {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .map_err(|e| Error::new(Code::ENoPassphrase, format!("stdin: {e}")))?;
        return Ok(s.trim_end_matches('\n').to_string());
    }
    if let Ok(p) = std::env::var("PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    if ctx.global.non_interactive {
        return Err(Error::new(
            Code::ENoPassphrase,
            "no new passphrase provided".to_string(),
        )
        .with_hint("pass --passphrase-file/--passphrase-stdin or set $PASSWORD"));
    }
    let p = crate::tui::prompt_line("New manual passphrase for the detached disk: ")?;
    if p.is_empty() {
        return Err(Error::new(
            Code::ENoPassphrase,
            "empty passphrase".to_string(),
        ));
    }
    Ok(p)
}

/// Resolve detach target disk names: explicit CLI names, or an interactive
/// multi-select over the managed (enabled) disks.
fn resolve_targets(ctx: &Context, names: &[String], interactive: bool) -> Result<Vec<String>> {
    if !names.is_empty() {
        return Ok(names.to_vec());
    }
    if !interactive {
        return Err(
            Error::new(Code::EConfig, "no disk named to detach".to_string()).with_hint(
                "name the disk(s) to detach, or run in an interactive terminal to multi-select",
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
    let chosen = crate::tui::multiselect("Select disk(s) to detach into manual mode:", &items)?;
    Ok(chosen
        .into_iter()
        .map(|i| ctx.config.disks[i].name.clone())
        .collect())
}

/// Human rendering: one line per detached disk with its resulting unlock method.
pub fn render(value: &Value) -> String {
    let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
    let mut out = String::new();
    out.push_str(if dry {
        "detach (dry-run):\n"
    } else {
        "detach:\n"
    });
    match value.get("detached").and_then(|v| v.as_array()) {
        Some(ds) if !ds.is_empty() => {
            for d in ds {
                let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let unlock = d.get("unlock").and_then(|v| v.as_str()).unwrap_or("?");
                out.push_str(&format!(
                    "  ✓ {name}: detached to manual mode — unlock: {unlock} (data kept)\n"
                ));
            }
        }
        _ => {
            let note = value
                .get("note")
                .and_then(|v| v.as_str())
                .unwrap_or("nothing detached");
            out.push_str(&format!("  ({note})\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_passphrase_unlocks_via_tpm2() {
        let a = enroll_passphrase_argv("/dev/sda");
        assert_eq!(
            a,
            vec![
                "systemd-cryptenroll",
                "--unlock-tpm2-device=auto",
                "--password",
                "/dev/sda"
            ]
        );
    }

    #[test]
    fn wipe_and_pin_argv_are_well_formed() {
        assert_eq!(
            wipe_tpm2_argv("/dev/nbd0"),
            vec!["systemd-cryptenroll", "--wipe-slot=tpm2", "/dev/nbd0"]
        );
        let p = enroll_tpm2_pin_argv("/dev/sdb");
        assert_eq!(p.first().unwrap(), "systemd-cryptenroll");
        assert!(p.iter().any(|s| s == "--tpm2-with-pin=yes"));
        assert!(p.iter().any(|s| s == "--tpm2-device=auto"));
        assert_eq!(p.last().unwrap(), "/dev/sdb");
    }
}
