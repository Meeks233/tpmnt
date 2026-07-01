//! `tpmnt pin enable|disable …` — the *post-encryption* entry point for a
//! mandatory unlock PIN.
//!
//! Enabling a PIN is not init-only: `systemd-cryptenroll` can re-enroll an
//! existing LUKS2 TPM2 token at any time. To add (or remove) a PIN we wipe the
//! current TPM2 slot and enroll a fresh one, authorized by the disk's managed
//! passphrase (retrieved from the local sealed bundle — no PIN needed for that,
//! since it's TPM/host-sealed). We then flip `disk.with_pin`, reconcile crypttab
//! so systemd knows to ask for the PIN (`tpm2-pin=yes`), and — on enable — drop
//! the key into the unified PIN vault for TPM-independent recovery.
//!
//! Scope mirrors the two things a user/AI wants to say: "this disk" (a name),
//! "every disk" (`--all`), or "every disk, and make it policy" (`--global`, which
//! also sets/clears `[defaults].require_pin` so future disks follow suit).
//!
//! Remote managed disks are handled the same way: their ciphertext is forwarded
//! here (NBD-over-SSH) so the header re-enrollment runs locally, exactly like
//! `adopt` — the key never touches the remote.

use std::path::Path;

use serde_json::{json, Value};

use crate::blockdev::{self, Attachment};
use crate::cli::{PinAction, PinArgs, PinScope};
use crate::config::Config;
use crate::error::{err, Code, Error, Result};
use crate::{keystore, manage, pin, reconcile, vault};

use super::Context;

pub fn run(ctx: &Context, args: &PinArgs) -> Result<Value> {
    let (enable, scope) = match &args.action {
        PinAction::Enable(s) => (true, s),
        PinAction::Disable(s) => (false, s),
    };
    let dry = ctx.global.effective_dry_run();
    let mut cfg = ctx.config.clone();

    // Which disks: a single name, or every managed disk (--all / --global).
    let targets = select_targets(&cfg, scope)?;

    // For `enable`, resolve the PIN once (the same PIN gates the TPM and encrypts
    // the vault). `disable` needs no PIN.
    let new_pin = if enable {
        let p = pin::resolve(scope.pin_file.as_deref(), ctx.global.non_interactive)?;
        std::env::set_var("TPMNT_PIN", &p);
        Some(p)
    } else {
        None
    };

    let mut results = Vec::new();
    for idx in targets {
        let res = set_pin_one(ctx, &mut cfg, idx, enable, new_pin.as_deref(), scope, dry)?;
        results.push(res);
    }

    // Persist config: with_pin flips, plus the require_pin policy for --global.
    if scope.global {
        cfg.defaults.require_pin = enable;
    }
    if !dry {
        cfg.save(&ctx.global.config)?;
    }

    Ok(json!({
        "ok": true,
        "action": if enable { "pin-enable" } else { "pin-disable" },
        "dry_run": dry,
        "require_pin": cfg.defaults.require_pin,
        "global": scope.global,
        "disks": results,
    }))
}

/// Resolve the set of disk indices to act on. A managed disk is required (we need
/// its local key + local decryption to re-enroll its TPM here).
fn select_targets(cfg: &Config, scope: &PinScope) -> Result<Vec<usize>> {
    if scope.all || scope.global {
        let idxs: Vec<usize> = cfg
            .disks
            .iter()
            .enumerate()
            .filter(|(_, d)| manage::classify(cfg, d).managed)
            .map(|(i, _)| i)
            .collect();
        if idxs.is_empty() {
            return err(
                Code::EConfig,
                "no managed disks to act on (run `tpmnt adopt` first)",
            );
        }
        return Ok(idxs);
    }
    let name = scope.name.as_deref().ok_or_else(|| {
        Error::new(Code::EConfig, "pin needs a disk name (or --all / --global)")
            .with_hint("e.g. `tpmnt pin enable arc` or `tpmnt pin enable --global`")
    })?;
    let idx = cfg
        .disks
        .iter()
        .position(|d| d.name == name)
        .ok_or_else(|| Error::new(Code::EConfig, format!("no [[disk]] named {name:?}")))?;
    let m = manage::classify(cfg, &cfg.disks[idx]);
    if !m.managed {
        return Err(Error::new(
            Code::EConfig,
            format!("disk {name:?} is not managed ({})", m.reason),
        )
        .with_hint("run `tpmnt adopt` to take ownership before setting a PIN"));
    }
    Ok(vec![idx])
}

/// Enable/disable the PIN on one disk: re-enroll its TPM2 token, flip `with_pin`,
/// reconcile crypttab, and (on enable) refresh the vault entry.
fn set_pin_one(
    ctx: &Context,
    cfg: &mut Config,
    idx: usize,
    enable: bool,
    new_pin: Option<&str>,
    scope: &PinScope,
    dry: bool,
) -> Result<Value> {
    let disk = cfg.disks[idx].clone();

    // The managed key bundle (from the TPM-sealed .cred / cleartext bundle) both
    // authorizes the re-enroll and is what we store in the vault.
    let bundle = managed_bundle(ctx, &disk.name)?;
    let passphrase = bundle
        .get("passphrase")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::new(
                Code::EEscrowFailed,
                format!("no usable passphrase in {}'s key bundle", disk.name),
            )
        })?
        .to_string();

    // Get the ciphertext as a LOCAL block device (forward a remote disk's blocks).
    let (op_device, attachment) = resolve_op_device(ctx, cfg, &disk, scope.local_port)?;

    // Only touch the header when there's a real device to inspect. Under dry-run
    // (or a forwarded device that isn't actually attached) we record intent
    // without failing the LUKS2 probe (mirrors `adopt`).
    let inspectable = !dry && Path::new(&op_device).exists();
    let enroll_res = if inspectable {
        let pass = passphrase.clone();
        super::enroll::enroll_device(ctx, &op_device, &disk.pcrs, enable, true, || Ok(pass))
    } else {
        Ok(json!({ "action": "planned", "with_pin": enable }))
    };

    // Always tear down a forward we created, success or failure.
    if let Some(att) = &attachment {
        blockdev::detach(&ctx.runner, att)?;
    }
    let enroll = enroll_res?;

    // Flip the stored policy for this disk.
    cfg.disks[idx].with_pin = enable;

    // Reconcile crypttab/fstab so `tpm2-pin=yes` is added/removed to match.
    let changes = reconcile::reconcile_disk(
        &ctx.paths.crypttab(),
        &ctx.paths.fstab(),
        &ctx.paths.systemd_unit_dir(),
        &cfg.disks[idx],
        cfg.defaults.mount_backend,
        dry,
    )?;

    // On enable, ensure the key is in the unified PIN vault for recovery.
    let mut vault_written = Value::Null;
    if enable {
        if let Some(pinv) = new_pin {
            let path = vault::upsert(
                &ctx.runner,
                &cfg.defaults.key_backup,
                pinv,
                &disk.name,
                &bundle,
                dry,
            )?;
            vault_written = json!({ "type": "vault", "path": path });
        }
    }

    Ok(json!({
        "name": disk.name,
        "with_pin": enable,
        "remote": disk.remote,
        "op_device": op_device,
        "enroll": enroll,
        "vault": vault_written,
        "changes": changes,
    }))
}

/// Load the disk's managed key bundle from the local store: the TPM-sealed
/// `<name>.cred` first, then the opt-in cleartext `<name>.json`. This is the
/// provenance that makes the disk "managed"; it needs no PIN to read (the seal is
/// TPM/host-bound), which is exactly why it can authorize *adding* a PIN.
fn managed_bundle(ctx: &Context, name: &str) -> Result<Value> {
    let dir = &ctx.config.defaults.key_backup;
    let sealed = keystore::sealed_path(dir, name);
    if sealed.exists() {
        let text = keystore::unseal(&ctx.runner, &sealed, name)?;
        return parse_bundle(&text);
    }
    let plain = dir.join(format!("{name}.json"));
    if plain.exists() {
        let text = std::fs::read_to_string(&plain).map_err(|e| {
            Error::new(
                Code::EEscrowFailed,
                format!("read {}: {e}", plain.display()),
            )
        })?;
        return parse_bundle(&text);
    }
    Err(
        Error::new(Code::EEscrowFailed, format!("no key bundle for {name:?}"))
            .with_hint("this disk has no local managed key; run `tpmnt adopt`"),
    )
}

fn parse_bundle(text: &str) -> Result<Value> {
    serde_json::from_str(text)
        .map_err(|e| Error::new(Code::EInternal, format!("parse key bundle: {e}")))
}

/// Produce a LOCAL ciphertext device to re-enroll against. If the mapping is
/// already open, reuse its backing device (no new forward). Otherwise forward a
/// remote disk's ciphertext (NBD-over-SSH), or use a local disk's device directly.
fn resolve_op_device(
    ctx: &Context,
    cfg: &Config,
    disk: &crate::config::Disk,
    local_port: u16,
) -> Result<(String, Option<Attachment>)> {
    let mapper = disk.mapper_name();
    if Path::new(&format!("/dev/mapper/{mapper}")).exists() {
        if let Some(backing) = mapper_backing_device(ctx, &mapper) {
            return Ok((backing, None));
        }
    }
    if disk.remote.is_some() {
        let remote = blockdev::require_remote(cfg.remote_for(disk), &disk.name)?;
        let att =
            blockdev::attach_nbd_over_ssh(&ctx.runner, remote, &disk.device_path(), local_port)?;
        let dev = att.local_device.clone();
        return Ok((dev, Some(att)));
    }
    Ok((disk.device_path(), None))
}

/// The backing (ciphertext) device of an open mapper, via `cryptsetup status`.
fn mapper_backing_device(ctx: &Context, mapper: &str) -> Option<String> {
    let out = ctx
        .runner
        .probe(
            &["cryptsetup", "status", mapper],
            "resolve mapper backing device",
        )
        .ok()?;
    if !out.ok() {
        return None;
    }
    out.stdout.lines().find_map(|l| {
        l.trim()
            .strip_prefix("device:")
            .map(|d| d.trim().to_string())
    })
}

/// Human rendering (JSON stays the machine contract).
pub fn render(value: &Value) -> String {
    let mut out = String::new();
    let action = value.get("action").and_then(|v| v.as_str()).unwrap_or("?");
    let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
    let verb = if action == "pin-enable" {
        "enable PIN"
    } else {
        "disable PIN"
    };
    out.push_str(&format!("{verb}{}:\n", if dry { " (dry-run)" } else { "" }));
    if let Some(ds) = value.get("disks").and_then(|v| v.as_array()) {
        for d in ds {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let with_pin = d.get("with_pin").and_then(|v| v.as_bool()) == Some(true);
            let vault = d.get("vault").map(|v| !v.is_null()).unwrap_or(false);
            out.push_str(&format!(
                "  {name}: TPM2 re-enrolled ({}){}\n",
                if with_pin { "with PIN" } else { "no PIN" },
                if vault { " · key in vault" } else { "" },
            ));
        }
    }
    if value.get("global").and_then(|v| v.as_bool()) == Some(true) {
        let rp = value.get("require_pin").and_then(|v| v.as_bool()) == Some(true);
        out.push_str(&format!(
            "  policy: [defaults].require_pin = {rp} (applies to future disks)\n"
        ));
    }
    out.push_str(
        "  note: for a ROOT disk, rebuild the initramfs so the PIN prompt applies at boot.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_enable_lists_disks_and_policy() {
        let v = json!({
            "action": "pin-enable", "dry_run": false, "global": true,
            "require_pin": true,
            "disks": [
                { "name": "arc", "with_pin": true, "vault": { "type": "vault" } },
                { "name": "cold", "with_pin": true, "vault": null }
            ]
        });
        let out = render(&v);
        assert!(out.contains("enable PIN:"));
        assert!(out.contains("arc: TPM2 re-enrolled (with PIN) · key in vault"));
        assert!(out.contains("cold: TPM2 re-enrolled (with PIN)"));
        assert!(out.contains("require_pin = true"));
    }

    #[test]
    fn render_disable_reads_no_pin() {
        let v = json!({
            "action": "pin-disable", "dry_run": true, "global": false,
            "disks": [ { "name": "arc", "with_pin": false, "vault": null } ]
        });
        let out = render(&v);
        assert!(out.contains("disable PIN (dry-run)"));
        assert!(out.contains("arc: TPM2 re-enrolled (no PIN)"));
    }
}
