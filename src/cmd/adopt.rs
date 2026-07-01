//! `tpmnt adopt <name…>` — take ownership of an existing disk so tpmnt truly
//! *manages* it under the threat model in `manage.rs`.
//!
//! You supply the disk's current ("old") key once. tpmnt then, entirely on THIS
//! host:
//!   1. forwards the disk's ciphertext here if it is remote (NBD-over-SSH), so
//!      every crypto step runs locally and the key never touches the remote;
//!   2. generates a fresh, unified random managed key (+ recovery key) and adds
//!      them to the LUKS2 header, authenticating with the old key;
//!   3. enrolls this host's TPM2 for auto-unlock;
//!   4. seals the new key bundle into the local key store (the provenance record
//!      that makes the disk "managed");
//!   5. optionally removes the old key (`--rotate-out-old`) so only tpmnt-owned
//!      keys remain;
//!   6. records `transport` for a remote disk so `status` reflects the new posture.
//!
//! After adopt, `tpmnt status` reports the disk as `managed`: locally-generated
//! key, decryption on this host only.

use std::io::Read;
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::blockdev::{self, Attachment};
use crate::cli::AdoptArgs;
use crate::config::Transport;
use crate::error::{err, Code, Error, Result};
use crate::keystore::{self, SecureDir};
use crate::luks;
use crate::manage;
use crate::secret;

use super::Context;

pub fn run(ctx: &Context, args: &AdoptArgs) -> Result<Value> {
    if args.names.is_empty() {
        return err(Code::EConfig, "adopt needs at least one disk name");
    }
    let transport = match &args.transport {
        Some(s) => Transport::parse(s)
            .ok_or_else(|| Error::new(Code::EConfig, format!("invalid --transport: {s:?}")))?,
        None => Transport::default(),
    };
    let old_key = read_old_key(ctx, args)?;

    let mut results = Vec::new();
    let mut config_dirty = false;
    let mut cfg = ctx.config.clone();

    for name in &args.names {
        let idx = cfg
            .disks
            .iter()
            .position(|d| &d.name == name)
            .ok_or_else(|| {
                Error::new(Code::EConfig, format!("no [[disk]] named {name:?}"))
                    .with_hint("adopt operates on already-configured disks; run `tpmnt status`")
            })?;

        // Snapshot the fields we need before borrowing cfg mutably later.
        let disk = cfg.disks[idx].clone();
        let already = manage::classify(&cfg, &disk);
        if already.managed {
            results.push(json!({
                "name": name, "action": "noop", "reason": "already managed",
                "management": already,
            }));
            continue;
        }

        let (res, set_transport) = adopt_one(ctx, &cfg, &disk, &old_key, transport, args)?;
        results.push(res);
        if let Some(t) = set_transport {
            cfg.disks[idx].transport = Some(t);
            config_dirty = true;
        }
    }

    if config_dirty && !ctx.global.effective_dry_run() {
        cfg.save(&ctx.global.config)?;
    }

    Ok(json!({
        "ok": true,
        "dry_run": ctx.global.effective_dry_run(),
        "adopted": results,
    }))
}

/// Adopt a single disk. Returns its JSON result and, for a remote disk, the
/// transport to persist into config.
fn adopt_one(
    ctx: &Context,
    cfg: &crate::config::Config,
    disk: &crate::config::Disk,
    old_key: &str,
    transport: Transport,
    args: &AdoptArgs,
) -> Result<(Value, Option<Transport>)> {
    let is_remote = disk.remote.is_some();

    // 1. Obtain the ciphertext as a LOCAL block device. Local disks are already
    //    local; remote disks are forwarded here via NBD-over-SSH so all crypto
    //    runs on this host.
    let att: Attachment = if is_remote {
        let remote = blockdev::require_remote(cfg.remote_for(disk), &disk.name)?;
        blockdev::attach_nbd_over_ssh(&ctx.runner, remote, &disk.device_path(), args.local_port)?
    } else {
        Attachment::local(&disk.device_path())
    };

    // Run the mutation, always detaching the forwarded ciphertext afterward.
    let outcome = adopt_on_device(ctx, disk, &att, old_key, args);
    blockdev::detach(&ctx.runner, &att)?;
    let out = outcome?;

    let set_transport = if is_remote { Some(transport) } else { None };
    let mut result = out;
    result["name"] = json!(disk.name);
    result["remote"] = json!(disk.remote);
    result["forwarded_via"] = json!(if is_remote { "nbd-over-ssh" } else { "local" });
    if is_remote {
        result["transport"] = json!(transport.as_str());
    }
    Ok((result, set_transport))
}

/// The on-device crypto: add the managed key + recovery, TPM-enroll, seal, and
/// optionally remove the old key. `device` is always local at this point.
fn adopt_on_device(
    ctx: &Context,
    disk: &crate::config::Disk,
    att: &Attachment,
    old_key: &str,
    args: &AdoptArgs,
) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let device = &att.local_device;

    // Verify it is LUKS2 (skip when a forwarded device isn't materialized under
    // dry-run — nothing was actually attached, so we only plan).
    let inspectable = std::path::Path::new(device).exists();
    if inspectable {
        let info = luks::inspect(&ctx.runner, device)?;
        luks::require_luks2(&info, device)?;
    } else if !dry {
        return Err(
            Error::new(Code::ENoDevice, format!("device not present: {device}"))
                .with_hint("the ciphertext forwarding did not produce a local block device"),
        );
    }

    // Key material. Under dry-run we don't touch a real SecureDir; argv still
    // records the intended `--key-file` paths for `--plan`.
    let secure = if dry { None } else { Some(SecureDir::new()?) };
    let new_pass = secret::generate_passphrase(&args.key_format)?;

    let (old_kf, new_kf) = match &secure {
        Some(sd) => (
            sd.write_key("old", old_key)?,
            sd.write_key("new", &new_pass)?,
        ),
        None => (PathBuf::from("<old-key>"), PathBuf::from("<new-key>")),
    };

    // 2. Add the managed key, authenticating with the old key.
    ctx.runner
        .run(
            &[
                "cryptsetup",
                "luksAddKey",
                device,
                &new_kf.to_string_lossy(),
                "--key-file",
                &old_kf.to_string_lossy(),
                "--batch-mode",
            ],
            "add unified managed key (authenticated by the old key)",
        )?
        .require("luksAddKey (managed)")?;

    // Recovery key (default on) — authenticated by the new managed key.
    let mut recovery_key: Option<String> = None;
    if !args.no_recovery_key {
        let rk = secret::generate_recovery_key()?;
        let rk_kf = match &secure {
            Some(sd) => sd.write_key("recovery", &rk)?,
            None => PathBuf::from("<recovery-key>"),
        };
        ctx.runner
            .run(
                &[
                    "cryptsetup",
                    "luksAddKey",
                    device,
                    &rk_kf.to_string_lossy(),
                    "--key-file",
                    &new_kf.to_string_lossy(),
                    "--batch-mode",
                ],
                "add recovery-key keyslot",
            )?
            .require("luksAddKey (recovery)")?;
        recovery_key = Some(rk);
    } else if !args.i_understand_no_recovery {
        return err(
            Code::EBackupRefused,
            "--no-recovery-key requires --i-understand-no-recovery",
        );
    }

    // 3. Enroll this host's TPM2 (runs locally; key stays local).
    let mut tpm_token = false;
    if !args.no_tpm && inspectable {
        let pcrs = super::enroll::parse_pcrs(args.pcrs.as_deref())?;
        let pass = new_pass.clone();
        let enroll = super::enroll::enroll_device(ctx, device, &pcrs, args.with_pin, || Ok(pass))?;
        tpm_token = enroll
            .get("tpm2_token_present")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    } else if !args.no_tpm {
        tpm_token = true; // planned under dry-run
    }

    // 4. Seal the new bundle locally — the provenance record that flips the disk
    //    to "managed". This must succeed before we consider removing the old key.
    let uuid = if inspectable && !dry {
        luks::inspect(&ctx.runner, device)?
            .uuid
            .unwrap_or_else(|| disk.uuid.clone())
    } else {
        disk.uuid.clone()
    };
    let bundle = json!({
        "tpmnt_key_bundle": 1,
        "name": disk.name,
        "adopted": true,
        "device": disk.device_path(),
        "luks_uuid": uuid,
        "mapper": disk.mapper_name(),
        "mountpoint": disk.mountpoint,
        "passphrase": new_pass,
        "recovery_key": recovery_key,
    });
    let bundle_json = serde_json::to_string_pretty(&bundle).unwrap();
    let dir = &ctx.config.defaults.key_backup;
    let bundle_location = if args.local_plaintext {
        if !args.i_understand_plaintext_keys {
            return err(
                Code::EBackupRefused,
                "--local-plaintext requires --i-understand-plaintext-keys",
            );
        }
        let path = dir.join(format!("{}.json", disk.name));
        if !dry {
            std::fs::create_dir_all(dir)
                .map_err(|e| Error::new(Code::EEscrowFailed, format!("mkdir key_backup: {e}")))?;
            std::fs::write(&path, &bundle_json)
                .map_err(|e| Error::new(Code::EEscrowFailed, format!("write bundle: {e}")))?;
        }
        json!({ "type": "plaintext", "path": path })
    } else {
        let path = keystore::seal(&ctx.runner, dir, &disk.name, bundle_json.as_bytes(), dry)?;
        json!({ "type": "sealed", "path": path })
    };

    // 5. Optionally rotate OUT the old key so only managed keys remain.
    let mut old_removed = false;
    if args.rotate_out_old {
        ctx.runner
            .run(
                &[
                    "cryptsetup",
                    "luksRemoveKey",
                    device,
                    &old_kf.to_string_lossy(),
                    "--batch-mode",
                ],
                "remove the old (now-superseded) key",
            )?
            .require("luksRemoveKey (old)")?;
        old_removed = true;
    }

    let mut result = json!({
        "action": "adopted",
        "device": device,
        "luks_uuid": uuid,
        "tpm2_token": tpm_token,
        "recovery_key_added": recovery_key.is_some(),
        "old_key_removed": old_removed,
        "bundle": bundle_location,
    });
    if args.emit_secrets && ctx.global.json {
        result["secrets"] = json!({
            "passphrase": new_pass,
            "recovery_key": recovery_key,
        });
    }
    Ok(result)
}

/// Read the disk's current key from --old-key-file, --old-key-stdin, $OLD_PASSWORD,
/// or an interactive prompt (never in --non-interactive without a source).
fn read_old_key(ctx: &Context, args: &AdoptArgs) -> Result<String> {
    if args.old_key_stdin {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| Error::new(Code::ENoPassphrase, format!("read stdin: {e}")))?;
        return Ok(s.trim_end_matches('\n').to_string());
    }
    if let Some(p) = &args.old_key_file {
        let s = std::fs::read_to_string(p)
            .map_err(|e| Error::new(Code::ENoPassphrase, format!("read {}: {e}", p.display())))?;
        return Ok(s.trim_end_matches('\n').to_string());
    }
    if let Ok(p) = std::env::var("OLD_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    if ctx.global.non_interactive {
        return err(
            Code::ENoPassphrase,
            "no old key: pass --old-key-file / --old-key-stdin or set $OLD_PASSWORD",
        );
    }
    eprint!("Enter the disk's CURRENT (old) LUKS key: ");
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Error::new(Code::ENoPassphrase, format!("stdin: {e}")))?;
    Ok(line.trim_end_matches('\n').to_string())
}

/// Human rendering for `adopt` (JSON stays the machine contract).
pub fn render(value: &Value) -> String {
    let mut out = String::new();
    let dry = value
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    out.push_str(if dry {
        "adopt (dry-run):\n"
    } else {
        "adopt:\n"
    });
    if let Some(arr) = value.get("adopted").and_then(|v| v.as_array()) {
        for d in arr {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let action = d.get("action").and_then(|v| v.as_str()).unwrap_or("?");
            if action == "noop" {
                out.push_str(&format!("  {name}: already managed (no change)\n"));
                continue;
            }
            let tpm = d
                .get("tpm2_token")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let rec = d
                .get("recovery_key_added")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let rot = d
                .get("old_key_removed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let via = d
                .get("forwarded_via")
                .and_then(|v| v.as_str())
                .unwrap_or("local");
            out.push_str(&format!(
                "  {name}: managed key added{}{}{}  (via {via})\n",
                if tpm { " + TPM2" } else { "" },
                if rec { " + recovery" } else { "" },
                if rot {
                    " · old key removed"
                } else {
                    " · old key kept"
                },
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_summarizes_adopted_and_noop_disks() {
        let v = json!({
            "dry_run": false,
            "adopted": [
                {
                    "name": "far", "action": "adopted", "tpm2_token": true,
                    "recovery_key_added": true, "old_key_removed": true,
                    "forwarded_via": "nbd-over-ssh"
                },
                { "name": "already", "action": "noop", "reason": "already managed" }
            ]
        });
        let out = render(&v);
        assert!(out.contains("far: managed key added + TPM2 + recovery · old key removed"));
        assert!(out.contains("via nbd-over-ssh"));
        assert!(out.contains("already: already managed"));
    }

    #[test]
    fn render_marks_kept_old_key_and_local_path() {
        let v = json!({
            "dry_run": true,
            "adopted": [{
                "name": "l", "action": "adopted", "tpm2_token": false,
                "recovery_key_added": true, "old_key_removed": false,
                "forwarded_via": "local"
            }]
        });
        let out = render(&v);
        assert!(out.contains("adopt (dry-run)"));
        assert!(out.contains("old key kept"));
        assert!(out.contains("(via local)"));
        assert!(!out.contains("+ TPM2"));
    }
}
