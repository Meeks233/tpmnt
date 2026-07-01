//! `tpmnt recover <name>` — authenticated retrieval of a disk's generated key,
//! and (optionally) a manual LUKS open for when TPM2 auto-unlock is broken.
//!
//! Auth model: the default source is the host-sealed `<name>.cred` bundle.
//! Decrypting it requires root and this host's TPM/host-key (enforced by
//! systemd-creds), so retrieval is already gated. Revealing plaintext or
//! touching the mapping additionally requires an explicit `--show` / `--open`
//! so a key can't leak into scrollback or be opened by accident. No TPM PIN is
//! needed even for `with_pin` disks: recovery uses the stored *passphrase*,
//! which opens the LUKS keyslot directly, independent of the TPM token.

use std::path::PathBuf;

use serde_json::{json, Value};

use crate::cli::RecoverArgs;
use crate::error::{Code, Error, Result};
use crate::keystore::{self, SecureDir};

use super::Context;

pub fn run(ctx: &Context, args: &RecoverArgs) -> Result<Value> {
    let disk = ctx
        .config
        .disks
        .iter()
        .find(|d| d.name == args.name)
        .ok_or_else(|| {
            Error::new(
                Code::EConfig,
                format!("no disk named {:?} in config", args.name),
            )
            .with_hint("run `tpmnt status` to list configured disks")
        })?;

    // Resolve the bundle source: default is the sealed local .cred.
    let dir = &ctx.config.defaults.key_backup;
    let (kind, path) = match &args.from {
        Some(spec) => {
            let (k, p) = spec.split_once(':').ok_or_else(|| {
                Error::new(Code::EConfig, format!("bad --from spec: {spec:?}"))
                    .with_hint("use creds:<file> or plaintext:<file>")
            })?;
            (k.to_string(), PathBuf::from(p))
        }
        None => ("creds".to_string(), keystore::sealed_path(dir, &disk.name)),
    };

    let bundle_json = match kind.as_str() {
        "creds" => {
            if !path.exists() {
                return Err(Error::new(
                    Code::EEscrowFailed,
                    format!("no sealed key bundle at {}", path.display()),
                )
                .with_hint("pass --from creds:<file> or plaintext:<file>"));
            }
            keystore::unseal(&ctx.runner, &path, &disk.name)?
        }
        "plaintext" => std::fs::read_to_string(&path).map_err(|e| {
            Error::new(Code::EEscrowFailed, format!("read {}: {e}", path.display()))
        })?,
        other => {
            return Err(
                Error::new(Code::EConfig, format!("unknown --from kind: {other}"))
                    .with_hint("use creds:<file> or plaintext:<file>"),
            )
        }
    };

    let bundle: Value = serde_json::from_str(&bundle_json)
        .map_err(|e| Error::new(Code::EInternal, format!("parse key bundle: {e}")))?;
    let passphrase = bundle.get("passphrase").and_then(|v| v.as_str());
    let recovery_key = bundle.get("recovery_key").and_then(|v| v.as_str());

    // Optionally open the mapping now with the recovered key.
    let mut opened = false;
    let mut already_open = false;
    if args.open {
        if disk.remote.is_some() {
            return Err(Error::new(
                Code::EConfig,
                format!(
                    "--open is local-only; disk {:?} lives on a remote",
                    disk.name
                ),
            )
            .with_hint("run `tpmnt recover --show` here and open it on the remote host"));
        }
        let key = passphrase
            .or(recovery_key)
            .ok_or_else(|| Error::new(Code::EEscrowFailed, "key bundle contains no usable key"))?;
        let mapper = disk.mapper_name();
        if PathBuf::from(format!("/dev/mapper/{mapper}")).exists() {
            already_open = true;
        } else {
            let dry = ctx.global.effective_dry_run();
            let secure = if dry { None } else { Some(SecureDir::new()?) };
            let kf = match &secure {
                Some(sd) => sd.write_key("recover", key)?,
                None => PathBuf::from("<securedir>/recover"),
            };
            let device = disk.device_path();
            ctx.runner
                .run(
                    &[
                        "cryptsetup",
                        "open",
                        &device,
                        &mapper,
                        "--key-file",
                        &kf.to_string_lossy(),
                    ],
                    "open LUKS mapping with the recovered key",
                )?
                .require("cryptsetup open")?;
            opened = true;
        }
    }

    let mut result = json!({
        "ok": true,
        "disk": disk.name,
        "source": { "kind": kind, "path": path },
        "has_passphrase": passphrase.is_some(),
        "has_recovery_key": recovery_key.is_some(),
        "mapper_name": disk.mapper_name(),
        "opened": opened,
        "already_open": already_open,
        "revealed": args.show,
    });
    if args.show {
        result["secrets"] = json!({
            "passphrase": passphrase,
            "recovery_key": recovery_key,
            "bundle": bundle,
        });
    }
    Ok(result)
}

/// Human rendering. Secrets are printed only when `--show` populated them.
pub fn render(value: &Value) -> String {
    let mut out = String::new();
    let disk = value.get("disk").and_then(|v| v.as_str()).unwrap_or("?");
    out.push_str(&format!("recover: {disk}\n"));

    if let Some(src) = value.get("source") {
        let kind = src.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
        let path = src.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        out.push_str(&format!("  source: {kind} {path}\n"));
    }
    let has_pass = value.get("has_passphrase").and_then(|v| v.as_bool()) == Some(true);
    let has_rk = value.get("has_recovery_key").and_then(|v| v.as_bool()) == Some(true);
    out.push_str(&format!(
        "  retrievable: passphrase={} recovery_key={}\n",
        yesno(has_pass),
        yesno(has_rk)
    ));

    if value.get("already_open").and_then(|v| v.as_bool()) == Some(true) {
        let m = value
            .get("mapper_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        out.push_str(&format!("  mapping /dev/mapper/{m} already open\n"));
    } else if value.get("opened").and_then(|v| v.as_bool()) == Some(true) {
        let m = value
            .get("mapper_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        out.push_str(&format!("  opened /dev/mapper/{m}\n"));
    }

    if let Some(secrets) = value.get("secrets") {
        out.push_str("  secrets:\n");
        if let Some(p) = secrets.get("passphrase").and_then(|v| v.as_str()) {
            out.push_str(&format!("    passphrase:   {p}\n"));
        }
        if let Some(rk) = secrets.get("recovery_key").and_then(|v| v.as_str()) {
            out.push_str(&format!("    recovery_key: {rk}\n"));
        }
    } else {
        out.push_str("  (pass --show to reveal the key, --open to unlock now)\n");
    }
    out
}

fn yesno(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_without_show_hides_the_key() {
        let v = json!({
            "disk": "arc",
            "source": { "kind": "creds", "path": "/etc/tpmnt/keys/arc.cred" },
            "has_passphrase": true,
            "has_recovery_key": true,
            "mapper_name": "tpmnt-arc",
            "opened": false,
            "already_open": false,
        });
        let out = render(&v);
        assert!(out.contains("retrievable: passphrase=yes recovery_key=yes"));
        assert!(out.contains("--show"));
        assert!(!out.contains("secrets:"));
    }

    #[test]
    fn render_with_show_prints_the_key() {
        let v = json!({
            "disk": "arc",
            "has_passphrase": true,
            "has_recovery_key": false,
            "mapper_name": "tpmnt-arc",
            "opened": true,
            "already_open": false,
            "secrets": { "passphrase": "correct-horse", "recovery_key": null },
        });
        let out = render(&v);
        assert!(out.contains("opened /dev/mapper/tpmnt-arc"));
        assert!(out.contains("passphrase:   correct-horse"));
    }
}
