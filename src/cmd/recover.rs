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
use crate::{pin, vault};

use super::Context;

/// Resolve the key bundle for `name` from `--from` (creds:/plaintext:/vault) or,
/// by default, the sealed local `.cred` — automatically falling back to the PIN
/// vault when the TPM seal can't be read. Returns `(source, bundle)` where
/// `source` is the JSON provenance shown to the caller.
fn acquire_bundle(ctx: &Context, name: &str, args: &RecoverArgs) -> Result<(Value, Value)> {
    let dir = &ctx.config.defaults.key_backup;

    // Load + parse a sealed .cred bundle.
    let from_creds = |path: &std::path::Path| -> Result<Value> {
        let text = keystore::unseal(&ctx.runner, path, name)?;
        parse_bundle(&text)
    };
    // Load one disk's bundle from the PIN vault (prompts for the PIN as needed).
    let from_vault = || -> Result<Value> {
        let pin = pin::resolve(args.pin_file.as_deref(), ctx.global.non_interactive)?;
        let v = vault::load(&ctx.runner, dir, &pin)?;
        vault::get(&v, name).cloned().ok_or_else(|| {
            Error::new(
                Code::EEscrowFailed,
                format!("disk {name:?} is not in the PIN vault"),
            )
            .with_hint("was it enrolled with a PIN? check `tpmnt vault list`")
        })
    };

    match args.from.as_deref() {
        Some("vault") => Ok((
            json!({ "kind": "vault", "path": vault::vault_path(dir) }),
            from_vault()?,
        )),
        Some(spec) => {
            let (kind, p) = spec.split_once(':').ok_or_else(|| {
                Error::new(Code::EConfig, format!("bad --from spec: {spec:?}"))
                    .with_hint("use creds:<file>, plaintext:<file>, or vault")
            })?;
            let path = PathBuf::from(p);
            let bundle = match kind {
                "creds" => {
                    if !path.exists() {
                        return Err(Error::new(
                            Code::EEscrowFailed,
                            format!("no sealed key bundle at {}", path.display()),
                        ));
                    }
                    from_creds(&path)?
                }
                "plaintext" => {
                    let text = std::fs::read_to_string(&path).map_err(|e| {
                        Error::new(Code::EEscrowFailed, format!("read {}: {e}", path.display()))
                    })?;
                    parse_bundle(&text)?
                }
                other => {
                    return Err(
                        Error::new(Code::EConfig, format!("unknown --from kind: {other}"))
                            .with_hint("use creds:<file>, plaintext:<file>, or vault"),
                    )
                }
            };
            Ok((json!({ "kind": kind, "path": path }), bundle))
        }
        // Default: the host-sealed .cred, with an automatic PIN-vault fallback so a
        // broken/changed TPM still recovers as long as the vault + PIN exist.
        None => {
            let sealed = keystore::sealed_path(dir, name);
            let cred_result = if sealed.exists() {
                from_creds(&sealed)
            } else {
                Err(Error::new(
                    Code::EEscrowFailed,
                    format!("no sealed key bundle at {}", sealed.display()),
                ))
            };
            match cred_result {
                Ok(b) => Ok((json!({ "kind": "creds", "path": sealed }), b)),
                Err(cred_err) => {
                    if vault::vault_path(dir).exists() {
                        eprintln!(
                            "note: TPM-sealed bundle unavailable ({}); recovering from the PIN vault",
                            cred_err.message
                        );
                        Ok((
                            json!({ "kind": "vault", "path": vault::vault_path(dir), "fallback": true }),
                            from_vault()?,
                        ))
                    } else {
                        Err(cred_err.with_hint(
                            "no PIN vault to fall back to; pass --from plaintext:<file>",
                        ))
                    }
                }
            }
        }
    }
}

fn parse_bundle(text: &str) -> Result<Value> {
    serde_json::from_str(text)
        .map_err(|e| Error::new(Code::EInternal, format!("parse key bundle: {e}")))
}

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

    // Acquire the key bundle from the requested (or default) source.
    let (source, bundle) = acquire_bundle(ctx, &disk.name, args)?;
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
        "source": source,
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
