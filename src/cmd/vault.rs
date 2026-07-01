//! `tpmnt vault …` — inspect and maintain the unified PIN vault.
//!
//!   * `list` — the disks whose keys are in the vault (proof-of-retrievability,
//!     no secrets revealed);
//!   * `rekey` — change the PIN (decrypt with the old, re-encrypt with a new one);
//!   * `sync` — (re)build the vault from the local sealed `.cred` bundles, e.g. to
//!     create the vault for disks that were enrolled before it existed.

use serde_json::{json, Value};

use crate::cli::{VaultAction, VaultArgs};
use crate::error::{Code, Error, Result};
use crate::{keystore, pin, vault};

use super::Context;

pub fn run(ctx: &Context, args: &VaultArgs) -> Result<Value> {
    let dir = &ctx.config.defaults.key_backup;
    let ni = ctx.global.non_interactive;
    let dry = ctx.global.effective_dry_run();

    match &args.action {
        VaultAction::List => {
            let pin = pin::resolve(args.pin_file.as_deref(), ni)?;
            let v = vault::load(&ctx.runner, dir, &pin)?;
            let mut disks = vault::names(&v);
            disks.sort();
            Ok(json!({
                "ok": true,
                "action": "list",
                "path": vault::vault_path(dir),
                "count": disks.len(),
                "disks": disks,
            }))
        }
        VaultAction::Rekey { new_pin_file } => {
            let old = pin::resolve(args.pin_file.as_deref(), ni)?;
            let v = vault::load(&ctx.runner, dir, &old)?;
            let new = pin::resolve_new(new_pin_file.as_deref(), ni)?;
            if new == old {
                return Err(Error::new(Code::EConfig, "new PIN equals the current PIN")
                    .with_hint("choose a different PIN"));
            }
            let path = vault::save(&ctx.runner, dir, &v, &new, dry)?;
            Ok(json!({
                "ok": true,
                "action": "rekey",
                "path": path,
                "count": vault::names(&v).len(),
                "dry_run": dry,
                "warning": "the TPM2 unlock PIN is unchanged; run `tpmnt enroll --with-pin` \
                            to rotate that too if desired",
            }))
        }
        VaultAction::Sync => {
            let pin = pin::resolve(args.pin_file.as_deref(), ni)?;
            // Start from whatever is already stored so we only add/refresh.
            let mut v = vault::load(&ctx.runner, dir, &pin)?;
            if !v.get("disks").map(|d| d.is_object()).unwrap_or(false) {
                v["disks"] = json!({});
            }
            let mut imported = Vec::new();
            let mut skipped = Vec::new();
            for disk in &ctx.config.disks {
                let sealed = keystore::sealed_path(dir, &disk.name);
                if !sealed.exists() {
                    skipped.push(json!({ "name": disk.name, "reason": "no sealed bundle" }));
                    continue;
                }
                match keystore::unseal(&ctx.runner, &sealed, &disk.name).and_then(|t| {
                    serde_json::from_str::<Value>(&t)
                        .map_err(|e| Error::new(Code::EInternal, format!("parse bundle: {e}")))
                }) {
                    Ok(bundle) => {
                        v["disks"][&disk.name] = bundle;
                        imported.push(disk.name.clone());
                    }
                    Err(e) => {
                        skipped.push(json!({ "name": disk.name, "reason": e.message }));
                    }
                }
            }
            let path = vault::save(&ctx.runner, dir, &v, &pin, dry)?;
            Ok(json!({
                "ok": true,
                "action": "sync",
                "path": path,
                "imported": imported,
                "skipped": skipped,
                "count": vault::names(&v).len(),
                "dry_run": dry,
            }))
        }
    }
}

/// Human rendering for `vault` (JSON stays the machine contract).
pub fn render(value: &Value) -> String {
    let mut out = String::new();
    let action = value.get("action").and_then(|v| v.as_str()).unwrap_or("?");
    let path = value.get("path").and_then(|v| v.as_str()).unwrap_or("?");
    out.push_str(&format!("vault {action}: {path}\n"));
    match action {
        "list" => {
            let count = value.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            out.push_str(&format!("  {count} disk(s):\n"));
            if let Some(ds) = value.get("disks").and_then(|v| v.as_array()) {
                for d in ds.iter().filter_map(|v| v.as_str()) {
                    out.push_str(&format!("    - {d}\n"));
                }
            }
        }
        "sync" => {
            let imported = value
                .get("imported")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let skipped = value
                .get("skipped")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            out.push_str(&format!("  imported {imported}, skipped {skipped}\n"));
        }
        "rekey" => out.push_str("  PIN changed\n"),
        _ => {}
    }
    if let Some(w) = value.get("warning").and_then(|v| v.as_str()) {
        out.push_str(&format!("  warning: {w}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_lists_disks() {
        let v = json!({
            "action": "list", "path": "/etc/tpmnt/keys/vault.gpg",
            "count": 2, "disks": ["arc", "cold"]
        });
        let out = render(&v);
        assert!(out.contains("2 disk(s)"));
        assert!(out.contains("- arc"));
        assert!(out.contains("- cold"));
    }
}
