//! `tpmnt enroll <device>` — register a TPM2 token on an existing LUKS2 device
//! by shelling out to `systemd-cryptenroll`, after backing up the header and
//! verifying a non-TPM fallback keyslot exists.

use serde_json::{json, Value};

use crate::cli::EnrollArgs;
use crate::error::{err, Code, Error, Result};
use crate::luks;

use super::Context;

/// Resolve the existing LUKS passphrase from (in order): --passphrase-file,
/// $PASSWORD, or an interactive prompt. Fails in --non-interactive without one.
fn resolve_passphrase(ctx: &Context, args: &EnrollArgs) -> Result<String> {
    if let Some(p) = &args.passphrase_file {
        let s = std::fs::read_to_string(p)
            .map_err(|e| Error::new(Code::ENoPassphrase, format!("read {}: {e}", p.display())))?;
        return Ok(s.trim_end_matches('\n').to_string());
    }
    if let Ok(p) = std::env::var("PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    if ctx.global.non_interactive {
        return err(
            Code::ENoPassphrase,
            "no passphrase: pass --passphrase-file or set $PASSWORD in non-interactive mode",
        );
    }
    // Interactive prompt (no echo would need a tty crate; keep MVP simple and
    // read a line). Reserved for human use only.
    eprint!("Enter existing LUKS passphrase for {}: ", args.device);
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Error::new(Code::ENoPassphrase, format!("stdin: {e}")))?;
    Ok(line.trim_end_matches('\n').to_string())
}

/// Parse a PCR spec ("7,14", "7+14", "", or None) into a list of PCR indices.
/// Empty/None means TPM-only binding (no PCRs).
pub fn parse_pcrs(spec: Option<&str>) -> Result<Vec<u32>> {
    let Some(s) = spec else { return Ok(Vec::new()) };
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split(['+', ','])
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            p.trim().parse::<u32>().map_err(|_| {
                Error::new(Code::EConfig, format!("invalid PCR index: {p:?}"))
                    .with_hint("PCRs must be integers, e.g. --pcrs 7,14")
            })
        })
        .collect()
}

/// Public entry. Returns a JSON result describing the enrollment.
pub fn run(ctx: &Context, args: &EnrollArgs) -> Result<Value> {
    let pcrs = parse_pcrs(args.pcrs.as_deref())?;
    enroll_device(ctx, &args.device, &pcrs, args.with_pin, false, || {
        resolve_passphrase(ctx, args)
    })
}

/// Reusable enrollment routine (also called by apply/migrate/pin). The passphrase
/// is fetched lazily so callers that only need a token check pay nothing.
///
/// `force` re-enrolls even when a TPM2 token already exists: it wipes the current
/// TPM2 slot and enrolls a fresh one (this is how a PIN is *added to* or *removed
/// from* an already-encrypted disk — see `cmd::pin`). Without it, an existing
/// token short-circuits to a no-op.
pub fn enroll_device(
    ctx: &Context,
    device: &str,
    pcrs: &[u32],
    with_pin: bool,
    force: bool,
    passphrase: impl FnOnce() -> Result<String>,
) -> Result<Value> {
    let mut warnings: Vec<String> = Vec::new();

    // 1. Must be LUKS2.
    let info = luks::inspect(&ctx.runner, device)?;
    luks::require_luks2(&info, device)?;

    // 2. Must have a non-TPM fallback keyslot as portable trust root.
    if !info.has_non_tpm_fallback() {
        return Err(Error::new(
            Code::ENoFallbackKeyslot,
            format!("{device} has no non-TPM (passphrase/recovery) keyslot"),
        )
        .with_hint("add a passphrase keyslot first; tpmnt refuses TPM-only enrollment"));
    }

    // 3. TPM must be present.
    if !ctx.env.tpm_rm_present {
        return Err(Error::new(
            Code::ENoTpm,
            "no TPM2 resource manager device (/dev/tpmrm0)",
        )
        .with_hint("ensure a TPM2 is present and the tpm_crb/tpm_tis driver is loaded"));
    }

    // 4. Safety warnings for weak policies.
    if pcrs.is_empty() && !with_pin {
        warnings.push(
            "TPM-only binding (no PCRs, no PIN): vulnerable to evil-maid key extraction. \
             Consider --with-pin and/or PCR 7/14 binding."
                .to_string(),
        );
    }

    // 5. Already enrolled? Idempotent no-op — unless forcing a re-enroll (e.g. to
    //    add/remove a PIN on an existing token).
    if info.has_tpm2_token() && !force {
        for w in &warnings {
            eprintln!("warning: {w}");
        }
        return Ok(json!({
            "ok": true,
            "device": device,
            "uuid": info.uuid,
            "action": "noop",
            "reason": "tpm2 token already present",
            "warnings": warnings,
        }));
    }

    // 6. Back up the header before any keyslot change.
    let uuid = info.uuid.clone().unwrap_or_else(|| "unknown".to_string());
    let backup = ctx.paths.header_backup(&uuid);
    luks::header_backup(&ctx.runner, device, &backup)?;

    // 7. Build and run systemd-cryptenroll.
    let pass = passphrase()?;
    let mut argv: Vec<String> = vec!["systemd-cryptenroll".into()];
    // Re-enrollment: drop the existing TPM2 slot first so the new (PIN / no-PIN)
    // token replaces it rather than piling up a second one.
    if force {
        argv.push("--wipe-slot=tpm2".into());
    }
    argv.push("--tpm2-device=auto".into());
    if !pcrs.is_empty() {
        let joined = pcrs
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("+");
        argv.push(format!("--tpm2-pcrs={joined}"));
    } else {
        argv.push("--tpm2-pcrs=".into()); // explicit: bind to no PCRs
    }
    if with_pin {
        argv.push("--tpm2-with-pin=yes".into());
    }
    argv.push(device.to_string());

    let argv_ref: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();

    let mut envs: Vec<(&str, &str)> = vec![("PASSWORD", pass.as_str())];
    let pin = std::env::var("TPMNT_PIN").unwrap_or_default();
    if with_pin && !pin.is_empty() {
        envs.push(("NEWPIN", pin.as_str()));
    }

    ctx.runner
        .run_env(
            &argv_ref,
            &envs,
            "enroll TPM2 token via systemd-cryptenroll",
        )?
        .require("systemd-cryptenroll")?;

    // 8. Verify (skip under dry-run, where nothing was written).
    let token_present = if ctx.runner.dry_run {
        true
    } else {
        luks::inspect(&ctx.runner, device)?.has_tpm2_token()
    };

    for w in &warnings {
        eprintln!("warning: {w}");
    }

    Ok(json!({
        "ok": true,
        "device": device,
        "uuid": uuid,
        "action": if force { "re-enrolled" } else { "enrolled" },
        "pcrs": pcrs,
        "with_pin": with_pin,
        "header_backup": backup.display().to_string(),
        "tpm2_token_present": token_present,
        "warnings": warnings,
    }))
}

#[cfg(test)]
mod tests {
    use super::parse_pcrs;

    #[test]
    fn empty_and_none_mean_tpm_only() {
        assert_eq!(parse_pcrs(None).unwrap(), Vec::<u32>::new());
        assert_eq!(parse_pcrs(Some("")).unwrap(), Vec::<u32>::new());
        assert_eq!(parse_pcrs(Some("  ")).unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn parses_comma_and_plus_separators() {
        assert_eq!(parse_pcrs(Some("7,14")).unwrap(), vec![7, 14]);
        assert_eq!(parse_pcrs(Some("7+14")).unwrap(), vec![7, 14]);
        assert_eq!(parse_pcrs(Some("0")).unwrap(), vec![0]);
    }

    #[test]
    fn rejects_non_numeric_pcr() {
        assert!(parse_pcrs(Some("7,foo")).is_err());
    }
}
