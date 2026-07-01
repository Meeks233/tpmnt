//! Thin helpers over `cryptsetup` for inspecting a LUKS2 container: type
//! detection, keyslot/token enumeration, UUID, and header backup. We parse
//! `luksDump` text output (stable enough for our needs) rather than linking
//! libcryptsetup, keeping the MVP a pure orchestrator.

use std::path::Path;

use serde::Serialize;

use crate::error::{Code, Error, Result};
use crate::exec::Runner;

#[derive(Debug, Clone, Serialize, Default)]
pub struct LuksInfo {
    pub is_luks: bool,
    pub is_luks2: bool,
    pub uuid: Option<String>,
    /// Keyslot indices that are in use.
    pub keyslots: Vec<u32>,
    /// Token types present (e.g. "systemd-tpm2").
    pub tokens: Vec<String>,
}

impl LuksInfo {
    pub fn has_tpm2_token(&self) -> bool {
        self.tokens.iter().any(|t| t.contains("tpm2"))
    }

    /// A passphrase/recovery keyslot count: total keyslots minus nothing,
    /// because TPM2 enrollment also occupies a keyslot. We can't perfectly
    /// distinguish here, so callers use token+keyslot counts together. A
    /// container with >=1 keyslot and (no token, or more keyslots than tokens)
    /// has a usable non-TPM fallback.
    pub fn has_non_tpm_fallback(&self) -> bool {
        // Each systemd-tpm2 token references one keyslot. If keyslots exceed
        // tpm2 tokens, at least one is a passphrase/recovery slot.
        let tpm_tokens = self.tokens.iter().filter(|t| t.contains("tpm2")).count();
        self.keyslots.len() > tpm_tokens
    }
}

/// Inspect a local device. Read-only; safe under dry-run.
pub fn inspect(runner: &Runner, device: &str) -> Result<LuksInfo> {
    inspect_on(runner, &[], device)
}

/// Inspect a device that may live on a remote. `prefix` is an SSH argv (empty =
/// local, from `Config::ssh_prefix_for`). For remote disks the local existence
/// check is skipped — the path is resolved on the remote — and `luksDump` runs
/// there over SSH. Read-only; safe under dry-run.
pub fn inspect_on(runner: &Runner, prefix: &[String], device: &str) -> Result<LuksInfo> {
    if prefix.is_empty() && !Path::new(device).exists() {
        return Err(
            Error::new(Code::ENoDevice, format!("device does not exist: {device}"))
                .with_hint("check the path or `--device by-id` symlink"),
        );
    }

    let out = runner.probe_on(
        prefix,
        &["cryptsetup", "luksDump", device],
        "inspect LUKS header",
    )?;
    if !out.ok() {
        // Not a LUKS device at all (or unreachable remote).
        return Ok(LuksInfo::default());
    }
    Ok(parse_luks_dump(&out.stdout))
}

/// Require a LUKS2 device or return a precise error.
pub fn require_luks2(info: &LuksInfo, device: &str) -> Result<()> {
    if !info.is_luks {
        return Err(Error::new(
            Code::ENotLuks2,
            format!("{device} is not a LUKS container"),
        ));
    }
    if !info.is_luks2 {
        return Err(Error::new(
            Code::ENotLuks2,
            format!("{device} is LUKS1; tpmnt requires LUKS2"),
        )
        .with_hint("convert with `cryptsetup convert --type luks2` (back up first)"));
    }
    Ok(())
}

pub fn parse_luks_dump(text: &str) -> LuksInfo {
    let mut info = LuksInfo::default();
    let mut section = Section::None;

    for raw in text.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("Version:") {
            info.is_luks = true;
            info.is_luks2 = rest.trim() == "2";
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("UUID:") {
            info.uuid = Some(rest.trim().to_string());
            continue;
        }

        // Section headers are unindented in luksDump output.
        if !line.starts_with(char::is_whitespace) {
            section = match trimmed {
                "Keyslots:" => Section::Keyslots,
                "Tokens:" => Section::Tokens,
                _ => Section::Other,
            };
            continue;
        }

        match section {
            Section::Keyslots => {
                // "  0: luks2" — a single leading indent + index + ": luks2"
                if let Some(idx) = parse_indexed_header(line, "luks2") {
                    info.keyslots.push(idx);
                }
            }
            Section::Tokens => {
                // "  0: systemd-tpm2"
                if let Some(t) = parse_token_type(line) {
                    info.tokens.push(t);
                }
            }
            _ => {}
        }
    }
    info
}

enum Section {
    None,
    Keyslots,
    Tokens,
    Other,
}

/// Parse a single-indent line like "  0: luks2" returning the index when the
/// type matches. Deeper-indented lines (key data) are ignored.
fn parse_indexed_header(line: &str, expect_type: &str) -> Option<u32> {
    let indent = line.len() - line.trim_start().len();
    if indent != 2 {
        return None;
    }
    let t = line.trim();
    let (idx, ty) = t.split_once(':')?;
    if ty.trim() == expect_type {
        idx.trim().parse().ok()
    } else {
        None
    }
}

fn parse_token_type(line: &str) -> Option<String> {
    let indent = line.len() - line.trim_start().len();
    if indent != 2 {
        return None;
    }
    let t = line.trim();
    let (_idx, ty) = t.split_once(':')?;
    Some(ty.trim().to_string())
}

/// Back up the LUKS2 header to a file, keyed by UUID. Idempotent: if a backup
/// already exists we keep it and skip — `cryptsetup luksHeaderBackup` refuses to
/// overwrite (it would error), and the FIRST backup is the pristine pre-management
/// header that `rollback` must restore. A later re-enrollment (e.g. `pin enable`
/// wiping+re-adding the TPM2 slot) therefore must not clobber it.
pub fn header_backup(runner: &Runner, device: &str, dest: &Path) -> Result<()> {
    // A pre-existing backup is the one we want to preserve; don't overwrite (and
    // don't fail). Under dry-run `dest` won't exist, so the step is still traced.
    if dest.exists() {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::new(Code::EInternal, format!("mkdir {}: {e}", parent.display())))?;
    }
    runner
        .run(
            &[
                "cryptsetup",
                "luksHeaderBackup",
                device,
                "--header-backup-file",
                &dest.to_string_lossy(),
            ],
            "back up LUKS2 header before keyslot change",
        )?
        .require("luksHeaderBackup")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Abridged real `cryptsetup luksDump` output: passphrase slot 0 + a TPM2
    // token enrolled into slot 1.
    const DUMP_LUKS2_TPM: &str = "\
LUKS header information
Version:       \t2
UUID:          \t782b1ce1-6d52-4dc3-bc89-a5ad909badf1
Keyslots:
  0: luks2
\tKey:        512 bits
  1: luks2
\tKey:        512 bits
Tokens:
  0: systemd-tpm2
\ttpm2-pcrs:
Digests:
  0: pbkdf2
";

    #[test]
    fn parses_luks2_with_tpm_and_fallback() {
        let info = parse_luks_dump(DUMP_LUKS2_TPM);
        assert!(info.is_luks2);
        assert_eq!(
            info.uuid.as_deref(),
            Some("782b1ce1-6d52-4dc3-bc89-a5ad909badf1")
        );
        assert_eq!(info.keyslots, vec![0, 1]);
        assert!(info.has_tpm2_token());
        // keyslots(2) > tpm tokens(1) => a passphrase fallback exists.
        assert!(info.has_non_tpm_fallback());
    }

    #[test]
    fn luks1_is_not_luks2() {
        let info = parse_luks_dump("Version:       \t1\nUUID:          \tabc\n");
        assert!(info.is_luks);
        assert!(!info.is_luks2);
    }

    #[test]
    fn tpm_only_has_no_fallback() {
        // One keyslot, one tpm token referencing it => no passphrase fallback.
        let info = parse_luks_dump(
            "Version:       \t2\nKeyslots:\n  1: luks2\nTokens:\n  0: systemd-tpm2\n",
        );
        assert!(!info.has_non_tpm_fallback());
    }

    #[test]
    fn ignores_deeply_indented_key_data() {
        let info = parse_luks_dump("Version:\t2\nKeyslots:\n  0: luks2\n\tAF stripes: 4000\n");
        assert_eq!(info.keyslots, vec![0]);
    }

    #[test]
    fn header_backup_is_idempotent_and_preserves_the_first() {
        let dir = std::env::temp_dir().join(format!("tpmnt-hdr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("header-uuid.img");

        // First call (dry-run): dest doesn't exist yet -> the backup command is traced.
        let r = Runner::new(true, false);
        header_backup(&r, "/dev/x", &dest).unwrap();
        assert_eq!(r.trace.borrow().len(), 1);
        assert_eq!(r.trace.borrow()[0].argv[1], "luksHeaderBackup");

        // Simulate the backup now existing; a second call must skip (no trace, no
        // overwrite) so a re-enroll can't clobber the pristine pre-management header.
        std::fs::write(&dest, b"pristine").unwrap();
        let r2 = Runner::new(true, false);
        header_backup(&r2, "/dev/x", &dest).unwrap();
        assert!(r2.trace.borrow().is_empty());
        assert_eq!(std::fs::read(&dest).unwrap(), b"pristine");

        std::fs::remove_dir_all(&dir).ok();
    }
}
