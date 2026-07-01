//! PIN resolution — the single secret the user actually remembers.
//!
//! The same PIN does double duty: it is the TPM2 unlock PIN (`systemd-cryptenroll
//! --tpm2-with-pin`, fed via `$TPMNT_PIN`) *and* the passphrase that encrypts the
//! unified recovery vault (`vault.rs`). Keeping it one value is the whole point —
//! if the TPM ever refuses to unlock a disk, the user types the *same* PIN they'd
//! use at the prompt and recovers the raw LUKS key from the vault.
//!
//! Sources, in order: `--pin-file`, `$TPMNT_PIN`, then an interactive prompt.
//! In `--non-interactive` mode a missing PIN is a hard error rather than a hang.

use std::path::Path;

use crate::error::{err, Code, Result};

/// Minimum PIN length. A short PIN under a memory-hard KDF is still weak; refuse
/// obviously-guessable ones up front so a typo doesn't become a weak vault.
const MIN_PIN_LEN: usize = 4;

/// Resolve the PIN from `--pin-file`, `$TPMNT_PIN`, or an interactive prompt.
/// Trailing newlines are stripped so a file written with `echo` still matches the
/// prompt-entered value. Errors (E_NO_PASSPHRASE) when none is available in
/// non-interactive use, or when the resolved PIN is too short.
pub fn resolve(pin_file: Option<&Path>, non_interactive: bool) -> Result<String> {
    let pin = resolve_raw(pin_file, non_interactive)?;
    if pin.len() < MIN_PIN_LEN {
        return err(
            Code::ENoPassphrase,
            format!("PIN too short (min {MIN_PIN_LEN} chars)"),
        );
    }
    Ok(pin)
}

fn resolve_raw(pin_file: Option<&Path>, non_interactive: bool) -> Result<String> {
    if let Some(f) = pin_file {
        let s = std::fs::read_to_string(f).map_err(|e| {
            crate::error::Error::new(Code::ENoPassphrase, format!("read {}: {e}", f.display()))
        })?;
        return Ok(strip_newline(&s));
    }
    if let Ok(p) = std::env::var("TPMNT_PIN") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    if non_interactive {
        return err(
            Code::ENoPassphrase,
            "no PIN: pass --pin-file or set $TPMNT_PIN in non-interactive mode",
        );
    }
    eprint!("Enter tpmnt PIN: ");
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| crate::error::Error::new(Code::ENoPassphrase, format!("stdin: {e}")))?;
    Ok(strip_newline(&line))
}

/// Resolve a *new* PIN (for `vault rekey`). Deliberately never consults
/// `$TPMNT_PIN` — that holds the current PIN and would silently reuse it. Reads
/// `--new-pin-file` or prompts; enforces the same minimum length.
pub fn resolve_new(pin_file: Option<&Path>, non_interactive: bool) -> Result<String> {
    let pin = if let Some(f) = pin_file {
        let s = std::fs::read_to_string(f).map_err(|e| {
            crate::error::Error::new(Code::ENoPassphrase, format!("read {}: {e}", f.display()))
        })?;
        strip_newline(&s)
    } else if non_interactive {
        return err(
            Code::ENoPassphrase,
            "no new PIN: pass --new-pin-file in non-interactive mode",
        );
    } else {
        eprint!("Enter NEW tpmnt PIN: ");
        use std::io::BufRead;
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| crate::error::Error::new(Code::ENoPassphrase, format!("stdin: {e}")))?;
        strip_newline(&line)
    };
    if pin.len() < MIN_PIN_LEN {
        return err(
            Code::ENoPassphrase,
            format!("new PIN too short (min {MIN_PIN_LEN} chars)"),
        );
    }
    Ok(pin)
}

fn strip_newline(s: &str) -> String {
    s.trim_end_matches(['\n', '\r']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn reads_pin_from_file_and_strips_newline() {
        let dir = std::env::temp_dir().join(format!("tpmnt-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("pin");
        let mut fh = std::fs::File::create(&f).unwrap();
        writeln!(fh, "hunter2").unwrap();
        assert_eq!(resolve(Some(&f), true).unwrap(), "hunter2");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_too_short_pin() {
        let dir = std::env::temp_dir().join(format!("tpmnt-pin2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("pin");
        std::fs::write(&f, "ab").unwrap();
        assert!(resolve(Some(&f), true).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn non_interactive_without_source_errors() {
        std::env::remove_var("TPMNT_PIN");
        assert!(resolve(None, true).is_err());
    }
}
