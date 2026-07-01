//! The unified PIN vault — one file, every disk's key, TPM-independent recovery.
//!
//! `keystore.rs` seals each disk's bundle to *this host's* TPM (convenient, but by
//! design unreadable if the TPM state changes or the host is lost). The vault is
//! the complementary escrow: a single file holding **all** managed disks' key
//! bundles, encrypted under the user's PIN. If the TPM ever refuses to unlock a
//! disk, the user types the same PIN and recovers the raw LUKS passphrase from
//! here — no per-disk backups to hunt down, nothing on another machine.
//!
//! ## Why gpg symmetric (and not age / hand-rolled crypto)
//!
//! Per the project rule we never implement crypto; we delegate to a trusted tool.
//! `age -p` is tempting but its passphrase mode reads only from a controlling tty
//! — unusable for the scripted, non-interactive recovery/migration paths tpmnt
//! exists to automate. `gpg --symmetric` takes the PIN from a file descriptor
//! (`--passphrase-file`), so it works interactively *and* headless. Its s2k
//! (string-to-key) is **salted + iterated** (mode 3): the random per-file salt
//! defeats precomputed rainbow tables, and a high iteration count slows brute
//! force — exactly the "不能被随随便便彩虹表" requirement. Output is AES-256 and
//! ASCII-armored; the plaintext never lands on persistent storage (it lives only
//! in a tmpfs `SecureDir` for the duration of one gpg call).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::error::{Code, Error, Result};
use crate::exec::Runner;
use crate::keystore::SecureDir;

/// The vault schema version stored inside the plaintext JSON.
const VAULT_VERSION: u64 = 1;

/// gpg's maximum s2k iteration count (a coded value). Combined with the random
/// per-file salt gpg adds automatically, this is the anti-rainbow-table hardening.
const S2K_COUNT: &str = "65011712";

/// Path of the single vault file under the key-backup directory.
pub fn vault_path(dir: &Path) -> PathBuf {
    dir.join("vault.gpg")
}

/// An empty vault document (used when no file exists yet, or under dry-run).
fn empty() -> Value {
    json!({ "tpmnt_vault": VAULT_VERSION, "disks": {} })
}

/// gpg argv to symmetric-encrypt `plaintext` → `out`, PIN read from `pin_file`.
fn encrypt_argv(pin_file: &str, plaintext: &str, out: &str) -> Vec<String> {
    vec![
        "gpg".into(),
        "--batch".into(),
        "--yes".into(),
        "--no-symkey-cache".into(),
        "--pinentry-mode".into(),
        "loopback".into(),
        "--passphrase-file".into(),
        pin_file.into(),
        "--s2k-mode".into(),
        "3".into(),
        "--s2k-count".into(),
        S2K_COUNT.into(),
        "--s2k-digest-algo".into(),
        "SHA512".into(),
        "--cipher-algo".into(),
        "AES256".into(),
        "--symmetric".into(),
        "--armor".into(),
        "--output".into(),
        out.into(),
        plaintext.into(),
    ]
}

/// gpg argv to decrypt the vault at `ciphertext` to stdout, PIN from `pin_file`.
fn decrypt_argv(pin_file: &str, ciphertext: &str) -> Vec<String> {
    vec![
        "gpg".into(),
        "--batch".into(),
        "--yes".into(),
        "--no-symkey-cache".into(),
        "--pinentry-mode".into(),
        "loopback".into(),
        "--passphrase-file".into(),
        pin_file.into(),
        "--decrypt".into(),
        ciphertext.into(),
    ]
}

/// Load and decrypt the vault. A missing file yields an empty vault (first run).
/// Read-only, so it executes even under `--plan`/`--dry-run` — recovery must
/// reflect reality. A wrong PIN or corrupt file is a precise E_ESCROW_FAILED.
pub fn load(runner: &Runner, dir: &Path, pin: &str) -> Result<Value> {
    let path = vault_path(dir);
    if !path.exists() {
        return Ok(empty());
    }
    let sd = SecureDir::labeled("vault")?;
    let pin_file = sd.write_key("pin", pin)?;
    let out = runner.probe(
        &decrypt_argv(&pin_file.to_string_lossy(), &path.to_string_lossy())
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "decrypt the PIN vault with gpg",
    )?;
    if !out.ok() {
        return Err(Error::new(
            Code::EEscrowFailed,
            format!(
                "cannot decrypt vault {} (exit {})",
                path.display(),
                out.status
            ),
        )
        .with_hint("wrong PIN, or the vault file is corrupt"));
    }
    serde_json::from_str(&out.stdout)
        .map_err(|e| Error::new(Code::EInternal, format!("parse vault JSON: {e}")))
}

/// Encrypt and write `value` as the vault. Under dry-run the gpg step is recorded
/// (for `--plan`) but skipped, and no plaintext is written to tmpfs.
pub fn save(runner: &Runner, dir: &Path, value: &Value, pin: &str, dry: bool) -> Result<PathBuf> {
    let path = vault_path(dir);
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| Error::new(Code::EInternal, format!("serialize vault: {e}")))?;

    // Real run: stage the PIN + plaintext in tmpfs and let gpg read them. Dry-run:
    // pass placeholder paths so `--plan` shows the real gpg invocation, write nothing.
    let (_sd, pin_file, plain_file) = if dry {
        (None, "<pin>".to_string(), "<vault-plaintext>".to_string())
    } else {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::new(Code::EEscrowFailed, format!("mkdir key_backup: {e}")))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
        let sd = SecureDir::labeled("vault")?;
        let pf = sd.write_key("pin", pin)?;
        let df = sd.write_key("plain", &json)?;
        (
            Some(sd),
            pf.to_string_lossy().into_owned(),
            df.to_string_lossy().into_owned(),
        )
    };

    // gpg refuses to overwrite silently even with --yes on some versions; remove
    // the old vault first so re-saves are clean.
    if !dry && path.exists() {
        let _ = std::fs::remove_file(&path);
    }

    runner
        .run(
            &encrypt_argv(&pin_file, &plain_file, &path.to_string_lossy())
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            "encrypt the PIN vault with gpg (salted+iterated s2k, AES-256)",
        )?
        .require("gpg --symmetric (vault)")?;

    if !dry {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
    }
    Ok(path)
}

/// Insert/replace one disk's `bundle` in the vault and re-encrypt. Merges into the
/// existing vault (so other disks' entries survive) — except under dry-run, where
/// we start from empty to avoid needing to decrypt during a plan.
pub fn upsert(
    runner: &Runner,
    dir: &Path,
    pin: &str,
    name: &str,
    bundle: &Value,
    dry: bool,
) -> Result<PathBuf> {
    let mut v = if dry {
        empty()
    } else {
        load(runner, dir, pin)?
    };
    if !v.get("disks").map(|d| d.is_object()).unwrap_or(false) {
        v["disks"] = json!({});
    }
    v["disks"][name] = bundle.clone();
    save(runner, dir, &v, pin, dry)
}

/// The disk names present in a loaded vault (proof-of-retrievability without
/// exposing any key material).
pub fn names(vault: &Value) -> Vec<String> {
    vault
        .get("disks")
        .and_then(|d| d.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Fetch one disk's bundle from a loaded vault.
pub fn get<'a>(vault: &'a Value, name: &str) -> Option<&'a Value> {
    vault.get("disks").and_then(|d| d.get(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_path_is_single_file() {
        assert_eq!(
            vault_path(Path::new("/etc/tpmnt/keys")),
            PathBuf::from("/etc/tpmnt/keys/vault.gpg")
        );
    }

    #[test]
    fn encrypt_argv_uses_salted_iterated_s2k_and_aes256() {
        let a = encrypt_argv("/shm/pin", "/shm/plain", "/etc/tpmnt/keys/vault.gpg");
        assert_eq!(a[0], "gpg");
        assert!(a.windows(2).any(|w| w == ["--s2k-mode", "3"]));
        assert!(a.windows(2).any(|w| w == ["--s2k-count", S2K_COUNT]));
        assert!(a.windows(2).any(|w| w == ["--cipher-algo", "AES256"]));
        assert!(a.contains(&"--symmetric".to_string()));
        assert!(a.windows(2).any(|w| w == ["--passphrase-file", "/shm/pin"]));
        // Loopback pinentry so the PIN file is honored non-interactively.
        assert!(a.windows(2).any(|w| w == ["--pinentry-mode", "loopback"]));
        assert_eq!(a.last().unwrap(), "/shm/plain");
    }

    #[test]
    fn decrypt_argv_reads_pin_from_file() {
        let a = decrypt_argv("/shm/pin", "/etc/tpmnt/keys/vault.gpg");
        assert!(a.contains(&"--decrypt".to_string()));
        assert!(a.windows(2).any(|w| w == ["--passphrase-file", "/shm/pin"]));
        assert_eq!(a.last().unwrap(), "/etc/tpmnt/keys/vault.gpg");
    }

    #[test]
    fn names_and_get_read_the_disks_map() {
        let v = json!({
            "tpmnt_vault": 1,
            "disks": {
                "arc": { "passphrase": "p1" },
                "cold": { "passphrase": "p2" }
            }
        });
        let mut n = names(&v);
        n.sort();
        assert_eq!(n, vec!["arc".to_string(), "cold".to_string()]);
        assert_eq!(
            get(&v, "arc").and_then(|b| b.get("passphrase")),
            Some(&json!("p1"))
        );
        assert!(get(&v, "missing").is_none());
    }

    #[test]
    fn missing_vault_file_loads_as_empty() {
        let r = Runner::new(false, false);
        let dir = Path::new("/nonexistent/tpmnt-keys");
        let v = load(&r, dir, "pin1234").unwrap();
        assert_eq!(names(&v), Vec::<String>::new());
    }

    #[test]
    fn save_under_dry_run_traces_gpg_without_writing() {
        let r = Runner::new(true, false);
        let dir = Path::new("/nonexistent/tpmnt-keys");
        let p = save(&r, dir, &empty(), "pin1234", true).unwrap();
        assert_eq!(p, PathBuf::from("/nonexistent/tpmnt-keys/vault.gpg"));
        assert!(!dir.exists());
        let trace = r.trace.borrow();
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].argv[0], "gpg");
        assert!(trace[0].skipped);
    }
}
