//! Management classification — the threat-model boundary.
//!
//! tpmnt only claims to *manage* a disk when it can honor its central promise:
//! **the LUKS key was generated or imported locally, and decryption only ever
//! happens on this host.** A disk that fails either test is reported as
//! `unmanaged`: tpmnt will not hold its key or decrypt it — for a remote disk it
//! merely forwards blocks, leaving unlock to whoever owns the key elsewhere.
//!
//! Two independent facts decide it:
//!
//! 1. **Provenance (`local_key`)** — is there a tpmnt key bundle for this disk in
//!    the local key store? tpmnt writes that bundle only when it generated the
//!    key (`init`) or rotated one in (`adopt`). Its presence is the proof that
//!    the key is ours, not a foreign key we happen to forward.
//!
//! 2. **Decrypt site (`local_decrypt`)** — does `cryptsetup open` run here? True
//!    for any local disk; true for a remote disk only when a ciphertext
//!    `transport` is configured (raw blocks forwarded, opened locally). A remote
//!    disk with no transport decrypts off-host, so tpmnt does not manage it.
//!
//! Managed ⇔ `local_key && local_decrypt`. Anything else is unmanaged, with a
//! stable machine `reason` so automation can branch and `tpmnt adopt` can offer
//! the fix.

use std::path::Path;

use serde::Serialize;

use crate::config::{Config, Disk};
use crate::keystore;

/// Per-disk management verdict. Serialized verbatim into `status` JSON, so field
/// names are part of the machine contract.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Management {
    /// The bottom line: does tpmnt manage this disk's key + decryption?
    pub managed: bool,
    /// Stable machine reason code (branch on this): "managed", "foreign-key",
    /// or "remote-decrypt".
    pub reason: &'static str,
    /// Human one-liner explaining the verdict (and, when unmanaged, the fix).
    pub detail: String,
    /// Provenance: a locally-generated/imported key bundle exists for this disk.
    pub local_key: bool,
    /// Decryption runs on this host (never on a remote).
    pub local_decrypt: bool,
}

/// Whether a locally-generated/imported key bundle is on record for `name`.
/// Matches both the sealed default (`<name>.cred`) and the opt-in cleartext
/// bundle (`<name>.json`) that `init`/`adopt` write under `key_backup`.
pub fn local_key_present(key_backup: &Path, name: &str) -> bool {
    keystore::sealed_path(key_backup, name).exists()
        || key_backup.join(format!("{name}.json")).exists()
}

/// Classify a disk against the current config. Pure + filesystem-only (checks
/// for the key bundle); no external commands, so it is safe under `--dry-run`.
pub fn classify(cfg: &Config, disk: &Disk) -> Management {
    // A dangling `remote` name is treated as remote (the safe side): such a disk
    // needs a transport before we'd consider its decryption local.
    let local_decrypt = disk.decrypts_locally();
    let local_key = local_key_present(&cfg.defaults.key_backup, &disk.name);

    if !local_decrypt {
        // Remote disk, no ciphertext transport: tpmnt only forwards.
        return Management {
            managed: false,
            reason: "remote-decrypt",
            detail: "remote disk with no ciphertext transport — tpmnt forwards blocks only \
                     and never decrypts it; run `tpmnt adopt` to forward its ciphertext here \
                     and take ownership"
                .to_string(),
            local_key,
            local_decrypt,
        };
    }
    if !local_key {
        // Decrypts locally, but the key isn't ours: we won't hold a foreign key.
        return Management {
            managed: false,
            reason: "foreign-key",
            detail: "no locally-generated key on record — tpmnt won't hold a foreign key; \
                     run `tpmnt adopt --old-key-file <f> <name>` to rotate in a managed key"
                .to_string(),
            local_key,
            local_decrypt,
        };
    }
    Management {
        managed: true,
        reason: "managed",
        detail: "key generated/imported locally and decryption stays on this host".to_string(),
        local_key,
        local_decrypt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg_with(disk_toml: &str, key_backup: &str) -> Config {
        let mut cfg: Config = toml::from_str(disk_toml).unwrap();
        cfg.defaults.key_backup = PathBuf::from(key_backup);
        cfg
    }

    #[test]
    fn local_disk_without_key_is_foreign_key_unmanaged() {
        let cfg = cfg_with(
            r#"
[[disk]]
name = "l"
uuid = "u"
mountpoint = "/mnt/l"
"#,
            "/nonexistent/keys",
        );
        let m = classify(&cfg, &cfg.disks[0]);
        assert!(!m.managed);
        assert_eq!(m.reason, "foreign-key");
        assert!(m.local_decrypt);
        assert!(!m.local_key);
    }

    #[test]
    fn remote_without_transport_is_forward_only() {
        let cfg = cfg_with(
            r#"
[[disk]]
name = "r"
uuid = "u"
mountpoint = "/mnt/r"
remote = "nas"
"#,
            "/nonexistent/keys",
        );
        let m = classify(&cfg, &cfg.disks[0]);
        assert!(!m.managed);
        assert_eq!(m.reason, "remote-decrypt");
        assert!(!m.local_decrypt);
    }

    #[test]
    fn local_disk_with_sealed_bundle_is_managed() {
        let dir = std::env::temp_dir().join(format!("tpmnt-manage-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(keystore::sealed_path(&dir, "l"), b"sealed").unwrap();

        let cfg = cfg_with(
            r#"
[[disk]]
name = "l"
uuid = "u"
mountpoint = "/mnt/l"
"#,
            &dir.to_string_lossy(),
        );
        let m = classify(&cfg, &cfg.disks[0]);
        assert!(m.managed, "{}", m.detail);
        assert_eq!(m.reason, "managed");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remote_with_transport_and_key_is_managed() {
        let dir = std::env::temp_dir().join(format!("tpmnt-manage-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Cleartext-bundle provenance is honored just like the sealed one.
        std::fs::write(dir.join("r.json"), b"{}").unwrap();

        let cfg = cfg_with(
            r#"
[[disk]]
name = "r"
uuid = "u"
mountpoint = "/mnt/r"
remote = "nas"
transport = "nbd"
"#,
            &dir.to_string_lossy(),
        );
        let m = classify(&cfg, &cfg.disks[0]);
        assert!(m.managed, "{}", m.detail);
        assert!(m.local_key && m.local_decrypt);

        std::fs::remove_dir_all(&dir).ok();
    }
}
