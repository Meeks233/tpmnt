//! Local at-rest storage for generated LUKS key bundles.
//!
//! The bundle (primary passphrase + recovery key) is **never written in
//! cleartext by default**. It is sealed with `systemd-creds encrypt`, which
//! binds the blob to this host's TPM2 (falling back to the root-only host key
//! at `/var/lib/systemd/credential.secret` when no TPM is present). Decryption
//! therefore requires the same host and root — a convenient local credential
//! with no passphrase to remember. Portable, off-host escrow (age/gpg/pass) is
//! handled separately in `cmd::init`; it exists for the case where this host is
//! lost, which a host-bound seal deliberately can't cover.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::{Code, Error, Result};
use crate::exec::Runner;

/// RAII guard: a private tmpfs dir for keyfiles, removed on drop. Secrets live
/// here only for the lifetime of a single command (e.g. to hand `cryptsetup` a
/// `--key-file`) and never touch persistent storage.
pub struct SecureDir {
    path: PathBuf,
}

impl SecureDir {
    pub fn new() -> Result<SecureDir> {
        Self::labeled("keys")
    }

    /// Like `new`, but with a caller-supplied label in the directory name. Two
    /// SecureDirs alive at once in the same process (e.g. `init`'s key dir plus a
    /// vault op) must not share a path, or one's `Drop` would delete the other's
    /// keyfiles. Distinct labels keep them separate.
    pub fn labeled(label: &str) -> Result<SecureDir> {
        // Prefer tmpfs (/dev/shm) so secrets never touch persistent storage.
        let base = if Path::new("/dev/shm").is_dir() {
            PathBuf::from("/dev/shm")
        } else {
            std::env::temp_dir()
        };
        // /dev/shm is world-writable+sticky (1777). A predictable name plus
        // create_dir_all (which reuses an existing path and follows symlinks)
        // would let a local attacker pre-plant a symlink and capture the
        // cleartext keyfiles. Use an unpredictable name and *exclusive* create
        // (create_dir fails with AlreadyExists rather than reusing/following),
        // so we never write secrets into an attacker-controlled directory.
        let path = base.join(format!(
            "tpmnt-{label}-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir(&path)
            .map_err(|e| Error::new(Code::EInternal, format!("mkdir securedir: {e}")))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::new(Code::EInternal, format!("chmod securedir: {e}")))?;
        Ok(SecureDir { path })
    }

    /// Write a secret to a 0600 keyfile and return its path.
    pub fn write_key(&self, name: &str, secret: &str) -> Result<PathBuf> {
        let p = self.path.join(name);
        std::fs::write(&p, secret.as_bytes())
            .map_err(|e| Error::new(Code::EInternal, format!("write keyfile: {e}")))?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::new(Code::EInternal, format!("chmod keyfile: {e}")))?;
        Ok(p)
    }
}

impl Drop for SecureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 16 hex chars of kernel randomness for an unpredictable tmpfs dir name. Falls
/// back to the high bits of a nanosecond clock if /dev/urandom is unreadable —
/// combined with the exclusive create, an unlucky guess merely errors, never
/// leaks. Linux-only, so /dev/urandom is always present in practice.
fn rand_suffix() -> String {
    use std::io::Read;
    let mut buf = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_err()
    {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        buf = (n as u64).to_le_bytes();
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// The credential name embedded in the sealed blob (used as AAD by
/// systemd-creds). Must match at decrypt time, so it's derived only from the
/// disk name.
fn cred_name(disk: &str) -> String {
    format!("tpmnt-{disk}")
}

/// Path of the sealed local bundle for `disk` under `dir`.
pub fn sealed_path(dir: &Path, disk: &str) -> PathBuf {
    dir.join(format!("{disk}.cred"))
}

/// Seal `plaintext` for `disk` into `<dir>/<disk>.cred` via `systemd-creds`.
/// Returns the output path. Under dry-run the path is returned without writing.
pub fn seal(
    runner: &Runner,
    dir: &Path,
    disk: &str,
    plaintext: &[u8],
    dry: bool,
) -> Result<PathBuf> {
    let out = sealed_path(dir, disk);
    let name = cred_name(disk);
    let out_str = out.to_string_lossy().into_owned();
    // Create the target dir only for real; under dry-run `run_stdin` records the
    // encrypt step as skipped so `--plan` still shows the real invocation.
    if !dry {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::new(Code::EEscrowFailed, format!("mkdir key_backup: {e}")))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
    }
    runner
        .run_stdin(
            &[
                "systemd-creds",
                "encrypt",
                &format!("--name={name}"),
                "-",
                &out_str,
            ],
            plaintext,
            "seal key bundle with systemd-creds (TPM2/host-bound)",
        )?
        .require("systemd-creds encrypt")?;
    if !dry {
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600)).ok();
    }
    Ok(out)
}

/// Decrypt a sealed `<disk>.cred` blob, returning the plaintext bundle JSON.
/// Read-only, so it runs even under --plan/--dry-run (recovery must reflect
/// reality). Requires root + this host's TPM/host-key, which is the auth gate.
pub fn unseal(runner: &Runner, path: &Path, disk: &str) -> Result<String> {
    let name = cred_name(disk);
    let p = path.to_string_lossy().into_owned();
    let out = runner.probe_secret(
        &[
            "systemd-creds",
            "decrypt",
            &format!("--name={name}"),
            &p,
            "-",
        ],
        "unseal key bundle with systemd-creds",
    )?;
    if !out.ok() {
        return Err(Error::new(
            Code::EEscrowFailed,
            format!("systemd-creds decrypt failed (exit {})", out.status),
        )
        .with_hint(if out.stderr.trim().is_empty() {
            "the blob may have been sealed on a different host or the TPM state changed".to_string()
        } else {
            out.stderr.trim().to_string()
        }));
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cred_name_and_sealed_path_are_derived_from_disk() {
        assert_eq!(cred_name("arc"), "tpmnt-arc");
        assert_eq!(
            sealed_path(Path::new("/etc/tpmnt/keys"), "arc"),
            PathBuf::from("/etc/tpmnt/keys/arc.cred")
        );
    }

    #[test]
    fn seal_dry_run_traces_the_command_without_touching_disk() {
        let runner = Runner::new(true, false);
        let dir = Path::new("/nonexistent/key_backup");
        let out = seal(&runner, dir, "arc", b"{}", true).unwrap();
        assert_eq!(out, PathBuf::from("/nonexistent/key_backup/arc.cred"));
        // The dir must NOT have been created under dry-run.
        assert!(!dir.exists());
        // …but the seal step must be recorded so --plan can show it.
        let trace = runner.trace.borrow();
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].argv[0], "systemd-creds");
        assert!(trace[0].skipped);
    }
}
