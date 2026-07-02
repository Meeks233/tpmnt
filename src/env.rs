//! Environment detection: distro, systemd, TPM presence, initramfs flavor.
//! Surfaced in `status` and used to warn about known-broken combinations.

use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EnvInfo {
    /// This machine's own hostname — titles the "self" box in the dashboard,
    /// symmetric with the hostname-named remotes.
    pub hostname: String,
    pub distro_id: String,
    pub systemd_version: Option<u32>,
    pub tpm_rm_present: bool,
    pub tpm_path: Option<String>,
    pub initramfs: Initramfs,
    /// Effective uid is 0. Reading LUKS headers (`cryptsetup luksDump`) and the
    /// root-only key store both require this; without it `status`/`dashboard`
    /// silently misreport every disk as "not LUKS2" and "unmanaged".
    pub privileged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(clippy::enum_variant_names)] // "initramfs-tools" is the real tool name
pub enum Initramfs {
    Dracut,
    InitramfsTools,
    Unknown,
}

impl EnvInfo {
    pub fn detect() -> EnvInfo {
        EnvInfo {
            hostname: detect_hostname(),
            distro_id: detect_distro(),
            systemd_version: detect_systemd_version(),
            tpm_rm_present: Path::new("/dev/tpmrm0").exists(),
            tpm_path: tpm_path(),
            initramfs: detect_initramfs(),
            privileged: detect_privileged(),
        }
    }

    /// Warn when initramfs-tools is in use: it ignores `tpm2-device=` for ROOT
    /// disks. Data/secondary disks are unaffected (handled post-boot).
    pub fn initramfs_warns_for_root(&self) -> bool {
        self.initramfs == Initramfs::InitramfsTools
    }
}

fn tpm_path() -> Option<String> {
    for p in ["/dev/tpmrm0", "/dev/tpm0"] {
        if Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

/// The live kernel hostname (what `hostname` prints), trimmed. Falls back to the
/// static `/etc/hostname`, then "localhost".
fn detect_hostname() -> String {
    for p in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(s) = std::fs::read_to_string(p) {
            let h = s.trim();
            if !h.is_empty() {
                return h.to_string();
            }
        }
    }
    "localhost".to_string()
}

fn detect_distro() -> String {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("ID=") {
            return rest.trim_matches('"').to_string();
        }
    }
    "unknown".to_string()
}

fn detect_systemd_version() -> Option<u32> {
    let out = std::process::Command::new("systemctl")
        .arg("--version")
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    // First line looks like: "systemd 255 (255.4-1)"
    let first = s.lines().next()?;
    let token = first.split_whitespace().nth(1)?;
    token
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()
}

/// Effective uid == 0, read without a `libc` dependency from `/proc/self/status`.
/// The `Uid:` line is `real<TAB>effective<TAB>saved<TAB>fs`; the effective uid is
/// the one that governs file access. Missing/unparsable `/proc` conservatively
/// reads as unprivileged so we warn rather than falsely claim full access.
fn detect_privileged() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|rest| rest.split_whitespace().nth(1).map(|s| s.to_string()))
        })
        .map(|euid| euid == "0")
        .unwrap_or(false)
}

fn detect_initramfs() -> Initramfs {
    if Path::new("/usr/bin/dracut").exists() || Path::new("/usr/sbin/dracut").exists() {
        Initramfs::Dracut
    } else if Path::new("/usr/sbin/update-initramfs").exists()
        || Path::new("/etc/initramfs-tools").exists()
    {
        Initramfs::InitramfsTools
    } else {
        Initramfs::Unknown
    }
}
