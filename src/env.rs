//! Environment detection: distro, systemd, TPM presence, initramfs flavor.
//! Surfaced in `status` and used to warn about known-broken combinations.

use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EnvInfo {
    pub distro_id: String,
    pub systemd_version: Option<u32>,
    pub tpm_rm_present: bool,
    pub tpm_path: Option<String>,
    pub initramfs: Initramfs,
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
            distro_id: detect_distro(),
            systemd_version: detect_systemd_version(),
            tpm_rm_present: Path::new("/dev/tpmrm0").exists(),
            tpm_path: tpm_path(),
            initramfs: detect_initramfs(),
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
