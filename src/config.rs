//! Declarative TOML configuration. This is the portable artifact a user carries
//! between machines; `apply`/`migrate` reconcile the local system to it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Code, Error, Result};

pub const DEFAULT_PATH: &str = "/etc/tpmnt/tpmnt.toml";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default, rename = "disk")]
    pub disks: Vec<Disk>,
    #[serde(default, rename = "remote_mount")]
    pub remote_mounts: Vec<RemoteMount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Defaults {
    #[serde(default = "default_cipher")]
    pub cipher: String,
    #[serde(default = "default_kdf")]
    pub kdf: String,
    #[serde(default = "default_fstype")]
    pub fstype: String,
    #[serde(default = "default_mount_backend")]
    pub mount_backend: MountBackend,
    #[serde(default)]
    pub pcrs: Vec<u32>,
    #[serde(default)]
    pub with_pin: bool,
    #[serde(default = "default_key_backup")]
    pub key_backup: PathBuf,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            cipher: default_cipher(),
            kdf: default_kdf(),
            fstype: default_fstype(),
            mount_backend: default_mount_backend(),
            pcrs: Vec::new(),
            with_pin: false,
            key_backup: default_key_backup(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MountBackend {
    Fstab,
    Systemd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disk {
    pub name: String,
    /// LUKS container UUID (from `cryptsetup luksUUID`).
    pub uuid: String,
    /// Optional explicit device path. When unset, the container is located via
    /// /dev/disk/by-uuid/<uuid>. Useful for stable by-id paths or loop devices.
    #[serde(default)]
    pub device: Option<String>,
    /// Optional explicit dm-crypt mapper name. When unset, defaults to
    /// `tpmnt-<name>`. Set this to manage a disk already opened under another
    /// name (e.g. the distro's `luks-<uuid>` from crypttab).
    #[serde(default)]
    pub mapper: Option<String>,
    pub mountpoint: PathBuf,
    #[serde(default = "default_fstype")]
    pub fstype: String,
    #[serde(default)]
    pub pcrs: Vec<u32>,
    #[serde(default)]
    pub with_pin: bool,
    /// Usage scenario. `always-on` (default) is never touched; `cold-standby`
    /// disks are spun down/powered off after `idle_timeout` with no real access.
    #[serde(default)]
    pub power_profile: PowerProfile,
    /// Idle window before a cold-standby disk powers off. Accepts "5min",
    /// "30s", "10m", "1h", or bare seconds. Ignored for always-on disks.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: String,
    /// How to power the backing disk down (see `PowerOffMethod`).
    #[serde(default)]
    pub power_off_method: PowerOffMethod,
    /// How the mapping is torn down on spindown. `direct` (default) runs raw
    /// `umount` + `cryptsetup close`. `systemd` stops the `.mount` and
    /// `systemd-cryptsetup@<mapper>.service` units instead, so a distro-managed
    /// (crypttab/fstab/automount) disk re-opens cleanly via TPM2 on next access.
    #[serde(default)]
    pub teardown: Teardown,
}

/// How a cold-standby disk's mapping is torn down on spindown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Teardown {
    /// Raw `umount` + `cryptsetup close` (tpmnt owns the mapping).
    #[default]
    Direct,
    /// Stop the systemd `.mount` + `systemd-cryptsetup@` units (distro-managed).
    Systemd,
}

/// Per-disk usage scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PowerProfile {
    /// Continuous use: tpmnt never spins the disk down (default).
    #[default]
    AlwaysOn,
    /// Cold backup/archival: auto power-off after an idle window.
    ColdStandby,
}

impl PowerProfile {
    /// Parse a CLI/config string ("always-on" / "cold-standby"); None if invalid.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "always-on" | "always" | "on" | "continuous" => Some(Self::AlwaysOn),
            "cold-standby" | "cold" | "standby" | "cold-backup" => Some(Self::ColdStandby),
            _ => None,
        }
    }
}

/// How the backing physical disk is powered down on spindown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PowerOffMethod {
    /// power-off for removable/USB, else standby for rotational, else skip.
    #[default]
    Auto,
    /// `hdparm -y`: spin down; auto-wakes on next access.
    Standby,
    /// `hdparm -Y`: lowest power; needs a reset to wake.
    Sleep,
    /// `udisksctl power-off`: truly cut power (USB docks/enclosures).
    PowerOff,
}

impl PowerOffMethod {
    /// Parse a CLI/config string; None if invalid.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "auto" => Some(Self::Auto),
            "standby" => Some(Self::Standby),
            "sleep" => Some(Self::Sleep),
            "power-off" | "poweroff" | "off" => Some(Self::PowerOff),
            _ => None,
        }
    }
}

impl Disk {
    /// The dm-crypt mapper name used in crypttab and at /dev/mapper. Honors an
    /// explicit `mapper` override (for distro-managed `luks-<uuid>` mappings).
    pub fn mapper_name(&self) -> String {
        self.mapper
            .clone()
            .unwrap_or_else(|| format!("tpmnt-{}", self.name))
    }

    /// Resolve the container device path: explicit override or by-uuid symlink.
    pub fn device_path(&self) -> String {
        self.device
            .clone()
            .unwrap_or_else(|| format!("/dev/disk/by-uuid/{}", self.uuid))
    }

    pub fn is_cold_standby(&self) -> bool {
        self.power_profile == PowerProfile::ColdStandby
    }

    /// Parsed idle window in seconds (falls back to 300s on a malformed value).
    pub fn idle_timeout_secs(&self) -> u64 {
        parse_duration(&self.idle_timeout).unwrap_or(300)
    }
}

/// Parse a human duration ("5min", "30s", "10m", "1h", "300") into seconds.
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    let unit = s[digits.len()..].trim().to_ascii_lowercase();
    let mult = match unit.as_str() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hour" | "hours" => 3600,
        "d" | "day" | "days" => 86400,
        _ => return None,
    };
    Some(n * mult)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteMount {
    pub name: String,
    pub host: String,
    pub remote_path: String,
    pub mountpoint: PathBuf,
    #[serde(default)]
    pub jump: Vec<String>,
    #[serde(default)]
    pub identity: Option<PathBuf>,
    #[serde(default)]
    pub sftp_server: Option<String>,
    #[serde(default = "default_true")]
    pub reconnect: bool,
}

fn default_cipher() -> String {
    "aes-xts-plain64".to_string()
}
fn default_kdf() -> String {
    "argon2id".to_string()
}
fn default_fstype() -> String {
    "xfs".to_string()
}
fn default_mount_backend() -> MountBackend {
    MountBackend::Fstab
}
fn default_key_backup() -> PathBuf {
    PathBuf::from("/etc/tpmnt/keys")
}
fn default_idle_timeout() -> String {
    "5min".to_string()
}
fn default_true() -> bool {
    true
}

impl Config {
    /// Load config from disk. A missing file yields an empty default config so
    /// that `status`/`init` work on a fresh system.
    pub fn load(path: &Path) -> Result<Config> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).map_err(|e| {
                Error::new(
                    Code::EConfig,
                    format!("invalid config {}: {e}", path.display()),
                )
                .with_hint("fix the TOML syntax or run `tpmnt init` to generate one")
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => err_config(path, e),
        }
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }
}

fn err_config<T>(path: &Path, e: std::io::Error) -> Result<T> {
    Err(Error::new(
        Code::EConfig,
        format!("cannot read config {}: {e}", path.display()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("300"), Some(300));
        assert_eq!(parse_duration("30s"), Some(30));
        assert_eq!(parse_duration("5min"), Some(300));
        assert_eq!(parse_duration("10m"), Some(600));
        assert_eq!(parse_duration("1h"), Some(3600));
        assert_eq!(parse_duration("2 hours"), Some(7200));
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("5years"), None);
    }

    #[test]
    fn power_profile_defaults_are_back_compatible() {
        // A disk table without the new keys must still parse.
        let cfg: Config = toml::from_str(
            r#"
[[disk]]
name = "d"
uuid = "u"
mountpoint = "/mnt/d"
"#,
        )
        .unwrap();
        let d = &cfg.disks[0];
        assert_eq!(d.power_profile, PowerProfile::AlwaysOn);
        assert!(!d.is_cold_standby());
        assert_eq!(d.idle_timeout_secs(), 300);
        assert_eq!(d.power_off_method, PowerOffMethod::Auto);
    }

    #[test]
    fn cold_standby_parses() {
        let cfg: Config = toml::from_str(
            r#"
[[disk]]
name = "cold"
uuid = "u"
mountpoint = "/mnt/cold"
power_profile = "cold-standby"
idle_timeout = "10m"
power_off_method = "power-off"
"#,
        )
        .unwrap();
        let d = &cfg.disks[0];
        assert!(d.is_cold_standby());
        assert_eq!(d.idle_timeout_secs(), 600);
        assert_eq!(d.power_off_method, PowerOffMethod::PowerOff);
    }
}
