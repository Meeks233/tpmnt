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
    /// SSH remotes this machine controls. A [[disk]] with `remote = "<name>"`
    /// lives on the matching remote; tpmnt runs that disk's operations there
    /// over SSH, transparently. Which host a disk sits on is surfaced only in
    /// the dashboard — ordinary disk operations don't require knowing it.
    #[serde(default, rename = "remote")]
    pub remotes: Vec<Remote>,
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
    /// Global cold-standby idle window before the platters are spun down to
    /// standby (mapping kept open, wakes on next access). A per-disk
    /// `standby_timeout` overrides this. There is deliberately no auto power-off
    /// stage: research shows standby already captures ~all the HDD-lifespan
    /// benefit a full power-off would (both cost the same start/stop cycle on
    /// wake), so tpmnt rests idle disks at standby and never auto-powers-off.
    /// Full power-off is a manual, explicit action (`tpmnt power … --method`).
    #[serde(default = "default_standby_timeout")]
    pub standby_timeout: String,
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
            standby_timeout: default_standby_timeout(),
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
    /// Usage scenario. `cold-standby` (default) disks are spun down to standby
    /// after `standby_timeout` with no real access and then rest there (tpmnt
    /// never auto-powers-off); `always-on` is never touched.
    #[serde(default)]
    pub power_profile: PowerProfile,
    /// Per-disk override for the idle window before the platters are spun down to
    /// standby (mapping kept open). Unset = the global `[defaults].standby_timeout`.
    /// Accepts "5min", "30s", "10m", "1h", or bare seconds. Ignored for always-on
    /// disks. The legacy `idle_timeout` key is accepted as an alias.
    #[serde(default, alias = "idle_timeout")]
    pub standby_timeout: Option<String>,
    /// How to power the backing disk down (see `PowerOffMethod`).
    #[serde(default)]
    pub power_off_method: PowerOffMethod,
    /// How the mapping is torn down on spindown. `direct` (default) runs raw
    /// `umount` + `cryptsetup close`. `systemd` stops the `.mount` and
    /// `systemd-cryptsetup@<mapper>.service` units instead, so a distro-managed
    /// (crypttab/fstab/automount) disk re-opens cleanly via TPM2 on next access.
    #[serde(default)]
    pub teardown: Teardown,
    /// Optional daily on/off schedule. When set, `tpmnt schedule <name>` powers
    /// the disk up inside the window and down outside it (data-safety gated).
    #[serde(default)]
    pub schedule: Option<Schedule>,
    /// Name of the [[remote]] this disk lives on. Unset = a local disk (the
    /// default). When set, tpmnt runs this disk's cryptsetup/mount operations on
    /// that remote over SSH; the disk's `uuid`/`device` are interpreted there.
    #[serde(default)]
    pub remote: Option<String>,
    /// For a REMOTE disk, how its *ciphertext* block device is forwarded to this
    /// host so decryption happens locally (never on the remote). When set, tpmnt
    /// attaches the remote's raw LUKS blocks here and runs `cryptsetup open`
    /// locally — the key never leaves this machine. Unset on a remote disk means
    /// tpmnt does NOT manage its decryption: it only forwards (see the threat
    /// model in `manage.rs`). Ignored for local disks (they decrypt locally by
    /// definition). `tpmnt adopt` sets this when taking ownership of a remote disk.
    #[serde(default)]
    pub transport: Option<Transport>,
}

/// How a remote disk's *ciphertext* block device is carried to this host so
/// LUKS is unlocked locally (the key never leaves this machine). This is the
/// industry pattern for untrusted remote storage: export the raw encrypted
/// blocks, decrypt at the client. Confidentiality holds even over a plaintext
/// link because only LUKS ciphertext crosses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// Network Block Device tunneled over SSH (default). `qemu-nbd` serves the
    /// raw ciphertext on the remote; `nbd-client` attaches it here through an
    /// `ssh -L` tunnel. Simple, widely packaged, supports TRIM/discard, and the
    /// SSH tunnel adds integrity + hides access patterns on top of LUKS. Best
    /// default for a WAN / untrusted path.
    #[default]
    Nbd,
    /// NVMe-over-TCP: lowest protocol overhead and highest small-block IOPS on a
    /// trusted LAN (outperforms iSCSI). `nvmet` exports the ciphertext on the
    /// remote; `nvme connect` imports it here, then LUKS opens locally. Prefer on
    /// a fast, trusted link where the SSH-tunnel CPU cost of NBD would cap speed.
    NvmeTcp,
}

impl Transport {
    /// Parse a CLI/config string ("nbd" / "nvme-tcp"); None if invalid.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "nbd" => Some(Self::Nbd),
            "nvme-tcp" | "nvmetcp" | "nvme" | "tcp" => Some(Self::NvmeTcp),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Nbd => "nbd",
            Transport::NvmeTcp => "nvme-tcp",
        }
    }
}

/// An SSH-reachable machine tpmnt controls. Purely a connection registry: the
/// disks it holds are the [[disk]] entries whose `remote` matches `name`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remote {
    /// Stable name referenced by `disk.remote`.
    pub name: String,
    /// SSH destination: user@addr[:port].
    pub host: String,
    /// Optional jump/bastion host(s): user@host[:port]. Comma-separated or
    /// repeated; routed via SSH `-J` (ProxyJump).
    #[serde(default)]
    pub jump: Vec<String>,
    /// Optional SSH identity (private key) file.
    #[serde(default)]
    pub identity: Option<PathBuf>,
}

impl Remote {
    /// The SSH argv prefix that runs a command on this remote. Prepended to a
    /// disk's local argv so `Runner::probe_on` executes it there. Empty jump +
    /// no identity yields a plain `ssh -o … <host>`.
    pub fn ssh_prefix(&self) -> Vec<String> {
        let mut argv = vec![
            "ssh".to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "ConnectTimeout=8".into(),
        ];
        if let Some(id) = &self.identity {
            argv.push("-o".into());
            argv.push("IdentitiesOnly=yes".into());
            argv.push("-i".into());
            argv.push(expand_tilde(&id.to_string_lossy()));
        }
        let jumps: Vec<String> = self
            .jump
            .iter()
            .flat_map(|j| j.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !jumps.is_empty() {
            argv.push("-J".into());
            argv.push(jumps.join(","));
        }
        let (host, port) = match self.host.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), Some(p.to_string())),
            _ => (self.host.clone(), None),
        };
        if let Some(p) = port {
            argv.push("-p".into());
            argv.push(p);
        }
        argv.push(host);
        argv
    }
}

/// Expand a leading `~/` to `$HOME` (mirrors mount_remote's helper; kept local
/// so config has no cross-module dependency).
fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        format!("{home}/{rest}")
    } else {
        p.to_string()
    }
}

/// A daily wall-clock window during which a disk should be powered on. Outside
/// the window `tpmnt schedule` tries to power the disk down, but never forces a
/// busy disk off (it waits a grace, then defers) so data transfer is preserved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    /// Local time the disk should power on, "HH:MM" (24-hour).
    pub on: String,
    /// Local time the disk should power off, "HH:MM" (24-hour). An `off` earlier
    /// than `on` denotes an overnight window (e.g. on=20:00, off=06:00).
    pub off: String,
    /// Timezone for `on`/`off`: a fixed UTC offset ("+08:00", "-0530", "Z") or an
    /// IANA name ("Asia/Shanghai") resolved via the system tzdata. Unset = the
    /// host's local time.
    #[serde(default)]
    pub timezone: Option<String>,
}

impl Schedule {
    fn on_secs(&self) -> u32 {
        parse_hm(&self.on).unwrap_or(0)
    }
    fn off_secs(&self) -> u32 {
        parse_hm(&self.off).unwrap_or(0)
    }

    /// Whether a second-of-day (0..86400) falls inside the on-window. Equal
    /// on/off means a 24h window (always on; never schedule-off).
    pub fn contains(&self, tod: u32) -> bool {
        let (on, off) = (self.on_secs(), self.off_secs());
        if on == off {
            true
        } else if on < off {
            tod >= on && tod < off
        } else {
            tod >= on || tod < off
        }
    }

    /// Total length of the on-window in seconds (the "总开机时间").
    pub fn on_window_secs(&self) -> u32 {
        let (on, off) = (self.on_secs(), self.off_secs());
        if on == off {
            86_400
        } else if off > on {
            off - on
        } else {
            86_400 - (on - off)
        }
    }

    /// Grace to wait for a busy disk before deferring power-off: 10% of the
    /// on-window.
    pub fn grace_secs(&self) -> u64 {
        (self.on_window_secs() as u64) / 10
    }
}

/// Parse a "HH:MM" (or "H:MM") 24-hour time into seconds-of-day. None if malformed.
pub fn parse_hm(s: &str) -> Option<u32> {
    let (h, m) = s.trim().split_once(':')?;
    let h: u32 = h.trim().parse().ok()?;
    let m: u32 = m.trim().parse().ok()?;
    if h >= 24 || m >= 60 {
        return None;
    }
    Some(h * 3600 + m * 60)
}

/// Parse a UTC offset ("+08:00", "+0800", "+8", "-0530", "Z"/"UTC") into seconds
/// east of UTC. None if it is not a fixed offset (e.g. an IANA zone name).
pub fn parse_utc_offset(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("z") || s.eq_ignore_ascii_case("utc") {
        return Some(0);
    }
    let (sign, rest) = match s.strip_prefix('-') {
        Some(r) => (-1, r),
        None => (1, s.strip_prefix('+')?),
    };
    let digits: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
    let (h, m): (u32, u32) = match (rest.split_once(':'), digits.len()) {
        (Some((hh, mm)), _) => (hh.trim().parse().ok()?, mm.trim().parse().ok()?),
        (None, 0) => return None,
        (None, 1 | 2) => (digits.parse().ok()?, 0),
        (None, _) => (
            digits[..digits.len() - 2].parse().ok()?,
            digits[digits.len() - 2..].parse().ok()?,
        ),
    };
    if h >= 24 || m >= 60 {
        return None;
    }
    Some(sign * (h as i64 * 3600 + m as i64 * 60))
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
    /// Continuous use: tpmnt never spins the disk down.
    AlwaysOn,
    /// Cold backup/archival: auto power-off after an idle window (default).
    /// A disk that doesn't declare a profile is treated as cold-standby.
    #[default]
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
    /// Spin down, then **remove the backing block device from its host OS**
    /// (`echo 1 > /sys/block/<dev>/device/delete`) — the disk disappears from
    /// the OS entirely, exactly like a disk manager's "Power Off Disk". Fully
    /// reversible: spin-up rescans the SCSI host (`.../scan`) to bring it back,
    /// so unlike `sleep` no physical replug is needed. For a remote NBD disk the
    /// ciphertext forward is torn down before removal and rebuilt on spin-up.
    Remove,
}

impl PowerOffMethod {
    /// Parse a CLI/config string; None if invalid.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "auto" => Some(Self::Auto),
            "standby" => Some(Self::Standby),
            "sleep" => Some(Self::Sleep),
            "power-off" | "poweroff" | "off" => Some(Self::PowerOff),
            "remove" | "eject" | "detach" => Some(Self::Remove),
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

    /// Whether decryption of this disk happens on THIS host — the pivot of the
    /// threat model. True for any local disk (`remote` unset); true for a remote
    /// disk only when a ciphertext `transport` is configured (its raw blocks are
    /// forwarded here and `cryptsetup open` runs locally). A remote disk with no
    /// transport is forward-only: tpmnt never holds its key or decrypts it.
    ///
    /// NB: this reads the disk in isolation; a dangling `remote` name (no matching
    /// `[[remote]]`) is treated as remote here, which is the safe side — such a
    /// disk needs a transport to be considered locally-decrypting.
    pub fn decrypts_locally(&self) -> bool {
        self.remote.is_none() || self.transport.is_some()
    }

    /// Idle window (seconds) before the platters are spun down to standby: the
    /// per-disk override if set, else the global default, else 300s (5min).
    pub fn standby_timeout_secs(&self, defaults: &Defaults) -> u64 {
        self.standby_timeout
            .as_deref()
            .and_then(parse_duration)
            .or_else(|| parse_duration(&defaults.standby_timeout))
            .unwrap_or(300)
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
fn default_standby_timeout() -> String {
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

    /// Persist the config to `path`, creating the parent directory. Used by
    /// commands that mutate the declarative source of truth (e.g. `adopt` setting
    /// a disk's transport when taking ownership).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, self.to_toml()).map_err(|e| {
            Error::new(
                Code::EConfig,
                format!("write config {}: {e}", path.display()),
            )
        })
    }

    /// The [[remote]] a disk lives on, if any. None = a local disk (or a
    /// dangling `remote` name with no matching entry — callers treat that as
    /// local so a typo can't silently ssh nowhere).
    pub fn remote_for(&self, disk: &Disk) -> Option<&Remote> {
        let name = disk.remote.as_deref()?;
        self.remotes.iter().find(|r| r.name == name)
    }

    /// SSH argv prefix to run `disk`'s operations on its remote; empty for a
    /// local disk. Threaded into `Runner::probe_on`/`run_on`.
    pub fn ssh_prefix_for(&self, disk: &Disk) -> Vec<String> {
        self.remote_for(disk)
            .map(Remote::ssh_prefix)
            .unwrap_or_default()
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
        // A disk table without the new keys must still parse. An undeclared
        // profile defaults to cold-standby.
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
        assert_eq!(d.power_profile, PowerProfile::ColdStandby);
        assert!(d.is_cold_standby());
        let defs = Defaults::default();
        // An undeclared standby window falls back to the global default: 5min.
        assert_eq!(d.standby_timeout_secs(&defs), 300);
        assert_eq!(d.power_off_method, PowerOffMethod::Auto);
    }

    #[test]
    fn parse_hm_and_offset() {
        assert_eq!(parse_hm("08:00"), Some(28_800));
        assert_eq!(parse_hm("8:05"), Some(29_100));
        assert_eq!(parse_hm("23:59"), Some(86_340));
        assert_eq!(parse_hm("24:00"), None);
        assert_eq!(parse_hm("8"), None);
        assert_eq!(parse_utc_offset("+08:00"), Some(28_800));
        assert_eq!(parse_utc_offset("+0800"), Some(28_800));
        assert_eq!(parse_utc_offset("+8"), Some(28_800));
        assert_eq!(parse_utc_offset("-0530"), Some(-19_800));
        assert_eq!(parse_utc_offset("Z"), Some(0));
        assert_eq!(parse_utc_offset("Asia/Shanghai"), None);
    }

    #[test]
    fn schedule_window_and_grace() {
        // Daytime window 08:00–23:00 (15h on).
        let day = Schedule {
            on: "08:00".into(),
            off: "23:00".into(),
            timezone: None,
        };
        assert!(day.contains(parse_hm("12:00").unwrap()));
        assert!(!day.contains(parse_hm("02:00").unwrap()));
        assert_eq!(day.on_window_secs(), 15 * 3600);
        assert_eq!(day.grace_secs(), (15 * 3600) / 10);

        // Overnight window 20:00–06:00 (10h on).
        let night = Schedule {
            on: "20:00".into(),
            off: "06:00".into(),
            timezone: None,
        };
        assert!(night.contains(parse_hm("23:00").unwrap()));
        assert!(night.contains(parse_hm("05:00").unwrap()));
        assert!(!night.contains(parse_hm("12:00").unwrap()));
        assert_eq!(night.on_window_secs(), 10 * 3600);
    }

    #[test]
    fn schedule_parses_from_toml() {
        let cfg: Config = toml::from_str(
            r#"
[[disk]]
name = "arc"
uuid = "u"
mountpoint = "/mnt/arc"

[disk.schedule]
on = "08:00"
off = "23:00"
timezone = "Asia/Shanghai"
"#,
        )
        .unwrap();
        let s = cfg.disks[0].schedule.as_ref().unwrap();
        assert_eq!(s.on, "08:00");
        assert_eq!(s.timezone.as_deref(), Some("Asia/Shanghai"));
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
standby_timeout = "10m"
power_off_method = "power-off"
"#,
        )
        .unwrap();
        let d = &cfg.disks[0];
        let defs = Defaults::default();
        assert!(d.is_cold_standby());
        assert_eq!(d.standby_timeout_secs(&defs), 600);
        assert_eq!(d.power_off_method, PowerOffMethod::PowerOff);
    }

    #[test]
    fn standby_override_and_legacy_alias() {
        // Global default raised; one disk overrides standby, the other uses the
        // legacy `idle_timeout` key (alias for standby_timeout).
        let cfg: Config = toml::from_str(
            r#"
[defaults]
standby_timeout = "2min"

[[disk]]
name = "a"
uuid = "u1"
mountpoint = "/mnt/a"
standby_timeout = "90s"

[[disk]]
name = "b"
uuid = "u2"
mountpoint = "/mnt/b"
idle_timeout = "45s"

[[disk]]
name = "c"
uuid = "u3"
mountpoint = "/mnt/c"
"#,
        )
        .unwrap();
        let defs = &cfg.defaults;
        // Disk a: per-disk standby overrides the global default.
        assert_eq!(cfg.disks[0].standby_timeout_secs(defs), 90);
        // Disk b: legacy idle_timeout populates standby via serde alias.
        assert_eq!(cfg.disks[1].standby_timeout_secs(defs), 45);
        // Disk c: no override -> the global default (2min).
        assert_eq!(cfg.disks[2].standby_timeout_secs(defs), 120);
    }

    #[test]
    fn power_off_method_parses_all_aliases() {
        use PowerOffMethod::*;
        assert_eq!(PowerOffMethod::parse("auto"), Some(Auto));
        assert_eq!(PowerOffMethod::parse("standby"), Some(Standby));
        assert_eq!(PowerOffMethod::parse("sleep"), Some(Sleep));
        assert_eq!(PowerOffMethod::parse("power-off"), Some(PowerOff));
        // The new OS-level removal method and its aliases.
        assert_eq!(PowerOffMethod::parse("remove"), Some(Remove));
        assert_eq!(PowerOffMethod::parse("eject"), Some(Remove));
        assert_eq!(PowerOffMethod::parse("detach"), Some(Remove));
        assert_eq!(PowerOffMethod::parse("nonsense"), None);
    }

    #[test]
    fn disk_without_remote_is_local() {
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
        assert!(d.remote.is_none());
        assert!(cfg.remote_for(d).is_none());
        assert!(cfg.ssh_prefix_for(d).is_empty());
    }

    #[test]
    fn multi_remote_registry_and_disk_association() {
        let cfg: Config = toml::from_str(
            r#"
[[remote]]
name = "nas"
host = "alice@192.168.5.10"

[[remote]]
name = "shed"
host = "bob@10.0.0.9:2222"
jump = ["gw@bastion"]
identity = "/keys/shed"

[[disk]]
name = "arc"
uuid = "u1"
mountpoint = "/mnt/arc"
remote = "shed"
"#,
        )
        .unwrap();
        assert_eq!(cfg.remotes.len(), 2);
        let d = &cfg.disks[0];
        assert!(d.remote.is_some());
        let r = cfg.remote_for(d).unwrap();
        assert_eq!(r.name, "shed");

        // ssh prefix carries identity, jump, and the split-off port.
        let pfx = cfg.ssh_prefix_for(d);
        assert_eq!(pfx.first().map(String::as_str), Some("ssh"));
        assert!(pfx.contains(&"-i".to_string()));
        assert!(pfx.contains(&"/keys/shed".to_string()));
        assert!(pfx.contains(&"-J".to_string()));
        assert!(pfx.contains(&"gw@bastion".to_string()));
        assert!(pfx.contains(&"-p".to_string()));
        assert!(pfx.contains(&"2222".to_string()));
        // host is the last element, port stripped.
        assert_eq!(pfx.last().map(String::as_str), Some("bob@10.0.0.9"));
    }

    #[test]
    fn dangling_remote_name_is_treated_as_local() {
        // A typo'd remote name must not silently ssh nowhere.
        let cfg: Config = toml::from_str(
            r#"
[[disk]]
name = "d"
uuid = "u"
mountpoint = "/mnt/d"
remote = "does-not-exist"
"#,
        )
        .unwrap();
        let d = &cfg.disks[0];
        assert!(d.remote.is_some());
        assert!(cfg.remote_for(d).is_none());
        assert!(cfg.ssh_prefix_for(d).is_empty());
    }

    #[test]
    fn transport_parse_and_decrypt_site() {
        assert_eq!(Transport::parse("nbd"), Some(Transport::Nbd));
        assert_eq!(Transport::parse("nvme-tcp"), Some(Transport::NvmeTcp));
        assert_eq!(Transport::parse("NVMe_TCP"), Some(Transport::NvmeTcp));
        assert_eq!(Transport::parse("iscsi"), None);

        // A local disk always decrypts locally.
        let cfg: Config = toml::from_str(
            r#"
[[disk]]
name = "l"
uuid = "u"
mountpoint = "/mnt/l"
"#,
        )
        .unwrap();
        assert!(cfg.disks[0].decrypts_locally());

        // A remote disk WITHOUT a transport is forward-only (not local-decrypt).
        let cfg: Config = toml::from_str(
            r#"
[[disk]]
name = "r"
uuid = "u"
mountpoint = "/mnt/r"
remote = "nas"
"#,
        )
        .unwrap();
        assert!(cfg.disks[0].transport.is_none());
        assert!(!cfg.disks[0].decrypts_locally());

        // A remote disk WITH a transport forwards ciphertext + decrypts locally.
        let cfg: Config = toml::from_str(
            r#"
[[disk]]
name = "r"
uuid = "u"
mountpoint = "/mnt/r"
remote = "nas"
transport = "nvme-tcp"
"#,
        )
        .unwrap();
        assert_eq!(cfg.disks[0].transport, Some(Transport::NvmeTcp));
        assert!(cfg.disks[0].decrypts_locally());
    }

    #[test]
    fn plain_remote_no_jump_no_identity() {
        let r = Remote {
            name: "nas".into(),
            host: "alice@192.168.5.10".into(),
            jump: vec![],
            identity: None,
        };
        let pfx = r.ssh_prefix();
        assert!(!pfx.contains(&"-J".to_string()));
        assert!(!pfx.contains(&"-i".to_string()));
        assert!(!pfx.contains(&"-p".to_string()));
        assert_eq!(pfx.last().map(String::as_str), Some("alice@192.168.5.10"));
    }
}
