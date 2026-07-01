//! Filesystem locations tpmnt reads/writes. All system paths honor a
//! `TPMNT_ROOT` prefix so the self-test harness can redirect crypttab/fstab/
//! units/backups into a throwaway directory without touching the real system.

use std::path::PathBuf;

pub struct Paths {
    root: PathBuf,
}

impl Paths {
    pub fn from_env() -> Paths {
        let root = std::env::var_os("TPMNT_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        Paths { root }
    }

    fn at(&self, rel: &str) -> PathBuf {
        self.root.join(rel.trim_start_matches('/'))
    }

    pub fn crypttab(&self) -> PathBuf {
        self.at("etc/crypttab")
    }

    pub fn fstab(&self) -> PathBuf {
        self.at("etc/fstab")
    }

    pub fn systemd_unit_dir(&self) -> PathBuf {
        self.at("etc/systemd/system")
    }

    /// Directory for udev rules tpmnt installs (e.g. hiding NBD ciphertext
    /// transport devices from udisks/the desktop file manager).
    pub fn udev_rules_dir(&self) -> PathBuf {
        self.at("etc/udev/rules.d")
    }

    /// Directory where LUKS header backups and config .bak files are stored.
    pub fn backup_dir(&self) -> PathBuf {
        self.at("var/lib/tpmnt/backups")
    }

    pub fn header_backup(&self, uuid: &str) -> PathBuf {
        self.backup_dir().join(format!("header-{uuid}.img"))
    }

    /// Per-disk idle-monitor state (last I/O counter + last-change epoch).
    pub fn monitor_state(&self, name: &str) -> PathBuf {
        self.at("var/lib/tpmnt/monitor")
            .join(format!("{name}.json"))
    }

    /// Per-disk schedule state (pending power-off grace deadline / deferral).
    pub fn schedule_state(&self, name: &str) -> PathBuf {
        self.at("var/lib/tpmnt/schedule")
            .join(format!("{name}.json"))
    }

    /// Per-disk forward state for the `remove` power-off method: how to rebuild
    /// the ciphertext forward and rescan the disk back after OS-level removal.
    pub fn forward_state(&self, name: &str) -> PathBuf {
        self.at("var/lib/tpmnt/forward")
            .join(format!("{name}.json"))
    }
}
