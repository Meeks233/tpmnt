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
}
