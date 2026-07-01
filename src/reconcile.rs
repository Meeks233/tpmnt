//! Idempotent management of /etc/crypttab and /etc/fstab (and systemd mount
//! units). Each managed line is tagged with a trailing `# tpmnt:<name>` marker
//! so re-applying replaces in place rather than duplicating. Every file is
//! backed up to a `.bak` before the first edit in a run.

use std::path::Path;

use crate::config::{Disk, MountBackend};
use crate::error::{Code, Error, Result};

/// What a reconcile pass would do to one managed file, for --dry-run/--plan.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FileChange {
    pub path: String,
    pub action: &'static str, // "create" | "update" | "noop"
    pub line: String,
}

fn marker(name: &str) -> String {
    format!("# tpmnt:{name}")
}

/// Insert or replace the single line tagged for `name`. Returns the change kind.
fn upsert_tagged_line(
    path: &Path,
    name: &str,
    new_line: &str,
    dry_run: bool,
) -> Result<FileChange> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let tag = marker(name);
    let tagged = format!("{new_line}  {tag}");

    let mut found = false;
    let mut changed = false;
    let mut out_lines: Vec<String> = Vec::new();
    for line in existing.lines() {
        if line.trim_end().ends_with(&tag) {
            found = true;
            if line != tagged {
                changed = true;
            }
            out_lines.push(tagged.clone());
        } else {
            out_lines.push(line.to_string());
        }
    }
    if !found {
        out_lines.push(tagged.clone());
        changed = true;
    }

    let action = if !found {
        "create"
    } else if changed {
        "update"
    } else {
        "noop"
    };

    if changed && !dry_run {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::new(Code::EInternal, format!("mkdir: {e}")))?;
        }
        // Back up once before mutating.
        if path.exists() {
            let bak = path.with_extension("bak");
            let _ = std::fs::copy(path, bak);
        }
        let mut content = out_lines.join("\n");
        content.push('\n');
        std::fs::write(path, content)
            .map_err(|e| Error::new(Code::EInternal, format!("write {}: {e}", path.display())))?;
    }

    Ok(FileChange {
        path: path.display().to_string(),
        action,
        line: tagged,
    })
}

/// Build the crypttab line for a disk: TPM2 auto-unlock with a passphrase
/// fallback (`none` keyfield => systemd asks if TPM fails), `nofail` so a
/// missing data disk never blocks boot.
pub fn crypttab_line(disk: &Disk) -> String {
    format!(
        "{} UUID={} none tpm2-device=auto,nofail",
        disk.mapper_name(),
        disk.uuid
    )
}

/// Mount options for a disk. Cold-standby disks get `noatime` so that reads
/// don't generate atime writes that would mask idleness from the power monitor.
/// btrfs (the cold-backup default) also gets `compress=zstd:3` for archival
/// density — transparent, low-CPU, and applied to new writes.
pub fn mount_options(disk: &Disk) -> String {
    let mut opts = vec!["defaults", "nofail"];
    if disk.is_cold_standby() {
        opts.push("noatime");
    }
    if disk.fstype == "btrfs" {
        opts.push("compress=zstd:3");
    }
    opts.join(",")
}

/// fstab fsck pass field: btrfs does its own integrity checking and must not be
/// fsck'd at boot (pass 0); other filesystems get a normal secondary pass (2).
fn fsck_pass(disk: &Disk) -> u8 {
    if disk.fstype == "btrfs" {
        0
    } else {
        2
    }
}

/// Build the fstab line mapping the decrypted device to its mountpoint.
pub fn fstab_line(disk: &Disk) -> String {
    format!(
        "/dev/mapper/{} {} {} {} 0 {}",
        disk.mapper_name(),
        disk.mountpoint.display(),
        disk.fstype,
        mount_options(disk),
        fsck_pass(disk),
    )
}

/// Reconcile crypttab + the configured mount backend for a single disk.
pub fn reconcile_disk(
    crypttab: &Path,
    fstab: &Path,
    unit_dir: &Path,
    disk: &Disk,
    backend: MountBackend,
    dry_run: bool,
) -> Result<Vec<FileChange>> {
    let mut changes = Vec::new();
    changes.push(upsert_tagged_line(
        crypttab,
        &disk.name,
        &crypttab_line(disk),
        dry_run,
    )?);

    match backend {
        MountBackend::Fstab => {
            changes.push(upsert_tagged_line(
                fstab,
                &disk.name,
                &fstab_line(disk),
                dry_run,
            )?);
        }
        MountBackend::Systemd => {
            changes.push(write_mount_unit(unit_dir, disk, dry_run)?);
        }
    }
    Ok(changes)
}

/// systemd .mount unit name is derived from the mountpoint path.
pub fn unit_name_for(mountpoint: &Path) -> String {
    let escaped = mountpoint
        .to_string_lossy()
        .trim_matches('/')
        .replace('-', "\\x2d")
        .replace('/', "-");
    format!("{escaped}.mount")
}

fn write_mount_unit(unit_dir: &Path, disk: &Disk, dry_run: bool) -> Result<FileChange> {
    let unit_name = unit_name_for(&disk.mountpoint);
    let path = unit_dir.join(&unit_name);
    let content = format!(
        "# tpmnt:{name}\n[Unit]\nDescription=tpmnt mount {name}\nRequires=systemd-cryptsetup@{mapper}.service\nAfter=systemd-cryptsetup@{mapper}.service\n\n[Mount]\nWhat=/dev/mapper/{mapper}\nWhere={where_}\nType={fstype}\nOptions={opts}\n\n[Install]\nWantedBy=multi-user.target\n",
        name = disk.name,
        mapper = disk.mapper_name(),
        where_ = disk.mountpoint.display(),
        fstype = disk.fstype,
        opts = mount_options(disk),
    );

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let action = if existing.is_empty() {
        "create"
    } else if existing != content {
        "update"
    } else {
        "noop"
    };
    if action != "noop" && !dry_run {
        std::fs::create_dir_all(unit_dir)
            .map_err(|e| Error::new(Code::EInternal, format!("mkdir unit dir: {e}")))?;
        std::fs::write(&path, &content)
            .map_err(|e| Error::new(Code::EInternal, format!("write unit: {e}")))?;
    }
    Ok(FileChange {
        path: path.display().to_string(),
        action,
        line: unit_name,
    })
}

/// Remove the tagged line for `name` from a file (used by rollback).
pub fn remove_tagged_line(path: &Path, name: &str, dry_run: bool) -> Result<FileChange> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let tag = marker(name);
    let mut removed = false;
    let kept: Vec<&str> = existing
        .lines()
        .filter(|l| {
            let hit = l.trim_end().ends_with(&tag);
            if hit {
                removed = true;
            }
            !hit
        })
        .collect();
    if removed && !dry_run {
        let bak = path.with_extension("bak");
        let _ = std::fs::copy(path, bak);
        let mut content = kept.join("\n");
        if !content.is_empty() {
            content.push('\n');
        }
        std::fs::write(path, content)
            .map_err(|e| Error::new(Code::EInternal, format!("write {}: {e}", path.display())))?;
    }
    Ok(FileChange {
        path: path.display().to_string(),
        action: if removed { "remove" } else { "noop" },
        line: tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Disk;
    use std::path::PathBuf;

    fn disk() -> Disk {
        Disk {
            name: "data".into(),
            uuid: "1111".into(),
            device: None,
            mapper: None,
            mountpoint: PathBuf::from("/mnt/data"),
            fstype: "xfs".into(),
            pcrs: vec![],
            with_pin: false,
            power_profile: crate::config::PowerProfile::AlwaysOn,
            idle_timeout: "5min".into(),
            power_off_method: crate::config::PowerOffMethod::Auto,
            teardown: crate::config::Teardown::Direct,
            schedule: None,
            remote: None,
            transport: None,
        }
    }

    #[test]
    fn crypttab_and_fstab_lines_are_well_formed() {
        let d = disk();
        assert_eq!(
            crypttab_line(&d),
            "tpmnt-data UUID=1111 none tpm2-device=auto,nofail"
        );
        assert_eq!(
            fstab_line(&d),
            "/dev/mapper/tpmnt-data /mnt/data xfs defaults,nofail 0 2"
        );
    }

    #[test]
    fn cold_standby_fstab_adds_noatime() {
        let mut d = disk();
        d.power_profile = crate::config::PowerProfile::ColdStandby;
        assert_eq!(
            fstab_line(&d),
            "/dev/mapper/tpmnt-data /mnt/data xfs defaults,nofail,noatime 0 2"
        );
    }

    #[test]
    fn btrfs_cold_standby_gets_compression_and_pass_zero() {
        let mut d = disk();
        d.fstype = "btrfs".into();
        d.power_profile = crate::config::PowerProfile::ColdStandby;
        assert_eq!(
            fstab_line(&d),
            "/dev/mapper/tpmnt-data /mnt/data btrfs defaults,nofail,noatime,compress=zstd:3 0 0"
        );
    }

    #[test]
    fn upsert_is_idempotent_and_removable() {
        let dir = std::env::temp_dir().join(format!("tpmnt-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("crypttab");
        let line = crypttab_line(&disk());

        let c1 = upsert_tagged_line(&f, "data", &line, false).unwrap();
        assert_eq!(c1.action, "create");
        let c2 = upsert_tagged_line(&f, "data", &line, false).unwrap();
        assert_eq!(c2.action, "noop");
        // Only one tagged line ever present.
        let body = std::fs::read_to_string(&f).unwrap();
        assert_eq!(body.matches("# tpmnt:data").count(), 1);

        let r = remove_tagged_line(&f, "data", false).unwrap();
        assert_eq!(r.action, "remove");
        assert!(!std::fs::read_to_string(&f)
            .unwrap()
            .contains("# tpmnt:data"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
