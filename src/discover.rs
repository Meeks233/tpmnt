//! Auto-discovery — find where a configured disk physically lives *right now*
//! and rebind the config so it stays reachable + locally-decrypted no matter
//! where it moved.
//!
//! A disk is identified by its stable LUKS2 **UUID**, not by a device path or a
//! host. The path (`/dev/sdb`), the host (a `[[remote]]`), even the transport can
//! all change when someone physically relocates the disk — pulls it out of the
//! NAS and plugs it into this laptop, or moves it from one remote to another. The
//! user does not know (and shouldn't have to care) where it currently sits: they
//! just want it accessible here, decrypted here. `locate` probes every candidate
//! location for the disk's UUID and `rebind` rewrites the disk's binding to match
//! what was found, preserving the threat-model invariant that decryption always
//! happens on THIS host:
//!
//!   * found **locally**  → `remote = None`, `transport = None`, device resolved
//!     via the stable `/dev/disk/by-uuid/<uuid>` symlink (survives the next move);
//!   * found on a **remote** → `remote = <that remote>`, `device = <path there>`,
//!     `transport = nbd` (ciphertext forwarded here, `cryptsetup open` runs local).
//!
//! Probing is read-only (`blkid -U <uuid>`), so it is safe under `--dry-run` and
//! reflects reality for planning. Nothing here mounts or decrypts; it only tells
//! the caller where the disk is and how the config should point at it.

use serde::Serialize;

use crate::config::{Disk, Remote, Transport};
use crate::exec::Runner;

/// Where a disk's LUKS UUID was found. `Absent` means it is currently unplugged
/// / unreachable everywhere tpmnt knows to look — the binding is left untouched.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "where", rename_all = "kebab-case")]
pub enum Location {
    /// Present as a local block device (path is the raw device blkid reported).
    Local { device: String },
    /// Present on a known remote (its `name`) at `device` over there.
    Remote { remote: String, device: String },
    /// Not found anywhere reachable.
    Absent,
}

impl Location {
    pub fn found(&self) -> bool {
        !matches!(self, Location::Absent)
    }
}

/// Locate a disk by its LUKS UUID: probe this host first (a locally-attached disk
/// is always preferred — decryption is cheapest and safest here), then each known
/// remote over SSH. The first hit wins. Read-only; safe under dry-run.
pub fn locate(runner: &Runner, remotes: &[Remote], disk: &Disk) -> Location {
    if disk.uuid.trim().is_empty() {
        return Location::Absent;
    }
    if let Some(device) = blkid_local(runner, &disk.uuid) {
        return Location::Local { device };
    }
    for r in remotes {
        if let Some(device) = blkid_remote(runner, r, &disk.uuid) {
            return Location::Remote {
                remote: r.name.clone(),
                device,
            };
        }
    }
    Location::Absent
}

/// Resolve a UUID to a local device path via `blkid -U`. blkid reports a LUKS2
/// container's own UUID, so this finds the ciphertext device directly. `None`
/// when the UUID is not present locally.
fn blkid_local(runner: &Runner, uuid: &str) -> Option<String> {
    let out = runner
        .probe(&["blkid", "-U", uuid], "locate disk by LUKS UUID (local)")
        .ok()?;
    let dev = out.stdout.trim();
    if out.ok() && !dev.is_empty() {
        Some(dev.to_string())
    } else {
        None
    }
}

/// Resolve a UUID to a device path on `remote` over SSH. Reading a root-owned
/// block device needs privilege, so blkid runs under `sudo -n` (mirroring the
/// qemu-nbd ciphertext export). `None` when unreachable or the UUID isn't there.
fn blkid_remote(runner: &Runner, remote: &Remote, uuid: &str) -> Option<String> {
    let prefix = remote.ssh_prefix();
    let out = runner
        .probe_on(
            &prefix,
            &["sudo", "-n", "blkid", "-U", uuid],
            "locate disk by LUKS UUID (remote)",
        )
        .ok()?;
    let dev = out.stdout.trim();
    if out.ok() && !dev.is_empty() {
        Some(dev.to_string())
    } else {
        None
    }
}

/// Rewrite `disk`'s binding to match where it was just found, keeping decryption
/// on this host. Returns `true` when the binding actually changed (so the caller
/// knows to persist the config and reconcile). An `Absent` disk is left alone.
pub fn rebind(disk: &mut Disk, loc: &Location) -> bool {
    match loc {
        Location::Local { .. } => {
            let mut changed = false;
            if disk.remote.take().is_some() {
                changed = true;
            }
            if disk.transport.take().is_some() {
                changed = true;
            }
            // Coming back from a remote leaves a stale remote device path behind;
            // drop it so `device_path()` resolves via the stable by-uuid symlink.
            if changed && disk.device.is_some() {
                disk.device = None;
            }
            changed
        }
        Location::Remote { remote, device } => {
            let mut changed = false;
            if disk.remote.as_deref() != Some(remote.as_str()) {
                disk.remote = Some(remote.clone());
                changed = true;
            }
            if disk.device.as_deref() != Some(device.as_str()) {
                disk.device = Some(device.clone());
                changed = true;
            }
            // A managed remote must forward its ciphertext here to keep decryption
            // local; default to NBD if no transport was recorded yet.
            if disk.transport.is_none() {
                disk.transport = Some(Transport::Nbd);
                changed = true;
            }
            changed
        }
        Location::Absent => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn disk(name: &str) -> Disk {
        Disk {
            name: name.into(),
            uuid: "u-123".into(),
            device: None,
            mapper: None,
            mountpoint: PathBuf::from(format!("/mnt/{name}")),
            fstype: "btrfs".into(),
            pcrs: vec![],
            with_pin: false,
            power_profile: crate::config::PowerProfile::default(),
            standby_timeout: None,
            power_off_method: crate::config::PowerOffMethod::default(),
            teardown: crate::config::Teardown::Direct,
            schedule: None,
            remote: None,
            transport: None,
        }
    }

    #[test]
    fn rebind_moves_remote_disk_home_to_local() {
        let mut d = disk("arc");
        d.remote = Some("nas".into());
        d.device = Some("/dev/sda".into());
        d.transport = Some(Transport::Nbd);

        let changed = rebind(
            &mut d,
            &Location::Local {
                device: "/dev/sdb1".into(),
            },
        );
        assert!(changed);
        assert!(d.remote.is_none());
        assert!(d.transport.is_none());
        // Stale remote device path dropped -> resolves via by-uuid.
        assert!(d.device.is_none());
        assert_eq!(d.device_path(), "/dev/disk/by-uuid/u-123");
        assert!(d.decrypts_locally());
    }

    #[test]
    fn rebind_local_disk_already_home_is_noop() {
        let mut d = disk("arc");
        assert!(!rebind(
            &mut d,
            &Location::Local {
                device: "/dev/sdb1".into(),
            }
        ));
    }

    #[test]
    fn rebind_moves_local_disk_out_to_remote_with_transport() {
        let mut d = disk("arc");
        let changed = rebind(
            &mut d,
            &Location::Remote {
                remote: "shed".into(),
                device: "/dev/sda".into(),
            },
        );
        assert!(changed);
        assert_eq!(d.remote.as_deref(), Some("shed"));
        assert_eq!(d.device.as_deref(), Some("/dev/sda"));
        // Ciphertext forwarded home -> still decrypts locally.
        assert_eq!(d.transport, Some(Transport::Nbd));
        assert!(d.decrypts_locally());
    }

    #[test]
    fn rebind_moves_disk_between_remotes() {
        let mut d = disk("arc");
        d.remote = Some("nas".into());
        d.device = Some("/dev/sda".into());
        d.transport = Some(Transport::Nbd);

        let changed = rebind(
            &mut d,
            &Location::Remote {
                remote: "shed".into(),
                device: "/dev/sdb".into(),
            },
        );
        assert!(changed);
        assert_eq!(d.remote.as_deref(), Some("shed"));
        assert_eq!(d.device.as_deref(), Some("/dev/sdb"));
        // An existing transport is preserved (not clobbered back to a default).
        assert_eq!(d.transport, Some(Transport::Nbd));
    }

    #[test]
    fn rebind_absent_leaves_binding_untouched() {
        let mut d = disk("arc");
        d.remote = Some("nas".into());
        d.device = Some("/dev/sda".into());
        assert!(!rebind(&mut d, &Location::Absent));
        assert_eq!(d.remote.as_deref(), Some("nas"));
        assert_eq!(d.device.as_deref(), Some("/dev/sda"));
    }
}
