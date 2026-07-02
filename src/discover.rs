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

use std::collections::HashMap;

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

/// A per-host map of `LUKS UUID → device path`, built with a *single* `blkid`
/// call per host rather than one lookup per (disk, host). This is the whole point
/// of the batched design: N disks across M remotes cost at most `1 + M` probes,
/// not `N × M`, so a "where did my disk go?" scan never fans out into a storm of
/// SSH round-trips that hammers every server.
pub type Uuids = HashMap<String, String>;

/// Inventory this host's block devices once: `blkid -o export` lists every device
/// with its UUID, which for a LUKS2 container is the container's own UUID. Empty
/// on any failure (treated as "nothing here" — the caller falls back to other
/// locations). Read-only; safe under dry-run.
pub fn local_inventory(runner: &Runner) -> Uuids {
    match runner.probe(&["blkid", "-o", "export"], "inventory local block UUIDs") {
        Ok(out) if out.ok() => parse_blkid_export(&out.stdout),
        _ => Uuids::new(),
    }
}

/// The single global remote sweep: inventory *every* known remote exactly once
/// (`sudo -n blkid -o export`, mirroring the qemu-nbd ciphertext export's need for
/// privilege). Returned in config order so the first remote that carries a UUID
/// wins, matching the "prefer where it was first found" intent. An unreachable
/// remote contributes an empty map instead of aborting the sweep.
pub fn remote_inventory(runner: &Runner, remotes: &[Remote]) -> Vec<(String, Uuids)> {
    remotes
        .iter()
        .map(|r| {
            let prefix = r.ssh_prefix();
            let uuids = match runner.probe_on(
                &prefix,
                &["sudo", "-n", "blkid", "-o", "export"],
                "inventory remote block UUIDs",
            ) {
                Ok(out) if out.ok() => parse_blkid_export(&out.stdout),
                _ => Uuids::new(),
            };
            (r.name.clone(), uuids)
        })
        .collect()
}

/// Parse `blkid -o export` output into a `UUID → DEVNAME` map. Records are blank-
/// line separated blocks of `KEY=VALUE` lines; we key on the LUKS container's
/// `UUID` (never `PARTUUID`/`UUID_SUB`, which have distinct key names).
fn parse_blkid_export(stdout: &str) -> Uuids {
    let mut map = Uuids::new();
    let mut devname: Option<String> = None;
    let mut uuid: Option<String> = None;
    let flush = |dev: &mut Option<String>, id: &mut Option<String>, map: &mut Uuids| {
        if let (Some(d), Some(u)) = (dev.take(), id.take()) {
            map.insert(u, d);
        }
    };
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            flush(&mut devname, &mut uuid, &mut map);
        } else if let Some(v) = line.strip_prefix("DEVNAME=") {
            devname = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("UUID=") {
            uuid = Some(v.to_string());
        }
    }
    flush(&mut devname, &mut uuid, &mut map); // final record has no trailing blank
    map
}

/// Decide where `disk` lives from an already-collected inventory — no I/O, so it
/// never adds a round-trip. Local always wins (decryption is cheapest here). When
/// a `remote_inv` sweep was performed it is authoritative (a UUID absent from it
/// is genuinely gone → `Absent`); when it was *not* performed we deliberately
/// trust the disk's last-known remote binding instead of probing every server —
/// the "don't proactively monitor all remotes" rule.
pub fn resolve(local: &Uuids, remote_inv: Option<&[(String, Uuids)]>, disk: &Disk) -> Location {
    let uuid = disk.uuid.trim();
    if uuid.is_empty() {
        return Location::Absent;
    }
    if let Some(device) = local.get(uuid) {
        return Location::Local {
            device: device.clone(),
        };
    }
    match remote_inv {
        Some(inv) => {
            for (name, uuids) in inv {
                if let Some(device) = uuids.get(uuid) {
                    return Location::Remote {
                        remote: name.clone(),
                        device: device.clone(),
                    };
                }
            }
            Location::Absent
        }
        // No sweep: trust the last-known remote binding rather than fanning out.
        None => match (disk.remote.as_deref(), disk.device.as_deref()) {
            (Some(remote), Some(device)) => Location::Remote {
                remote: remote.to_string(),
                device: device.to_string(),
            },
            _ => Location::Absent,
        },
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
            // A local disk always resolves via the stable /dev/disk/by-uuid/<uuid>
            // symlink, which survives re-enumeration (sda↔sdb↔sdc) — so never keep a
            // pinned /dev/sdX. Drop any stored device path (whether it's a stale
            // remote path from coming home, or a fragile local node from adopt).
            if disk.device.take().is_some() {
                changed = true;
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
            enabled: true,
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
    fn rebind_local_disk_drops_pinned_device_for_by_uuid() {
        // A local disk adopted with a fragile /dev/sda pin must be re-pointed at the
        // stable by-uuid symlink so it survives re-enumeration.
        let mut d = disk("arc");
        d.device = Some("/dev/sda".into());
        let changed = rebind(
            &mut d,
            &Location::Local {
                device: "/dev/sdb".into(),
            },
        );
        assert!(changed);
        assert!(d.device.is_none());
        assert_eq!(d.device_path(), "/dev/disk/by-uuid/u-123");
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

    #[test]
    fn parse_blkid_export_keys_on_luks_uuid_only() {
        // Two records, one trailing (no final blank line); a PARTUUID must not be
        // mistaken for the container UUID.
        let out = "DEVNAME=/dev/sda1\nUUID=u-123\nTYPE=crypto_LUKS\nPARTUUID=p-999\n\n\
                   DEVNAME=/dev/sdb\nUUID=u-456\nTYPE=crypto_LUKS\n";
        let map = parse_blkid_export(out);
        assert_eq!(map.get("u-123").map(String::as_str), Some("/dev/sda1"));
        assert_eq!(map.get("u-456").map(String::as_str), Some("/dev/sdb"));
        assert!(!map.contains_key("p-999"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn resolve_prefers_local_over_remote() {
        let d = disk("arc"); // uuid u-123
        let mut local = Uuids::new();
        local.insert("u-123".into(), "/dev/sdb1".into());
        let mut r = Uuids::new();
        r.insert("u-123".into(), "/dev/sda".into());
        let inv = vec![("nas".into(), r)];
        assert_eq!(
            resolve(&local, Some(&inv), &d),
            Location::Local {
                device: "/dev/sdb1".into()
            }
        );
    }

    #[test]
    fn resolve_without_sweep_trusts_last_known_remote() {
        let mut d = disk("arc");
        d.remote = Some("nas".into());
        d.device = Some("/dev/sda".into());
        // Not present locally, no remote sweep performed -> assume last-known spot.
        assert_eq!(
            resolve(&Uuids::new(), None, &d),
            Location::Remote {
                remote: "nas".into(),
                device: "/dev/sda".into()
            }
        );
    }

    #[test]
    fn resolve_sweep_is_authoritative_and_can_report_absent() {
        let mut d = disk("arc");
        d.remote = Some("nas".into());
        d.device = Some("/dev/sda".into());
        // A sweep ran and the UUID is nowhere -> genuinely gone, despite a binding.
        let inv: Vec<(String, Uuids)> = vec![("nas".into(), Uuids::new())];
        assert_eq!(resolve(&Uuids::new(), Some(&inv), &d), Location::Absent);
    }

    #[test]
    fn resolve_sweep_finds_disk_moved_to_another_remote() {
        let mut d = disk("arc");
        d.remote = Some("nas".into());
        d.device = Some("/dev/sda".into());
        let mut shed = Uuids::new();
        shed.insert("u-123".into(), "/dev/sdc".into());
        let inv = vec![("nas".into(), Uuids::new()), ("shed".into(), shed)];
        assert_eq!(
            resolve(&Uuids::new(), Some(&inv), &d),
            Location::Remote {
                remote: "shed".into(),
                device: "/dev/sdc".into()
            }
        );
    }
}
