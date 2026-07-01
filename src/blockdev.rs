//! Ciphertext block-device forwarding — the fast path for remote managed disks.
//!
//! The threat model forbids decrypting a remote disk on the remote. So instead
//! of running `cryptsetup` over SSH, tpmnt forwards the disk's **raw LUKS
//! ciphertext** to this host as a local block device and runs `cryptsetup open`
//! here. The key never leaves this machine, and — because only ciphertext ever
//! crosses the wire — confidentiality holds even over an untrusted link.
//!
//! This is the established industry pattern for untrusted remote storage (e.g.
//! the `ragnar` tool, and countless "LUKS-over-NBD" setups): export the encrypted
//! blocks, decrypt at the client. It is dramatically faster than the sshfs/SFTP
//! path because access is block-level — the local kernel gets its own page
//! cache, readahead, and the filesystem runs locally — instead of a per-file
//! FUSE round-trip. It also gains TRIM/discard, which SFTP cannot express.
//!
//! Transports (see `config::Transport`):
//!   * **NBD over SSH** (default) — `qemu-nbd` serves the ciphertext bound to the
//!     remote's loopback; an `ssh -L` tunnel carries it here; `nbd-client`
//!     attaches it as `/dev/nbdN`. Simple, universally packaged, and the tunnel
//!     adds integrity + access-pattern hiding for a WAN.
//!   * **NVMe-TCP** — lowest overhead / highest small-block IOPS on a *trusted*
//!     LAN (it beats iSCSI). Client attach is `nvme connect -t tcp`; the remote
//!     `nvmet` subsystem is a persistent LAN export configured out of band.
//!
//! One-shot ciphertext forwarding (used by `adopt`, which only needs to touch the
//! header to rotate in a keyslot) always uses the NBD-over-SSH path: it is the
//! most reliable ephemeral mechanism and needs no persistent server-side state.
//! The disk's steady-state `transport` is a hint recorded for `status` and the
//! (future) `apply`/`open` mount path.

use crate::config::Remote;
use crate::error::{Code, Error, Result};
use crate::exec::Runner;

/// The NBD port `qemu-nbd` binds on the remote loopback; the SSH tunnel forwards
/// a local port to it. Fixed default — collisions are avoided by binding to the
/// remote's 127.0.0.1 and using a distinct local port per attach.
pub const REMOTE_NBD_PORT: u16 = 10809;

/// A live ciphertext attachment: the local block device now backing the remote
/// disk's raw LUKS blocks, plus the teardown handles. Hand the `local_device` to
/// `cryptsetup open`; call `detach` when done.
#[derive(Debug, Clone)]
pub struct Attachment {
    /// Local block device exposing the remote ciphertext (e.g. `/dev/nbd0`), or
    /// simply the disk's own device when it is local (no forwarding needed).
    pub local_device: String,
    /// True when forwarding is active and `detach` must run.
    pub forwarded: bool,
}

impl Attachment {
    /// A local disk needs no forwarding: it *is* its own ciphertext device.
    pub fn local(device: &str) -> Attachment {
        Attachment {
            local_device: device.to_string(),
            forwarded: false,
        }
    }
}

/// `qemu-nbd` argv to serve `ciphertext_dev` as raw NBD on the remote loopback.
/// `--persistent`/`--shared` keep it up across reconnects; `--discard=unmap`
/// forwards TRIM; raw format means qemu never interprets the LUKS payload.
pub fn qemu_nbd_serve_argv(ciphertext_dev: &str, port: u16) -> Vec<String> {
    vec![
        "qemu-nbd".into(),
        "--persistent".into(),
        "--shared=8".into(),
        "--format=raw".into(),
        "--discard=unmap".into(),
        "--cache=none".into(),
        "-b".into(),
        "127.0.0.1".into(),
        "-p".into(),
        port.to_string(),
        ciphertext_dev.to_string(),
    ]
}

/// `ssh` argv that opens a background `-L local_port:127.0.0.1:remote_port`
/// tunnel over the same connection `prefix` uses, then runs `serve` on the
/// remote. Built by injecting the tunnel + no-shell flags into the SSH prefix
/// (whose last element is the destination host).
pub fn tunnel_and_serve_argv(prefix: &[String], local_port: u16, serve: &[String]) -> Vec<String> {
    // prefix is `ssh <opts...> <host>`; keep host last, inject after "ssh".
    let mut argv: Vec<String> = Vec::with_capacity(prefix.len() + serve.len() + 4);
    let mut it = prefix.iter();
    if let Some(first) = it.next() {
        argv.push(first.clone()); // "ssh"
    }
    argv.push("-L".into());
    argv.push(format!("{local_port}:127.0.0.1:{REMOTE_NBD_PORT}"));
    argv.extend(it.cloned()); // remaining opts + host
                              // Append the remote command (qemu-nbd …). ssh collapses trailing words.
    argv.extend(serve.iter().cloned());
    argv
}

/// `nbd-client` argv attaching the tunneled export to `local_dev`. `-persist`
/// auto-reconnects; `-b 4096` matches a 4K LUKS sector for aligned I/O.
pub fn nbd_client_argv(local_port: u16, local_dev: &str) -> Vec<String> {
    vec![
        "nbd-client".into(),
        "127.0.0.1".into(),
        local_port.to_string(),
        local_dev.to_string(),
        "-persist".into(),
        "-b".into(),
        "4096".into(),
    ]
}

/// `nbd-client -d` argv to disconnect `local_dev`.
pub fn nbd_client_disconnect_argv(local_dev: &str) -> Vec<String> {
    vec!["nbd-client".into(), "-d".into(), local_dev.to_string()]
}

/// Pick a free local `/dev/nbdN`: one whose `/sys/block/nbdN/size` reads 0
/// (kernel `nbd` module must be loaded). Read-only probe; returns `/dev/nbd0`
/// as a deterministic fallback when nothing is loaded (e.g. under dry-run).
pub fn free_nbd_device() -> String {
    for n in 0..16 {
        let size = std::fs::read_to_string(format!("/sys/block/nbd{n}/size"));
        match size {
            Ok(s) if s.trim() == "0" => return format!("/dev/nbd{n}"),
            Err(_) => continue, // module not loaded / device absent
            _ => continue,      // in use
        }
    }
    "/dev/nbd0".into()
}

/// Forward a remote disk's ciphertext here over NBD-over-SSH and return the local
/// block device. The remote serves via qemu-nbd through an SSH tunnel; we attach
/// with nbd-client. Under dry-run the steps are traced but skipped, and a
/// deterministic device is returned so callers can preview the plan.
pub fn attach_nbd_over_ssh(
    runner: &Runner,
    remote: &Remote,
    ciphertext_dev: &str,
    local_port: u16,
) -> Result<Attachment> {
    let local_dev = free_nbd_device();
    let prefix = remote.ssh_prefix();
    let serve = qemu_nbd_serve_argv(ciphertext_dev, REMOTE_NBD_PORT);

    // 1. Open the tunnel + start the remote NBD server (backgrounded by ssh).
    //    Run detached so it keeps serving; we don't wait on it.
    let tunnel = tunnel_and_serve_argv(&prefix, local_port, &serve);
    // Force ssh into the background-with-command form: -f -N would drop the
    // command, so we keep the command and rely on qemu-nbd's own daemonization
    // (it forks once the export is ready). Record it as a destructive step.
    let tunnel_ref: Vec<&str> = tunnel.iter().map(String::as_str).collect();
    runner
        .run(
            &tunnel_ref,
            "open SSH tunnel + serve remote ciphertext via qemu-nbd",
        )?
        .require("qemu-nbd over ssh")?;

    // 2. Attach the tunneled export locally.
    let client = nbd_client_argv(local_port, &local_dev);
    let client_ref: Vec<&str> = client.iter().map(String::as_str).collect();
    runner
        .run(
            &client_ref,
            "attach forwarded ciphertext as a local NBD device",
        )?
        .require("nbd-client")?;

    Ok(Attachment {
        local_device: local_dev,
        forwarded: true,
    })
}

/// Tear down a ciphertext attachment: disconnect nbd-client locally. The remote
/// qemu-nbd + tunnel exit on their own once the client disconnects and the SSH
/// channel closes. No-op for a local (non-forwarded) attachment.
pub fn detach(runner: &Runner, att: &Attachment) -> Result<()> {
    if !att.forwarded {
        return Ok(());
    }
    let dis = nbd_client_disconnect_argv(&att.local_device);
    let dis_ref: Vec<&str> = dis.iter().map(String::as_str).collect();
    // Best-effort: a failed disconnect shouldn't mask the primary result.
    let _ = runner.run(&dis_ref, "disconnect local NBD device");
    Ok(())
}

/// Guard against forwarding a remote disk that has no reachable `[[remote]]`.
pub fn require_remote<'a>(remote: Option<&'a Remote>, disk_name: &str) -> Result<&'a Remote> {
    remote.ok_or_else(|| {
        Error::new(
            Code::ETransport,
            format!("disk {disk_name} has no reachable [[remote]] to forward ciphertext from"),
        )
        .with_hint("add a matching [[remote]] entry, or fix the disk's `remote` name")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nas() -> Remote {
        Remote {
            name: "nas".into(),
            host: "alice@10.0.0.5:2222".into(),
            jump: vec!["gw@bastion".into()],
            identity: Some("/k/id".into()),
        }
    }

    #[test]
    fn qemu_nbd_serves_raw_ciphertext_on_loopback() {
        let a = qemu_nbd_serve_argv("/dev/sdb1", 10809);
        assert_eq!(a[0], "qemu-nbd");
        assert!(a.contains(&"--format=raw".to_string()));
        assert!(a.contains(&"127.0.0.1".to_string()));
        assert_eq!(a.last().unwrap(), "/dev/sdb1");
    }

    #[test]
    fn tunnel_injects_dash_l_after_ssh_and_keeps_host_last_then_command() {
        let prefix = nas().ssh_prefix();
        let serve = qemu_nbd_serve_argv("/dev/sdb1", REMOTE_NBD_PORT);
        let argv = tunnel_and_serve_argv(&prefix, 21809, &serve);
        assert_eq!(argv[0], "ssh");
        assert_eq!(argv[1], "-L");
        assert_eq!(argv[2], format!("21809:127.0.0.1:{REMOTE_NBD_PORT}"));
        // Identity / jump / port options from the prefix survive.
        assert!(argv.contains(&"-i".to_string()));
        assert!(argv.contains(&"-J".to_string()));
        assert!(argv.contains(&"/k/id".to_string()));
        // The remote command trails after the host.
        assert!(argv.contains(&"qemu-nbd".to_string()));
        let host_idx = argv.iter().position(|s| s == "alice@10.0.0.5").unwrap();
        let qemu_idx = argv.iter().position(|s| s == "qemu-nbd").unwrap();
        assert!(host_idx < qemu_idx, "host must precede the remote command");
    }

    #[test]
    fn nbd_client_attaches_with_alignment_and_persist() {
        let a = nbd_client_argv(21809, "/dev/nbd3");
        assert_eq!(a[0], "nbd-client");
        assert!(a.contains(&"-persist".to_string()));
        assert!(a.contains(&"/dev/nbd3".to_string()));
        assert!(a.windows(2).any(|w| w == ["-b", "4096"]));
    }

    #[test]
    fn local_attachment_is_not_forwarded() {
        let a = Attachment::local("/dev/disk/by-uuid/abc");
        assert!(!a.forwarded);
        assert_eq!(a.local_device, "/dev/disk/by-uuid/abc");
        // detach on a local attachment is a no-op (no runner call needed).
        let r = Runner::new(true, false);
        detach(&r, &a).unwrap();
        assert!(r.trace.borrow().is_empty());
    }
}
