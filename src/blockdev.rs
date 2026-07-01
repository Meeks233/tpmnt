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
//!   * **NBD over SSH** (default) — a persistent background SSH ControlMaster
//!     tunnel (`ssh -f -N -M -S … -L …`) carries the ciphertext; over that same
//!     connection `sudo qemu-nbd --fork` serves the raw blocks bound to the
//!     remote loopback; `nbd-client` attaches it here as `/dev/nbdN`. Teardown
//!     disconnects the client, kills the remote server, and closes the master.
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

/// Teardown handles for a forwarded attachment: the SSH prefix + ControlMaster
/// socket used to reach the remote, and the remote device we served (for killing
/// the server). Kept so `detach` can reverse exactly what `attach` set up.
#[derive(Debug, Clone)]
struct Forward {
    ssh_prefix: Vec<String>,
    control_path: String,
    remote_dev: String,
}

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
    /// Teardown handles; `None` for a local (non-forwarded) attachment.
    forward: Option<Forward>,
}

impl Attachment {
    /// A local disk needs no forwarding: it *is* its own ciphertext device.
    pub fn local(device: &str) -> Attachment {
        Attachment {
            local_device: device.to_string(),
            forwarded: false,
            forward: None,
        }
    }
}

/// The ControlMaster socket path for a forward on `local_port`. Unique per port
/// so concurrent forwards don't collide.
pub fn control_path(local_port: u16) -> String {
    format!("/tmp/tpmnt-nbd-{local_port}.ctl")
}

/// Inject `flags` right after `ssh` in an SSH `prefix` (whose last element is the
/// destination host), keeping the host last, then append an optional remote
/// command. This is how every SSH invocation below is assembled from the disk's
/// own prefix so `--plan` shows the real command.
fn ssh_with(prefix: &[String], flags: &[String], remote_cmd: &[String]) -> Vec<String> {
    let mut argv: Vec<String> = Vec::with_capacity(prefix.len() + flags.len() + remote_cmd.len());
    let mut it = prefix.iter();
    if let Some(first) = it.next() {
        argv.push(first.clone()); // "ssh"
    }
    argv.extend(flags.iter().cloned());
    argv.extend(it.cloned()); // remaining opts + host
    argv.extend(remote_cmd.iter().cloned());
    argv
}

/// `ssh -f -N -M -S <ctl> -L <lport>:127.0.0.1:<rport>` argv: open a persistent
/// background ControlMaster tunnel and return immediately (`-f` backgrounds,
/// `-N` runs no remote command). Later SSH calls reuse it via `-S <ctl>`.
pub fn master_tunnel_argv(
    prefix: &[String],
    control_path: &str,
    local_port: u16,
    remote_port: u16,
) -> Vec<String> {
    let flags = vec![
        "-f".into(),
        "-N".into(),
        "-M".into(),
        "-S".into(),
        control_path.to_string(),
        "-L".into(),
        format!("{local_port}:127.0.0.1:{remote_port}"),
    ];
    ssh_with(prefix, &flags, &[])
}

/// The remote command that serves `ciphertext_dev` as raw NBD on the loopback.
/// `sudo -n` because serving a root-owned block device needs privilege; `--fork`
/// daemonizes once the export is ready so the SSH call returns; `--discard=unmap`
/// forwards TRIM; raw format means qemu never interprets the LUKS payload.
pub fn qemu_nbd_serve_argv(ciphertext_dev: &str, port: u16) -> Vec<String> {
    vec![
        "sudo".into(),
        "-n".into(),
        "qemu-nbd".into(),
        "--fork".into(),
        "--shared=1".into(),
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

/// `ssh -S <ctl> … <host> <remote_cmd…>` argv: run `remote_cmd` over the existing
/// ControlMaster connection (no re-auth, no new tunnel).
pub fn serve_over_master_argv(
    prefix: &[String],
    control_path: &str,
    remote_cmd: &[String],
) -> Vec<String> {
    let flags = vec!["-S".into(), control_path.to_string()];
    ssh_with(prefix, &flags, remote_cmd)
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
/// block device. A persistent background ControlMaster tunnel carries the link;
/// `sudo qemu-nbd --fork` serves the raw blocks on the remote loopback; we attach
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
    let ctl = control_path(local_port);

    // 1. Open the persistent background tunnel (ControlMaster).
    let tunnel = master_tunnel_argv(&prefix, &ctl, local_port, REMOTE_NBD_PORT);
    let tunnel_ref: Vec<&str> = tunnel.iter().map(String::as_str).collect();
    runner
        .run(&tunnel_ref, "open persistent SSH ControlMaster tunnel")?
        .require("ssh -M tunnel")?;

    // 2. Serve the remote ciphertext over that tunnel (qemu-nbd daemonizes).
    let serve = qemu_nbd_serve_argv(ciphertext_dev, REMOTE_NBD_PORT);
    let serve_cmd = serve_over_master_argv(&prefix, &ctl, &serve);
    let serve_ref: Vec<&str> = serve_cmd.iter().map(String::as_str).collect();
    if let Err(e) = runner
        .run(&serve_ref, "serve remote ciphertext via qemu-nbd")
        .and_then(|o| o.require("qemu-nbd --fork"))
    {
        close_master(runner, &prefix, &ctl);
        return Err(e);
    }

    // 3. Attach the tunneled export locally.
    let client = nbd_client_argv(local_port, &local_dev);
    let client_ref: Vec<&str> = client.iter().map(String::as_str).collect();
    if let Err(e) = runner
        .run(
            &client_ref,
            "attach forwarded ciphertext as a local NBD device",
        )
        .and_then(|o| o.require("nbd-client"))
    {
        kill_remote_server(runner, &prefix, &ctl, ciphertext_dev);
        close_master(runner, &prefix, &ctl);
        return Err(e);
    }

    Ok(Attachment {
        local_device: local_dev,
        forwarded: true,
        forward: Some(Forward {
            ssh_prefix: prefix,
            control_path: ctl,
            remote_dev: ciphertext_dev.to_string(),
        }),
    })
}

/// Close the ControlMaster tunnel (`ssh -S <ctl> -O exit`). Best-effort.
fn close_master(runner: &Runner, prefix: &[String], ctl: &str) {
    let flags = vec!["-S".into(), ctl.to_string(), "-O".into(), "exit".into()];
    let argv = ssh_with(prefix, &flags, &[]);
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let _ = runner.run(&refs, "close SSH ControlMaster tunnel");
}

/// Kill the remote `qemu-nbd` serving `dev` (`sudo pkill -f`). Best-effort.
fn kill_remote_server(runner: &Runner, prefix: &[String], ctl: &str, dev: &str) {
    let cmd = vec![
        "sudo".into(),
        "-n".into(),
        "pkill".into(),
        "-f".into(),
        format!("qemu-nbd.*{dev}"),
    ];
    let argv = serve_over_master_argv(prefix, ctl, &cmd);
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let _ = runner.run(&refs, "stop remote qemu-nbd server");
}

/// Tear down a ciphertext attachment: disconnect nbd-client locally, kill the
/// remote qemu-nbd, and close the ControlMaster tunnel. No-op for a local
/// (non-forwarded) attachment. Best-effort so a failed step can't mask the
/// primary result.
pub fn detach(runner: &Runner, att: &Attachment) -> Result<()> {
    if !att.forwarded {
        return Ok(());
    }
    let dis = nbd_client_disconnect_argv(&att.local_device);
    let dis_ref: Vec<&str> = dis.iter().map(String::as_str).collect();
    let _ = runner.run(&dis_ref, "disconnect local NBD device");
    if let Some(f) = &att.forward {
        kill_remote_server(runner, &f.ssh_prefix, &f.control_path, &f.remote_dev);
        close_master(runner, &f.ssh_prefix, &f.control_path);
    }
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
        assert_eq!(a[0], "sudo"); // needs privilege to read the block device
        assert!(a.contains(&"qemu-nbd".to_string()));
        assert!(a.contains(&"--fork".to_string())); // daemonizes so ssh returns
        assert!(a.contains(&"--format=raw".to_string()));
        assert!(a.contains(&"127.0.0.1".to_string()));
        assert_eq!(a.last().unwrap(), "/dev/sdb1");
    }

    #[test]
    fn master_tunnel_injects_flags_after_ssh_and_keeps_host_last() {
        let prefix = nas().ssh_prefix();
        let ctl = control_path(21809);
        let argv = master_tunnel_argv(&prefix, &ctl, 21809, REMOTE_NBD_PORT);
        assert_eq!(argv[0], "ssh");
        assert!(argv.windows(2).any(|w| w == ["-M", "-S"]));
        assert!(argv.contains(&format!("21809:127.0.0.1:{REMOTE_NBD_PORT}")));
        assert!(argv.contains(&"-f".to_string()) && argv.contains(&"-N".to_string()));
        // Identity / jump options from the prefix survive, host is present.
        assert!(argv.contains(&"-i".to_string()));
        assert!(argv.contains(&"-J".to_string()));
        assert!(argv.contains(&"alice@10.0.0.5".to_string()));
        // No remote command on the master tunnel.
        assert!(!argv.contains(&"qemu-nbd".to_string()));
    }

    #[test]
    fn serve_over_master_reuses_control_socket_and_trails_command() {
        let prefix = nas().ssh_prefix();
        let ctl = control_path(21809);
        let serve = qemu_nbd_serve_argv("/dev/sdb1", REMOTE_NBD_PORT);
        let argv = serve_over_master_argv(&prefix, &ctl, &serve);
        assert_eq!(argv[0], "ssh");
        assert!(argv.windows(2).any(|w| w == ["-S", ctl.as_str()]));
        // The remote command trails after the host.
        let host_idx = argv.iter().position(|s| s == "alice@10.0.0.5").unwrap();
        let sudo_idx = argv.iter().position(|s| s == "sudo").unwrap();
        assert!(host_idx < sudo_idx, "host must precede the remote command");
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
