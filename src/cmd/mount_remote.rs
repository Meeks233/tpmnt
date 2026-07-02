//! `tpmnt mount-remote` (alias `client`) — mount a remote tpmnt-managed,
//! already-decrypted directory onto THIS machine over sshfs, with optional LAN
//! jump host(s) (SSH ProxyJump). Managed by a per-mount systemd --user service
//! (self-healing, no root, no fstab). Every decision has a flag + default +
//! bypass; fully AI-native.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::cli::{MountRemoteArgs, UmountRemoteArgs};
use crate::config::RemoteMount;
use crate::error::{Code, Error, Result};

use super::Context;

/// `--from-config` end-state for a single remote mount.
#[derive(Debug, Default, Deserialize)]
struct RemoteSpec {
    name: Option<String>,
    host: Option<String>,
    remote_path: Option<String>,
    mountpoint: Option<PathBuf>,
    #[serde(default)]
    jump: Vec<String>,
    identity: Option<PathBuf>,
    sftp_server: Option<String>,
}

// --- entry points ----------------------------------------------------------

pub fn run(ctx: &Context, args: &MountRemoteArgs) -> Result<Value> {
    if args.list {
        return list(ctx);
    }
    let rm = resolve(ctx, args)?;
    let dry = ctx.global.effective_dry_run();

    // Validate identity early.
    if let Some(id) = &rm.identity {
        let expanded = expand_tilde(&id.to_string_lossy());
        if !Path::new(&expanded).exists() {
            return Err(Error::new(
                Code::EIdentityMissing,
                format!("identity file not found: {expanded}"),
            )
            .with_hint("create the key or fix --identity"));
        }
    }

    let mountpoint = expand_tilde(&rm.mountpoint.to_string_lossy());
    let jump_chain = flatten_jumps(&rm.jump);

    // Mountpoint busy? Idempotent if it's already our mount; else refuse.
    if is_mountpoint(&mountpoint) {
        if mount_source_matches(&mountpoint, &rm) {
            return Ok(json!({
                "ok": true, "name": rm.name, "action": "noop",
                "reason": "already mounted", "mountpoint": mountpoint,
            }));
        }
        return Err(Error::new(
            Code::EMountpointBusy,
            format!("{mountpoint} is already a mountpoint"),
        )
        .with_hint("choose another --mountpoint or unmount it first"));
    }

    // Per-hop reachability + sftp detection (always run; they are probes).
    // In --plan/--dry-run we REPORT reachability/sftp rather than abort, so a
    // preview never fails just because a hop is momentarily down.
    let reachability = check_reachability(ctx, &rm, &jump_chain, !dry)?;
    let (sftp_path_used, sftp_server) = detect_sftp(ctx, &rm, &jump_chain, dry)?;

    let sshfs_argv = build_sshfs_argv(&rm, &mountpoint, &jump_chain, sftp_server.as_deref());
    let unit_name = format!("tpmnt-mount-{}.service", rm.name);
    let unit_body = unit_file(&rm, &sshfs_argv);

    if dry {
        return Ok(json!({
            "ok": true,
            "dry_run": true,
            "name": rm.name,
            "host": rm.host,
            "jump_chain": jump_chain,
            "mountpoint": mountpoint,
            "unit_name": unit_name,
            "sftp_path_used": sftp_path_used,
            "reachability": reachability,
            "sshfs_argv": sshfs_argv,
            "unit_would_write": unit_body,
        }));
    }

    std::fs::create_dir_all(&mountpoint)
        .map_err(|e| Error::new(Code::EInternal, format!("mkdir mountpoint: {e}")))?;

    // Prefer a systemd --user unit; fall back to a direct sshfs spawn when no
    // user session bus is available (e.g. headless CI), so the mount still works.
    let unit_managed = if systemd_user_available(ctx) {
        write_and_start_unit(ctx, &unit_name, &unit_body)?;
        wait_for_mount(&mountpoint);
        true
    } else {
        eprintln!("warning: no systemd --user session; starting sshfs directly (not self-healing)");
        // Without -f sshfs backgrounds itself once mounted.
        let argv: Vec<&str> = sshfs_argv
            .iter()
            .filter(|a| *a != "-f")
            .map(|s| s.as_str())
            .collect();
        ctx.runner
            .run(&argv, "mount remote over sshfs (direct)")?
            .require("sshfs")?;
        false
    };

    let active = is_mountpoint(&mountpoint);
    let bytes_readable = readdir_probe(&mountpoint);

    Ok(json!({
        "ok": true,
        "name": rm.name,
        "host": rm.host,
        "jump_chain": jump_chain,
        "mountpoint": mountpoint,
        "unit_name": unit_name,
        "unit_managed": unit_managed,
        "active": active,
        "sftp_path_used": sftp_path_used,
        "bytes_readable": bytes_readable,
        "reachability": reachability,
    }))
}

pub fn umount(ctx: &Context, args: &UmountRemoteArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let unit_name = format!("tpmnt-mount-{}.service", args.name);

    // Resolve the mountpoint from config if present (for fusermount cleanup).
    let mountpoint = ctx
        .config
        .remote_mounts
        .iter()
        .find(|m| m.name == args.name)
        .map(|m| expand_tilde(&m.mountpoint.to_string_lossy()));

    if dry {
        return Ok(json!({
            "ok": true, "dry_run": true, "name": args.name,
            "unit_name": unit_name, "mountpoint": mountpoint,
        }));
    }

    if systemd_user_available(ctx) {
        let _ = ctx.runner.run(
            &["systemctl", "--user", "disable", "--now", &unit_name],
            "stop+disable remote mount unit",
        );
        remove_unit(ctx, &unit_name)?;
        let _ = ctx.runner.run(
            &["systemctl", "--user", "daemon-reload"],
            "reload user units",
        );
    }
    if let Some(mp) = &mountpoint {
        let _ = ctx.runner.run(&["fusermount3", "-u", mp], "unmount sshfs");
    }

    Ok(json!({
        "ok": true, "name": args.name, "unit_name": unit_name,
        "mountpoint": mountpoint, "action": "torn-down",
    }))
}

fn list(ctx: &Context) -> Result<Value> {
    let mut out = Vec::new();
    for m in &ctx.config.remote_mounts {
        let mp = expand_tilde(&m.mountpoint.to_string_lossy());
        out.push(json!({
            "name": m.name,
            "host": m.host,
            "jump_chain": flatten_jumps(&m.jump),
            "mountpoint": mp,
            "active": is_mountpoint(&mp),
        }));
    }
    Ok(json!({ "ok": true, "remote_mounts": out }))
}

// --- resolution ------------------------------------------------------------

fn resolve(ctx: &Context, args: &MountRemoteArgs) -> Result<RemoteMount> {
    // 1. --from-config wins as a base.
    if let Some(p) = &args.from_config {
        let s = std::fs::read_to_string(p)
            .map_err(|e| Error::new(Code::EConfig, format!("read {}: {e}", p.display())))?;
        let spec: RemoteSpec = toml::from_str(&s)
            .map_err(|e| Error::new(Code::EConfig, format!("invalid --from-config: {e}")))?;
        return Ok(RemoteMount {
            name: spec
                .name
                .or_else(|| args.name.clone())
                .unwrap_or_else(|| "remote".into()),
            host: req(spec.host.or_else(|| args.host.clone()), "host")?,
            remote_path: req(
                spec.remote_path.or_else(|| args.remote_path.clone()),
                "remote_path",
            )?,
            mountpoint: spec
                .mountpoint
                .or_else(|| args.mountpoint.clone())
                .ok_or_else(|| Error::new(Code::EConfig, "missing mountpoint"))?,
            jump: if !args.jump.is_empty() {
                args.jump.clone()
            } else {
                spec.jump
            },
            identity: args.identity.clone().or(spec.identity),
            sftp_server: args.sftp_server.clone().or(spec.sftp_server),
            reconnect: true,
        });
    }

    // 2. Named config entry, optionally overridden by flags.
    if let Some(name) = &args.name {
        if let Some(base) = ctx.config.remote_mounts.iter().find(|m| &m.name == name) {
            let mut rm = base.clone();
            if let Some(h) = &args.host {
                rm.host = h.clone();
            }
            if let Some(rp) = &args.remote_path {
                rm.remote_path = rp.clone();
            }
            if let Some(mp) = &args.mountpoint {
                rm.mountpoint = mp.clone();
            }
            if !args.jump.is_empty() {
                rm.jump = args.jump.clone();
            }
            if args.identity.is_some() {
                rm.identity = args.identity.clone();
            }
            if args.sftp_server.is_some() {
                rm.sftp_server = args.sftp_server.clone();
            }
            return Ok(rm);
        }
    }

    // 3. Pure flags.
    Ok(RemoteMount {
        name: args.name.clone().unwrap_or_else(|| "remote".into()),
        host: req(args.host.clone(), "host")?,
        remote_path: req(args.remote_path.clone(), "remote_path")?,
        mountpoint: args
            .mountpoint
            .clone()
            .ok_or_else(|| Error::new(Code::EConfig, "missing --mountpoint"))?,
        jump: args.jump.clone(),
        identity: args.identity.clone(),
        sftp_server: args.sftp_server.clone(),
        reconnect: true,
    })
}

fn req(v: Option<String>, what: &str) -> Result<String> {
    v.ok_or_else(|| {
        Error::new(Code::EConfig, format!("missing {what}"))
            .with_hint("provide it via flag, a [[remote_mount]] entry, or --from-config")
    })
}

// --- ssh / sshfs argv ------------------------------------------------------

/// Split comma-separated jump entries into a flat ordered list.
fn flatten_jumps(jump: &[String]) -> Vec<String> {
    jump.iter()
        .flat_map(|j| j.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// sshfs argv (foreground `-f` for systemd supervision; stripped for direct).
fn build_sshfs_argv(
    rm: &RemoteMount,
    mountpoint: &str,
    jump_chain: &[String],
    sftp_server: Option<&str>,
) -> Vec<String> {
    let (hostonly, port) = split_host_port(&rm.host);
    let mut argv = vec![
        "sshfs".to_string(),
        format!("{}:{}", hostonly, rm.remote_path),
        mountpoint.to_string(),
        "-f".to_string(),
    ];
    let mut opts = vec![
        "ConnectTimeout=10".to_string(),
        "ServerAliveInterval=15".to_string(),
        "ServerAliveCountMax=3".to_string(),
    ];
    if let Some(p) = port {
        opts.push(format!("port={p}"));
    }
    if rm.reconnect {
        opts.push("reconnect".to_string());
    }
    if rm.identity.is_some() {
        opts.push("IdentitiesOnly=yes".to_string());
    }
    if let Some(id) = &rm.identity {
        opts.push(format!(
            "IdentityFile={}",
            expand_tilde(&id.to_string_lossy())
        ));
    }
    // ProxyJump (or, with an explicit identity, an identity-carrying
    // ProxyCommand — OpenSSH does not propagate -i to ProxyJump hops).
    opts.extend(proxy_opt_values(rm, jump_chain));
    if let Some(srv) = sftp_server {
        opts.push(format!("sftp_server={srv}"));
    }
    for o in opts {
        argv.push("-o".to_string());
        argv.push(o);
    }
    argv
}

/// Base ssh args for probes: the same connection shape sshfs will use.
fn ssh_probe_args(rm: &RemoteMount, jump_chain: &[String], target: &str) -> Vec<String> {
    let mut argv = vec!["ssh".to_string()];
    argv.push("-o".into());
    argv.push("BatchMode=yes".into());
    argv.push("-o".into());
    argv.push("ConnectTimeout=8".into());
    if let Some(id) = &rm.identity {
        argv.push("-o".into());
        argv.push("IdentitiesOnly=yes".into());
        argv.push("-i".into());
        argv.push(expand_tilde(&id.to_string_lossy()));
    }
    for v in proxy_opt_values(rm, jump_chain) {
        argv.push("-o".into());
        argv.push(v);
    }
    // When `target` is a direct ssh destination, split any `:port` suffix into
    // `-p` (jump entries keep their own user@host:port form inside ProxyJump).
    let (dest, port) = split_host_port(target);
    if let Some(p) = port {
        argv.push("-p".into());
        argv.push(p.to_string());
    }
    argv.push(dest);
    argv
}

/// The connection option(s) that route through `jumps`. With no jumps: none.
/// Without an explicit identity: `ProxyJump=<chain>` (honors agent + ssh_config).
/// With an explicit identity: an identity-carrying `ProxyCommand` that reaches
/// every hop, since OpenSSH does NOT pass -i to implicit ProxyJump connections
/// (which would otherwise break under a systemd unit with no agent).
fn proxy_opt_values(rm: &RemoteMount, jumps: &[String]) -> Vec<String> {
    if jumps.is_empty() {
        return Vec::new();
    }
    match &rm.identity {
        None => vec![format!("ProxyJump={}", jumps.join(","))],
        Some(id) => {
            let idp = expand_tilde(&id.to_string_lossy());
            let idopts = vec![
                "-o".to_string(),
                "IdentitiesOnly=yes".to_string(),
                "-i".to_string(),
                idp,
            ];
            vec![format!(
                "ProxyCommand={}",
                build_proxy_command(&idopts, jumps)
            )]
        }
    }
}

/// Build a `/bin/sh`-evaluated ProxyCommand string that tunnels to the final
/// target through `jumps` (jumps[0] is the first bastion), carrying `idopts` to
/// every hop. Nested ProxyCommands are shell-quoted for each level.
///
/// Crucially, only the OUTERMOST hop forwards to `[%h]:%p` (the real target,
/// expanded by the calling ssh). Inner hops forward to the LITERAL next bastion
/// address — because the outer ssh `%`-expands the whole command string, a nested
/// `%h:%p` would wrongly resolve to the final target and collapse the chain.
fn build_proxy_command(idopts: &[String], jumps: &[String]) -> String {
    let n = jumps.len();
    let mut pc: Option<String> = None;
    for (k, j) in jumps.iter().enumerate() {
        let (dest, port) = split_host_port(j);
        // The destination this hop forwards to: the next bastion (literal), or
        // the real target (%h:%p) for the last hop.
        // Use unbracketed host:port: brackets would glob under zsh and force
        // single-quoting, whose nested `'\''` escaping then breaks when the
        // command is embedded in a systemd ExecStart. (IPv6 literals are not
        // supported as jump hops as a result — use a ~/.ssh/config alias.)
        let forward_to = if k + 1 == n {
            "%h:%p".to_string()
        } else {
            // -W takes host:port only — strip any `user@` from the next hop.
            let (ndest, np) = split_host_port(&jumps[k + 1]);
            let nhost = ndest.rsplit('@').next().unwrap_or(&ndest);
            format!("{}:{}", nhost, np.unwrap_or(22))
        };
        let mut parts = vec!["ssh".to_string(), "-o".into(), "BatchMode=yes".into()];
        parts.extend(idopts.iter().cloned());
        if let Some(inner) = &pc {
            parts.push("-o".into());
            parts.push(format!("ProxyCommand={inner}"));
        }
        if let Some(p) = port {
            parts.push("-p".into());
            parts.push(p.to_string());
        }
        parts.push("-W".into());
        parts.push(forward_to);
        parts.push(dest);
        pc = Some(shell_join(&parts));
    }
    pc.unwrap_or_default()
}

fn shell_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| {
            // NB: '[' and ']' are intentionally NOT "safe" — the ProxyCommand
            // runs via the user's shell, and zsh glob-expands `[%h]:%p` (failing
            // with "no matches"). Quoting forces it through literally.
            let safe = !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_=/:.%@".contains(c));
            if safe {
                p.clone()
            } else {
                format!("'{}'", p.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Split a `user@host:port` / `host:port` destination into (dest, port). Only a
/// trailing numeric segment after the last colon is treated as a port; anything
/// else (paths, IPv6 without brackets) is left intact.
fn split_host_port(host: &str) -> (String, Option<u16>) {
    if let Some((left, right)) = host.rsplit_once(':') {
        if let Ok(p) = right.parse::<u16>() {
            return (left.to_string(), Some(p));
        }
    }
    (host.to_string(), None)
}

// --- reachability + sftp detection ----------------------------------------

/// Test each jump hop progressively, then the final target. With `enforce`
/// (real mount), the first failure is fatal (E_JUMP_UNREACHABLE for a hop,
/// E_TARGET_UNREACHABLE for the target). Without it (--plan/--dry-run), every
/// hop is probed and merely REPORTED, so a preview never aborts.
fn check_reachability(
    ctx: &Context,
    rm: &RemoteMount,
    jump_chain: &[String],
    enforce: bool,
) -> Result<Value> {
    let mut hops = Vec::new();
    for i in 0..jump_chain.len() {
        let prefix = &jump_chain[..i];
        let hop = &jump_chain[i];
        let mut full = ssh_probe_args(rm, prefix, hop);
        full.push("true".into());
        let argv_ref: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
        let ok = ctx
            .runner
            .probe(&argv_ref, "check jump-host reachability")
            .map(|o| o.ok())
            .unwrap_or(false);
        hops.push(json!({ "hop": hop, "kind": "jump", "reachable": ok }));
        if !ok && enforce {
            return Err(Error::new(
                Code::EJumpUnreachable,
                format!("jump host unreachable: {hop}"),
            )
            .with_hint("check the bastion address, key, and that it forwards"));
        }
    }
    // Final target through the full chain.
    let mut full = ssh_probe_args(rm, jump_chain, &rm.host);
    full.push("true".into());
    let argv_ref: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
    let ok = ctx
        .runner
        .probe(&argv_ref, "check target reachability")
        .map(|o| o.ok())
        .unwrap_or(false);
    hops.push(json!({ "hop": rm.host, "kind": "target", "reachable": ok }));
    if !ok && enforce {
        return Err(Error::new(
            Code::ETargetUnreachable,
            format!("target unreachable: {}", rm.host),
        )
        .with_hint("check the target address, key, and network path"));
    }
    Ok(json!(hops))
}

/// Detect the sftp path. If --sftp-server is given, use direct-exec. Otherwise
/// probe the subsystem via `ssh -s <host> sftp`; if it fails, fall back to
/// exec'ing the default sftp-server path directly.
fn detect_sftp(
    ctx: &Context,
    rm: &RemoteMount,
    jump_chain: &[String],
    dry: bool,
) -> Result<(String, Option<String>)> {
    if let Some(srv) = &rm.sftp_server {
        return Ok(("direct-exec".into(), Some(srv.clone())));
    }
    // Probe the sftp subsystem: `ssh ... -s <host> sftp` with stdin closed.
    let mut argv = ssh_probe_args(rm, jump_chain, &rm.host);
    // Insert "-s" before the target (last element).
    let target = argv.pop().unwrap();
    argv.push("-s".into());
    argv.push(target);
    argv.push("sftp".into());
    let argv_ref: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let subsystem_ok = ctx
        .runner
        .probe(&argv_ref, "probe remote sftp subsystem")
        .map(|o| o.ok())
        .unwrap_or(false);
    if subsystem_ok {
        return Ok(("subsystem".into(), None));
    }

    // No subsystem: fall back to exec'ing sftp-server directly, but only if it
    // actually exists on the remote — probe the common per-distro locations.
    const CANDIDATES: &[&str] = &[
        "/usr/lib/openssh/sftp-server",     // Debian/Ubuntu
        "/usr/libexec/openssh/sftp-server", // Fedora/RHEL/Nobara
        "/usr/lib/ssh/sftp-server",         // Arch/SUSE
    ];
    let mut probe = ssh_probe_args(rm, jump_chain, &rm.host);
    let test_cmd = CANDIDATES
        .iter()
        .map(|c| format!("test -x {c} && echo {c}"))
        .collect::<Vec<_>>()
        .join(" || ");
    probe.push(test_cmd);
    let probe_ref: Vec<&str> = probe.iter().map(|s| s.as_str()).collect();
    let out = ctx
        .runner
        .probe(&probe_ref, "locate remote sftp-server binary");
    if let Ok(o) = out {
        let found = o
            .stdout
            .trim()
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if o.ok() && !found.is_empty() {
            return Ok(("direct-exec".into(), Some(found)));
        }
    }
    // In --plan/--dry-run, the host may simply be unreachable for probing; don't
    // fail a preview over it — report the path as undetermined.
    if dry {
        return Ok(("unknown".into(), None));
    }
    Err(Error::new(
        Code::ESftpUnavailable,
        format!(
            "remote {} has no sftp subsystem and no sftp-server binary",
            rm.host
        ),
    )
    .with_hint("install openssh-sftp-server on the remote or pass --sftp-server <path>"))
}

// --- systemd --user unit ---------------------------------------------------

fn user_unit_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join(".config/systemd/user")
}

fn unit_file(rm: &RemoteMount, sshfs_argv: &[String]) -> String {
    let exec = sshfs_argv
        .iter()
        .map(|a| {
            // systemd expands `%` specifiers in ExecStart (e.g. %h -> home);
            // escape `%%` so ssh's ProxyCommand `%h`/`%p` survive verbatim.
            let a = a.replace('%', "%%");
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "# tpmnt:{name}\n[Unit]\nDescription=tpmnt remote mount {name}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exec}\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
        name = rm.name,
    )
}

fn systemd_user_available(ctx: &Context) -> bool {
    ctx.runner
        .probe(
            &["systemctl", "--user", "is-system-running"],
            "probe user systemd availability",
        )
        .map(|o| o.status != 127 && !o.stderr.contains("Failed to connect to bus"))
        .unwrap_or(false)
}

fn write_and_start_unit(ctx: &Context, unit_name: &str, body: &str) -> Result<()> {
    let dir = user_unit_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::new(Code::EInternal, format!("mkdir unit dir: {e}")))?;
    let path = dir.join(unit_name);
    std::fs::write(&path, body)
        .map_err(|e| Error::new(Code::EInternal, format!("write unit: {e}")))?;
    ctx.runner.run(
        &["systemctl", "--user", "daemon-reload"],
        "reload user units",
    )?;
    ctx.runner
        .run(
            &["systemctl", "--user", "enable", "--now", unit_name],
            "enable+start remote mount unit",
        )?
        .require("systemctl enable --now")?;
    Ok(())
}

fn remove_unit(ctx: &Context, unit_name: &str) -> Result<()> {
    let _ = ctx;
    let path = user_unit_dir().join(unit_name);
    let _ = std::fs::remove_file(path);
    Ok(())
}

// --- helpers ---------------------------------------------------------------

fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        format!("{home}/{rest}")
    } else {
        p.to_string()
    }
}

fn is_mountpoint(path: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|s| s.lines().any(|l| l.split_whitespace().nth(1) == Some(path)))
        .unwrap_or(false)
}

/// Whether an existing mount at `path` is our sshfs to the same host (idempotency).
fn mount_source_matches(path: &str, rm: &RemoteMount) -> bool {
    // The /proc/mounts source field is the string sshfs was given, which
    // build_sshfs_argv constructs as `{hostonly}:{remote_path}` with the port
    // moved into `-o port=`. Compare against that (not the raw `rm.host`, which
    // may carry a `:port` suffix that never appears in the source).
    let (hostonly, _) = split_host_port(&rm.host);
    let expected = format!("{}:{}", hostonly, rm.remote_path);
    std::fs::read_to_string("/proc/mounts")
        .map(|s| {
            s.lines().any(|l| {
                let mut it = l.split_whitespace();
                let src = it.next().unwrap_or("");
                let mp = it.next().unwrap_or("");
                mp == path && (src == expected || src.starts_with(&format!("{hostonly}:")))
            })
        })
        .unwrap_or(false)
}

fn wait_for_mount(path: &str) {
    // sshfs needs a moment after the unit starts; poll briefly.
    for _ in 0..50 {
        if is_mountpoint(path) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Tiny readdir probe to prove the mount really works: can we list it at all?
fn readdir_probe(path: &str) -> bool {
    std::fs::read_dir(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rm(jump: Vec<&str>, identity: Option<&str>) -> RemoteMount {
        RemoteMount {
            name: "t".into(),
            host: "alice@192.168.5.10".into(),
            remote_path: "/data".into(),
            mountpoint: PathBuf::from("/mnt/t"),
            jump: jump.into_iter().map(String::from).collect(),
            identity: identity.map(PathBuf::from),
            sftp_server: None,
            reconnect: true,
        }
    }

    #[test]
    fn split_host_port_parses_trailing_port_only() {
        assert_eq!(split_host_port("a@h"), ("a@h".into(), None));
        assert_eq!(split_host_port("a@h:22"), ("a@h".into(), Some(22)));
        assert_eq!(split_host_port("h:2222"), ("h".into(), Some(2222)));
        // Non-numeric tail is not a port.
        assert_eq!(split_host_port("h:/path"), ("h:/path".into(), None));
    }

    #[test]
    fn flatten_jumps_splits_commas_and_trims() {
        assert_eq!(
            flatten_jumps(&["a, b".into(), "c".into()]),
            vec!["a".to_string(), "b".into(), "c".into()]
        );
        assert!(flatten_jumps(&[]).is_empty());
    }

    #[test]
    fn no_jumps_yields_no_proxy_option() {
        assert!(proxy_opt_values(&rm(vec![], None), &[]).is_empty());
    }

    #[test]
    fn jump_without_identity_uses_proxyjump() {
        let m = rm(vec!["bastion"], None);
        let chain = flatten_jumps(&m.jump);
        let opts = proxy_opt_values(&m, &chain);
        assert_eq!(opts, vec!["ProxyJump=bastion".to_string()]);
    }

    #[test]
    fn jump_with_identity_uses_identity_carrying_proxycommand() {
        let m = rm(vec!["me@bastion:2222"], Some("/k/id"));
        let chain = flatten_jumps(&m.jump);
        let opts = proxy_opt_values(&m, &chain);
        assert_eq!(opts.len(), 1);
        let pc = &opts[0];
        assert!(pc.starts_with("ProxyCommand=ssh "));
        // identity is carried to the jump hop, not lost like bare ProxyJump.
        assert!(pc.contains("-i /k/id"));
        assert!(pc.contains("-p 2222"));
        assert!(pc.contains("me@bastion"));
        // unbracketed %h:%p (no globbing, no quoting needed; systemd-safe).
        assert!(pc.contains("-W %h:%p"));
    }

    #[test]
    fn multi_hop_identity_nests_both_bastions_in_order() {
        let m = rm(vec!["h1:2201", "h2:2202"], Some("/k/id"));
        let chain = flatten_jumps(&m.jump);
        let pc = &proxy_opt_values(&m, &chain)[0];
        // Both bastion ports present; h1 is reached by the inner (nested) command.
        assert!(pc.contains("-p 2201"));
        assert!(pc.contains("-p 2202"));
        assert!(pc.contains("ProxyCommand=")); // nested inner proxy for hop 1
                                               // Inner nesting is single-quoted within the outer command:
        assert!(pc.contains("'ProxyCommand=ssh"));
    }
}
