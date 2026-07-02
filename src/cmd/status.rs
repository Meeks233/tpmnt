//! `tpmnt status` — per-disk reality check: LUKS2? TPM2 token? crypttab entry?
//! mounted? Emits both a human table and `--json`.

use std::io::IsTerminal;

use serde_json::{json, Value};

use crate::error::Result;
use crate::luks;
use crate::manage;
use crate::power;

use super::Context;

fn crypttab_has(ctx: &Context, name: &str) -> bool {
    let tag = format!("# tpmnt:{name}");
    std::fs::read_to_string(ctx.paths.crypttab())
        .map(|s| s.lines().any(|l| l.trim_end().ends_with(&tag)))
        .unwrap_or(false)
}

fn is_mounted(mountpoint: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|s| {
            s.lines()
                .any(|l| l.split_whitespace().nth(1) == Some(mountpoint))
        })
        .unwrap_or(false)
}

/// The backing (ciphertext) device of an open local mapper, via `cryptsetup
/// status`. For a managed remote disk that's the forwarded `/dev/nbdN`, whose
/// LUKS header we can then read locally. `None` if the mapper isn't open.
fn mapper_backing_device(ctx: &Context, mapper: &str) -> Option<String> {
    let out = ctx
        .runner
        .probe(
            &["cryptsetup", "status", mapper],
            "resolve mapper backing device",
        )
        .ok()?;
    if !out.ok() {
        return None;
    }
    out.stdout.lines().find_map(|l| {
        l.trim()
            .strip_prefix("device:")
            .map(|d| d.trim().to_string())
    })
}

pub fn run(ctx: &Context) -> Result<Value> {
    let mut rows = Vec::new();

    for disk in &ctx.config.disks {
        let device = disk.device_path();
        let prefix = ctx.config.ssh_prefix_for(disk);
        let mp = disk.mountpoint.to_string_lossy().to_string();
        let mapper = disk.mapper_name();
        let remote = ctx.config.remote_for(disk);

        // Where each fact is probed follows the threat-model verdict, not merely
        // whether the disk is remote. A MANAGED remote disk (ciphertext forwarded,
        // transport set) is decrypted, mapped, and mounted HERE — only its physical
        // spindown lives on the far side. A forward-only remote disk lives entirely
        // on the remote.
        let local_decrypt = disk.decrypts_locally();
        let local_mapper_open = std::path::Path::new(&format!("/dev/mapper/{mapper}")).exists();

        // LUKS header: for a locally-decrypting disk read it HERE — via the open
        // mapper's backing (ciphertext) device when attached, else the recorded
        // local device. A forward-only remote disk is inspected over SSH.
        let info = if remote.is_some() && local_decrypt {
            match mapper_backing_device(ctx, &mapper) {
                Some(backing) => luks::inspect(&ctx.runner, &backing).unwrap_or_default(),
                None => luks::inspect(&ctx.runner, &device).unwrap_or_default(),
            }
        } else {
            luks::inspect_on(&ctx.runner, &prefix, &device).unwrap_or_default()
        };

        let monitor_unit = ctx
            .paths
            .systemd_unit_dir()
            .join(format!("tpmnt-monitor-{}.service", disk.name));
        let (physical_device, crypttab, monitored, mounted, powered) = match remote {
            // Managed remote: mapper / mount / monitor units are LOCAL; the
            // physical disk (spindown) is remote and not tracked via local /sys.
            Some(_) if local_decrypt => (
                Value::Null,
                json!(crypttab_has(ctx, &disk.name)),
                json!(monitor_unit.exists()),
                json!(is_mounted(&mp)),
                json!(local_mapper_open),
            ),
            // Forward-only remote: mount/power state come from the remote host;
            // the local-only management artifacts don't apply, so they are null
            // rather than a misleading `false`.
            Some(_) => (
                Value::Null,
                Value::Null,
                Value::Null,
                json!(remote_mounted(ctx, &prefix, &mp)),
                json!(remote_powered(ctx, &prefix, &mapper)),
            ),
            None => (
                json!(power::physical_device_for(&device)),
                json!(crypttab_has(ctx, &disk.name)),
                json!(monitor_unit.exists()),
                json!(is_mounted(&mp)),
                json!(power::is_powered(disk)),
            ),
        };

        let mgmt = manage::classify(&ctx.config, disk);

        rows.push(json!({
            "name": disk.name,
            "enabled": disk.enabled,
            "remote": disk.remote,
            "transport": disk.transport.map(|t| t.as_str()),
            "management": mgmt,
            "host": remote.map(|r| r.host.clone()),
            "device": device,
            "physical_device": physical_device,
            "mapper": disk.mapper_name(),
            "uuid": disk.uuid,
            "fstype": disk.fstype,
            "luks2": info.is_luks2,
            "keyslots": info.keyslots.len(),
            "tokens": info.tokens,
            "tpm2_token": info.has_tpm2_token(),
            "non_tpm_fallback": info.has_non_tpm_fallback(),
            "crypttab": crypttab,
            "mountpoint": mp,
            "mounted": mounted,
            "power_profile": disk.power_profile,
            "standby_timeout_secs": disk.standby_timeout_secs(&ctx.config.defaults),
            "teardown": disk.teardown,
            "monitored": monitored,
            "powered": powered,
        }));
    }

    // Per-remote metadata for the dashboard's source grouping: the machines that
    // actually hold configured disks, each with the epoch tpmnt last connected it
    // (so the dashboard can order them most-recently-connected first).
    let remotes: Vec<Value> = ctx
        .config
        .remotes
        .iter()
        .filter(|r| {
            ctx.config
                .disks
                .iter()
                .any(|d| d.remote.as_deref() == Some(r.name.as_str()))
        })
        .map(|r| {
            json!({
                "name": r.name,
                "enabled": r.enabled,
                "host": r.host,
                "last_connected": crate::remote_state::last_connected(&ctx.paths, &r.name),
            })
        })
        .collect();

    Ok(json!({
        "ok": true,
        "env": ctx.env,
        "now": crate::remote_state::now_secs(),
        "remotes": remotes,
        "disks": rows,
    }))
}

/// Whether `mountpoint` is an active mount on a remote, via `findmnt` over SSH.
fn remote_mounted(ctx: &Context, prefix: &[String], mountpoint: &str) -> bool {
    ctx.runner
        .probe_on(
            prefix,
            &["findmnt", "-rn", "-M", mountpoint],
            "check remote mount state",
        )
        .map(|o| o.ok())
        .unwrap_or(false)
}

/// Whether a remote disk's mapper is open (`/dev/mapper/<mapper>` exists there).
fn remote_powered(ctx: &Context, prefix: &[String], mapper: &str) -> bool {
    ctx.runner
        .probe_on(
            prefix,
            &["test", "-e", &format!("/dev/mapper/{mapper}")],
            "check remote mapper (powered) state",
        )
        .map(|o| o.ok())
        .unwrap_or(false)
}

/// Render the status JSON as a human-readable table.
pub fn render_table(value: &Value) -> String {
    let mut out = String::new();
    if let Some(env) = value.get("env") {
        out.push_str(&format!(
            "env: distro={} systemd={} tpm={} initramfs={}\n",
            env.get("distro_id").and_then(|v| v.as_str()).unwrap_or("?"),
            env.get("systemd_version")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
            env.get("tpm_rm_present")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            env.get("initramfs").and_then(|v| v.as_str()).unwrap_or("?"),
        ));
        // See render_dashboard: non-root can't read headers or the key store,
        // so LUKS2/MANAGED columns would be uniformly (and falsely) "no".
        if env.get("privileged").and_then(|v| v.as_bool()) == Some(false) {
            out.push_str(
                "warning: not running as root — LUKS2/MANAGED columns can't be read; re-run with sudo\n",
            );
        }
    }
    out.push_str(&format!(
        "{:<12} {:<11} {:<7} {:<6} {:<9} {:<8} {:<13} {}\n",
        "NAME", "MANAGED", "LUKS2", "TOKEN", "CRYPTTAB", "MOUNTED", "PROFILE", "MOUNTPOINT"
    ));
    if let Some(disks) = value.get("disks").and_then(|v| v.as_array()) {
        if disks.is_empty() {
            out.push_str("(no disks configured)\n");
        }
        for d in disks {
            let yn = |k: &str| {
                if d.get(k).and_then(|v| v.as_bool()).unwrap_or(false) {
                    "yes"
                } else {
                    "no"
                }
            };
            // Managed disks show "managed"; unmanaged show the reason.
            let mgmt = d.get("management");
            let managed = mgmt
                .and_then(|m| m.get("managed"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mgmt_label = if managed {
                "managed"
            } else {
                mgmt.and_then(|m| m.get("reason"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unmanaged")
            };
            out.push_str(&format!(
                "{:<12} {:<11} {:<7} {:<6} {:<9} {:<8} {:<13} {}\n",
                d.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                mgmt_label,
                yn("luks2"),
                yn("tpm2_token"),
                yn("crypttab"),
                yn("mounted"),
                d.get("power_profile")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?"),
                d.get("mountpoint").and_then(|v| v.as_str()).unwrap_or("?"),
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// `tpmnt dashboard` — a fancy, TUI-style rendering of the same status JSON.
// Pure presentation: it consumes the exact value `status` returns, so the
// machine contract is unchanged. Colors are emitted only to a real terminal
// (and never when NO_COLOR is set), so piped/`--json` output stays clean.
// ---------------------------------------------------------------------------

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const GREY: &str = "\x1b[90m";
const BOLD_CYAN: &str = "\x1b[1m\x1b[36m";

/// Visible content width inside each panel (between the side borders + padding).
/// Wide enough for a full `device   /dev/disk/by-uuid/<uuid>` line.
const C: usize = 68;

/// Whether to emit ANSI color: a real stdout terminal with NO_COLOR unset.
fn color_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

/// A line built from styled fragments. Width is tracked on the *visible* text
/// (escape codes are zero-width) and the line is truncated to `C` columns at
/// render time, so every border lines up no matter how long a value runs.
struct Row {
    on: bool,
    spans: Vec<(String, &'static str)>,
}

impl Row {
    fn new(on: bool) -> Row {
        Row {
            on,
            spans: Vec::new(),
        }
    }

    fn add(&mut self, text: &str, code: &'static str) -> &mut Row {
        if !text.is_empty() {
            self.spans.push((text.to_string(), code));
        }
        self
    }

    fn plain(&mut self, text: &str) -> &mut Row {
        self.add(text, "")
    }

    fn paint(&self, text: &str, code: &str) -> String {
        if self.on && !code.is_empty() {
            format!("{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    /// Close the row into a bordered line, padded — or truncated with `…` — to
    /// exactly the panel width.
    fn finish(&self) -> String {
        let mut buf = String::new();
        let mut used = 0usize;
        for (text, code) in &self.spans {
            let chars: Vec<char> = text.chars().collect();
            if used + chars.len() <= C {
                buf.push_str(&self.paint(text, code));
                used += chars.len();
            } else {
                let room = C.saturating_sub(used);
                if room == 0 {
                    break;
                }
                let take = room.saturating_sub(1);
                let mut part: String = chars[..take].iter().collect();
                part.push('…');
                buf.push_str(&self.paint(&part, code));
                used = C;
                break;
            }
        }
        format!("│ {}{} │\n", buf, " ".repeat(C - used))
    }
}

fn b(v: &Value, k: &str) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(false)
}
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("?")
}

/// Top border carrying the panel title; width matches `Row::finish`.
fn panel_top(title_plain: &str, title_painted: &str) -> String {
    let dashes = C.saturating_sub(title_plain.chars().count() + 1);
    format!("┌─ {} {}┐\n", title_painted, "─".repeat(dashes))
}
fn panel_bottom() -> String {
    format!("└{}┘\n", "─".repeat(C + 2))
}

/// Format an elapsed span (now − then, both unix seconds) as a compact "ago"
/// string. Returns `None` when either timestamp is missing so the caller can
/// omit the annotation entirely.
fn fmt_ago(now: Option<u64>, then: Option<u64>) -> Option<String> {
    let (now, then) = (now?, then?);
    let d = now.saturating_sub(then);
    Some(if d < 60 {
        "just now".to_string()
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86_400)
    })
}

/// One compact line summarizing a single disk, for rendering *inside* a source
/// box. Leads with a power/mount glyph, then the disk name and the facts that
/// matter at a glance: LUKS2 + TPM2 posture (with a ▲ lockout-risk flag),
/// management verdict, and mount state. Truncated to the panel width by `Row`.
fn disk_line(on: bool, d: &Value) -> String {
    // A disabled disk is dormant — show it greyed with a distinct marker and skip
    // the live power/mount facts (they don't apply while it's disabled).
    let enabled = d.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    if !enabled {
        let mut r = Row::new(on);
        r.add("⊘ ", GREY);
        r.add(&format!("{:<12} ", s(d, "name")), GREY);
        r.add("disabled", YELLOW);
        r.add("  (enable to manage)", GREY);
        return r.finish();
    }

    let mounted = b(d, "mounted");
    let powered = b(d, "powered");
    let cold = s(d, "power_profile") == "cold-standby";
    let (glyph, gcolor) = if mounted {
        ("●", GREEN)
    } else if powered {
        ("◐", YELLOW)
    } else if cold {
        ("◌", CYAN)
    } else {
        ("○", GREY)
    };

    let luks2 = b(d, "luks2");
    let tpm = b(d, "tpm2_token");
    let fallback = b(d, "non_tpm_fallback");

    let mut r = Row::new(on);
    r.add(&format!("{glyph} "), gcolor);
    r.add(&format!("{:<12} ", s(d, "name")), BOLD_CYAN);

    if luks2 {
        r.add("LUKS2", GREEN);
    } else {
        r.add("✗LUKS2", RED);
    }
    r.add("·", GREY);
    if tpm {
        r.add("TPM2", GREEN);
    } else {
        r.add("noTPM", GREY);
    }
    if luks2 && !fallback {
        r.add(" ▲", YELLOW);
    }

    r.plain("  ");
    let managed = d
        .get("management")
        .and_then(|m| m.get("managed"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let reason = d
        .get("management")
        .and_then(|m| m.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    if managed {
        r.add("managed", GREEN);
    } else if reason == "remote-decrypt" {
        r.add("forward-only", YELLOW);
    } else {
        r.add("foreign-key", YELLOW);
    }

    if mounted {
        r.plain("  ");
        r.add(&format!("→ {}", s(d, "mountpoint")), DIM);
    }
    r.finish()
}

/// Render the status JSON as a fancy dashboard — one box per *source* (this
/// machine first, then each remote most-recently-connected first), with a
/// compact line per disk inside.
pub fn render_dashboard(value: &Value) -> String {
    let on = color_enabled();
    let paint = |t: &str, code: &str| -> String {
        if on && !code.is_empty() {
            format!("{code}{t}{RESET}")
        } else {
            t.to_string()
        }
    };
    let mut out = String::new();

    // ---- header: product banner + detected environment -------------------
    out.push('\n');
    out.push_str(&format!(
        " {} {}\n",
        paint("▟▙ tpmnt", &format!("{BOLD}{CYAN}")),
        paint("disk dashboard", DIM),
    ));
    if let Some(env) = value.get("env") {
        let tpm = env.get("tpm_rm_present").and_then(|v| v.as_bool());
        let tpm_str = match tpm {
            Some(true) => paint(&format!("● {}", s(env, "tpm_path")), GREEN),
            _ => paint("○ no TPM resource manager", YELLOW),
        };
        out.push_str(&format!(
            " {}  distro {}  ·  systemd {}  ·  initramfs {}  ·  TPM {}\n",
            paint("env", GREY),
            s(env, "distro_id"),
            env.get("systemd_version")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
            s(env, "initramfs"),
            tpm_str,
        ));
        // Without root, `cryptsetup luksDump` and the root-only key store are
        // both unreadable, so every disk would misreport as "not LUKS2" and
        // "unmanaged". Warn loudly rather than let the panels lie.
        if env.get("privileged").and_then(|v| v.as_bool()) == Some(false) {
            out.push_str(&format!(
                " {}\n",
                paint(
                    "⚠ not running as root — LUKS2 and management state can't be read; re-run with sudo",
                    &format!("{BOLD}{YELLOW}"),
                ),
            ));
        }
    }
    out.push('\n');

    let disks = value.get("disks").and_then(|v| v.as_array());
    let disks = match disks {
        Some(d) if !d.is_empty() => d,
        _ => {
            out.push_str(&format!(
                " {}\n\n",
                paint(
                    "no disks configured — run `tpmnt init` or `tpmnt enroll`",
                    DIM
                )
            ));
            return out;
        }
    };

    // -- footer counts, tallied once over every disk -----------------------
    let mut n_enc = 0;
    let mut n_auto = 0;
    let mut n_risk = 0;
    let mut n_mounted = 0;
    let mut n_remote = 0;
    let mut n_managed = 0;
    let mut n_unmanaged = 0;
    for d in disks {
        if b(d, "luks2") {
            n_enc += 1;
        }
        if b(d, "tpm2_token") {
            n_auto += 1;
        }
        if b(d, "luks2") && !b(d, "non_tpm_fallback") {
            n_risk += 1;
        }
        if b(d, "mounted") {
            n_mounted += 1;
        }
        if d.get("host").and_then(|v| v.as_str()).is_some() {
            n_remote += 1;
        }
        if d.get("management")
            .and_then(|m| m.get("managed"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            n_managed += 1;
        } else {
            n_unmanaged += 1;
        }
    }

    // -- group disks by source: local (host null) vs each remote -----------
    let mut local: Vec<&Value> = Vec::new();
    let mut by_remote: std::collections::BTreeMap<&str, Vec<&Value>> =
        std::collections::BTreeMap::new();
    for d in disks {
        if d.get("host").and_then(|v| v.as_str()).is_some() {
            let rn = s(d, "remote");
            by_remote.entry(rn).or_default().push(d);
        } else {
            local.push(d);
        }
    }

    let now = value.get("now").and_then(|v| v.as_u64());

    // -- box 1: always "self" (this machine), even if it holds no disks ------
    let hostname = value
        .get("env")
        .and_then(|e| e.get("hostname"))
        .and_then(|v| v.as_str())
        .unwrap_or("this machine");
    let title_plain = format!("{hostname}  · local");
    let title_painted = format!(
        "{}{}",
        paint(hostname, &format!("{BOLD}{CYAN}")),
        paint("  · local", GREY),
    );
    out.push_str(&panel_top(&title_plain, &title_painted));
    if local.is_empty() {
        let mut r = Row::new(on);
        r.add("(no local disks)", DIM);
        out.push_str(&r.finish());
    } else {
        for d in &local {
            out.push_str(&disk_line(on, d));
        }
    }
    out.push_str(&panel_bottom());

    // -- remaining boxes: remotes, most-recently-connected first -----------
    let remote_meta = |name: &str| -> Option<&Value> {
        value
            .get("remotes")
            .and_then(|v| v.as_array())
            .and_then(|rs| {
                rs.iter()
                    .find(|r| r.get("name").and_then(|v| v.as_str()) == Some(name))
            })
    };
    let last_of = |name: &str| -> Option<u64> {
        remote_meta(name).and_then(|r| r.get("last_connected").and_then(|v| v.as_u64()))
    };
    let remote_enabled = |name: &str| -> bool {
        remote_meta(name)
            .and_then(|r| r.get("enabled").and_then(|v| v.as_bool()))
            .unwrap_or(true)
    };
    let mut order: Vec<(&str, Option<u64>)> = by_remote.keys().map(|n| (*n, last_of(n))).collect();
    // Newest connection first; never-connected (None) sink to the bottom; ties
    // broken by name so the ordering is deterministic (and testable).
    order.sort_by(|a, b| match (a.1, b.1) {
        (Some(x), Some(y)) => y.cmp(&x).then(a.0.cmp(b.0)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.0.cmp(b.0),
    });

    for (name, last) in order {
        let group = &by_remote[name];
        let host = group
            .first()
            .and_then(|d| d.get("host").and_then(|v| v.as_str()))
            .unwrap_or("?");
        // A source is "connected" if any of its disks is currently up here; a
        // disabled remote is called out so `up` skipping it makes sense.
        let connected = group.iter().any(|d| b(d, "mounted") || b(d, "powered"));
        let (state_glyph, state_word, state_color) = if !remote_enabled(name) {
            ("⊘", "disabled", YELLOW)
        } else if connected {
            ("●", "connected", GREEN)
        } else {
            ("○", "idle", GREY)
        };
        let ago = fmt_ago(now, last);

        let mut title_plain = format!("{name}  ⇄ {host}  {state_glyph} {state_word}");
        let mut title_painted = format!(
            "{}{}{}",
            paint(name, &format!("{BOLD}{CYAN}")),
            paint(&format!("  ⇄ {host}  "), GREY),
            paint(&format!("{state_glyph} {state_word}"), state_color),
        );
        if let Some(a) = &ago {
            title_plain.push_str(&format!("  · {a}"));
            title_painted.push_str(&paint(&format!("  · {a}"), DIM));
        }
        out.push_str(&panel_top(&title_plain, &title_painted));
        for d in group.iter() {
            out.push_str(&disk_line(on, d));
        }
        out.push_str(&panel_bottom());
    }

    // ---- footer summary ---------------------------------------------------
    let total = disks.len();
    out.push('\n');
    out.push_str(&format!(
        " {}  {} disk(s)  ·  {} managed  ·  {} encrypted  ·  {} auto-unlock  ·  {} mounted",
        paint("summary", GREY),
        total,
        n_managed,
        n_enc,
        n_auto,
        n_mounted,
    ));
    if n_unmanaged > 0 {
        out.push_str(&paint(&format!("  ·  ○ {n_unmanaged} unmanaged"), YELLOW));
    }
    if n_remote > 0 {
        out.push_str(&paint(&format!("  ·  ⇄ {n_remote} remote"), CYAN));
    }
    if n_risk > 0 {
        out.push_str(&paint(
            &format!("  ·  ▲ {n_risk} without fallback key"),
            YELLOW,
        ));
    }
    out.push_str("\n\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        json!({
            "env": {
                "hostname": "nobara",
                "distro_id": "fedora", "systemd_version": 255,
                "tpm_rm_present": true, "tpm_path": "/dev/tpmrm0",
                "initramfs": "dracut"
            },
            "now": 1_000_000,
            "remotes": [],
            "disks": [{
                "name": "backup", "device": "/dev/disk/by-uuid/abcd",
                "physical_device": "/dev/sdb", "mapper": "tpmnt-backup",
                "uuid": "abcd", "fstype": "xfs", "luks2": true, "keyslots": 2,
                "tokens": ["systemd-tpm2"], "tpm2_token": true,
                "non_tpm_fallback": true, "crypttab": true,
                "mountpoint": "/mnt/backup", "mounted": false,
                "power_profile": "cold-standby", "standby_timeout_secs": 600,
                "teardown": "direct", "monitored": true, "powered": false,
                "management": {
                    "managed": true, "reason": "managed",
                    "detail": "key generated/imported locally and decryption stays on this host",
                    "local_key": true, "local_decrypt": true
                }
            }]
        })
    }

    /// A minimal remote disk row for grouping/ordering tests.
    fn remote_disk(name: &str, remote: &str, host: &str, up: bool) -> Value {
        json!({
            "name": name, "remote": remote, "host": host,
            "uuid": "u", "mapper": "m", "fstype": "btrfs",
            "luks2": true, "tpm2_token": true, "non_tpm_fallback": true,
            "mountpoint": format!("/mnt/{name}"), "mounted": up, "powered": up,
            "power_profile": "cold-standby",
            "management": { "managed": true, "reason": "managed",
                "detail": "", "local_key": true, "local_decrypt": true }
        })
    }

    #[test]
    fn dashboard_renders_key_fields_uncolored() {
        // Force the no-color path so the assertions are escape-free and stable.
        std::env::set_var("NO_COLOR", "1");
        let out = render_dashboard(&sample());
        // The local box is titled with this machine's hostname.
        assert!(out.contains("nobara"));
        assert!(out.contains("· local"));
        // The disk shows up as a compact line inside it.
        assert!(out.contains("backup"));
        assert!(out.contains("LUKS2"));
        assert!(out.contains("TPM2"));
        assert!(out.contains("summary"));
        assert!(
            !out.contains('\x1b'),
            "NO_COLOR output must carry no escapes"
        );
    }

    #[test]
    fn dashboard_warns_when_unprivileged() {
        std::env::set_var("NO_COLOR", "1");
        // Non-root: header must carry the warning so misreported LUKS2/managed
        // panels aren't taken at face value.
        let mut v = sample();
        v["env"]["privileged"] = json!(false);
        assert!(render_dashboard(&v).contains("not running as root"));
        assert!(render_table(&v).contains("not running as root"));

        // Root (or unknown): no warning.
        v["env"]["privileged"] = json!(true);
        assert!(!render_dashboard(&v).contains("not running as root"));
        assert!(!render_dashboard(&sample()).contains("not running as root"));
    }

    #[test]
    fn dashboard_shows_management_verdict_and_footer() {
        std::env::set_var("NO_COLOR", "1");
        // Managed disk renders the managed tag + footer count.
        let out = render_dashboard(&sample());
        assert!(out.contains("managed"));
        assert!(out.contains("1 managed"));

        // A foreign-key (unmanaged) disk is tagged as such and counted.
        let mut v = sample();
        v["disks"][0]["management"] = json!({
            "managed": false, "reason": "foreign-key", "detail": "",
            "local_key": false, "local_decrypt": true
        });
        let out = render_dashboard(&v);
        assert!(out.contains("foreign-key"));
        assert!(out.contains("1 unmanaged"));
    }

    #[test]
    fn dashboard_flags_lockout_risk() {
        std::env::set_var("NO_COLOR", "1");
        let mut v = sample();
        v["disks"][0]["non_tpm_fallback"] = json!(false);
        let out = render_dashboard(&v);
        // Compact line carries the ▲ risk marker; the footer tallies it.
        assert!(out.contains('▲'));
        assert!(out.contains("without fallback key"));
    }

    #[test]
    fn dashboard_handles_no_disks() {
        std::env::set_var("NO_COLOR", "1");
        let out = render_dashboard(&json!({"disks": []}));
        assert!(out.contains("no disks configured"));
    }

    #[test]
    fn dashboard_groups_remote_disks_under_a_source_box() {
        std::env::set_var("NO_COLOR", "1");
        let mut v = sample();
        v["disks"][0]["remote"] = json!("nas");
        v["disks"][0]["host"] = json!("alice@192.168.5.10");
        v["remotes"] = json!([{ "name": "nas", "host": "alice@192.168.5.10",
                                 "last_connected": 999_400 }]);
        let out = render_dashboard(&v);
        // The remote's own box carries the remote name + host in its title…
        assert!(out.contains("nas"));
        assert!(out.contains("⇄ alice@192.168.5.10"));
        // …a relative "ago" from now (1_000_000) − last (999_400) = 600s = 10m…
        assert!(out.contains("10m ago"), "{out}");
        // …the disk still lists inside, and the footer counts it as remote.
        assert!(out.contains("backup"));
        assert!(out.contains("1 remote"));
    }

    #[test]
    fn dashboard_self_first_then_remotes_newest_connection_first() {
        std::env::set_var("NO_COLOR", "1");
        // One local disk, plus disks on two remotes with different recency.
        let v = json!({
            "env": { "hostname": "myhost" },
            "now": 1_000_000,
            "remotes": [
                { "name": "attic", "host": "u@attic", "last_connected": 100 },
                { "name": "shed",  "host": "u@shed",  "last_connected": 900_000 },
            ],
            "disks": [
                json!({ "name": "here", "uuid": "u", "mapper": "m", "fstype": "xfs",
                    "luks2": true, "tpm2_token": true, "non_tpm_fallback": true,
                    "mountpoint": "/mnt/here", "mounted": true, "powered": true,
                    "power_profile": "always-on",
                    "management": { "managed": true, "reason": "managed", "detail": "",
                        "local_key": true, "local_decrypt": true } }),
                remote_disk("a", "attic", "u@attic", false),
                remote_disk("s", "shed", "u@shed", true),
            ]
        });
        let out = render_dashboard(&v);
        let i_self = out.find("myhost").expect("self box");
        let i_shed = out.find("shed").expect("shed box");
        let i_attic = out.find("attic").expect("attic box");
        // Self is always first; then remotes most-recently-connected first, so
        // shed (900_000) precedes attic (100).
        assert!(i_self < i_shed, "self must come first\n{out}");
        assert!(i_shed < i_attic, "newer remote must precede older\n{out}");
        // The connected remote reads "connected"; the idle one reads "idle".
        assert!(out.contains("● connected"));
        assert!(out.contains("○ idle"));
    }

    #[test]
    fn dashboard_always_renders_self_box_even_with_no_local_disks() {
        std::env::set_var("NO_COLOR", "1");
        let v = json!({
            "env": { "hostname": "myhost" },
            "now": 1_000_000,
            "remotes": [{ "name": "shed", "host": "u@shed", "last_connected": 900_000 }],
            "disks": [ remote_disk("s", "shed", "u@shed", true) ]
        });
        let out = render_dashboard(&v);
        let i_self = out.find("myhost").expect("self box present");
        let i_shed = out.find("shed").expect("shed box");
        assert!(i_self < i_shed, "self box first even when empty\n{out}");
        assert!(out.contains("(no local disks)"));
    }

    #[test]
    fn fmt_ago_buckets_by_magnitude() {
        assert_eq!(fmt_ago(Some(1000), Some(999)).as_deref(), Some("just now"));
        assert_eq!(fmt_ago(Some(1000), Some(400)).as_deref(), Some("10m ago"));
        assert_eq!(fmt_ago(Some(10_000), Some(2800)).as_deref(), Some("2h ago"));
        assert_eq!(fmt_ago(Some(200_000), Some(0)).as_deref(), Some("2d ago"));
        // Missing either endpoint → no annotation.
        assert_eq!(fmt_ago(None, Some(1)), None);
        assert_eq!(fmt_ago(Some(1), None), None);
    }
}
