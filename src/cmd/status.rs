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
            "poweroff_timeout_secs": disk.poweroff_timeout_secs(&ctx.config.defaults),
            "teardown": disk.teardown,
            "monitored": monitored,
            "powered": powered,
        }));
    }

    Ok(json!({
        "ok": true,
        "env": ctx.env,
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
fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(|x| x.as_u64()).unwrap_or(0)
}

/// Top border carrying the panel title; width matches `Row::finish`.
fn panel_top(title_plain: &str, title_painted: &str) -> String {
    let dashes = C.saturating_sub(title_plain.chars().count() + 1);
    format!("┌─ {} {}┐\n", title_painted, "─".repeat(dashes))
}
fn panel_bottom() -> String {
    format!("└{}┘\n", "─".repeat(C + 2))
}

/// Format an idle window in seconds back to a compact human string.
fn fmt_idle(secs: u64) -> String {
    if secs >= 3600 && secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs >= 60 && secs.is_multiple_of(60) {
        format!("{}min", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Render the status JSON as a fancy, panel-per-disk dashboard.
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

    let mut n_enc = 0;
    let mut n_auto = 0;
    let mut n_risk = 0;
    let mut n_mounted = 0;
    let mut n_remote = 0;
    let mut n_managed = 0;
    let mut n_unmanaged = 0;

    for d in disks {
        let name = s(d, "name");
        let profile = s(d, "power_profile");

        // -- title: name + power profile -----------------------------------
        let title_plain = format!("{name}  ·  {profile}");
        let title_painted = format!(
            "{}{}{}",
            paint(name, &format!("{BOLD}{CYAN}")),
            paint("  ·  ", GREY),
            paint(profile, DIM),
        );
        out.push_str(&panel_top(&title_plain, &title_painted));

        // -- identity ------------------------------------------------------
        let device = s(d, "device");
        let phys = s(d, "physical_device");
        let mut r = Row::new(on);
        r.add("device   ", GREY).plain(device);
        if phys != device && phys != "?" {
            r.add("  →  ", GREY).plain(phys);
        }
        out.push_str(&r.finish());

        let mut r = Row::new(on);
        r.add("uuid     ", GREY).plain(s(d, "uuid"));
        r.add("   mapper ", GREY).plain(s(d, "mapper"));
        out.push_str(&r.finish());

        // -- remote host (the only place a disk's machine is surfaced) -------
        if let Some(host) = d.get("host").and_then(|v| v.as_str()) {
            n_remote += 1;
            let mut r = Row::new(on);
            r.add("remote   ", GREY);
            r.add(&format!("⇄ {host}"), CYAN);
            if let Some(rn) = d.get("remote").and_then(|v| v.as_str()) {
                r.add(&format!("  [{rn}]"), DIM);
            }
            // How its ciphertext reaches this host (managed remote) vs forward-only.
            if let Some(t) = d.get("transport").and_then(|v| v.as_str()) {
                r.add(&format!("  ciphertext via {t}"), GREEN);
            } else {
                r.add("  forward-only", YELLOW);
            }
            out.push_str(&r.finish());
        }

        // -- encryption posture (the part tpmnt owns) ----------------------
        let luks2 = b(d, "luks2");
        let tpm = b(d, "tpm2_token");
        let fallback = b(d, "non_tpm_fallback");
        if luks2 {
            n_enc += 1;
        }
        if tpm {
            n_auto += 1;
        }
        let mut r = Row::new(on);
        r.add("crypto   ", GREY);
        if luks2 {
            r.add("● LUKS2", GREEN);
        } else {
            r.add("✗ not LUKS2", RED);
        }
        r.plain("   ");
        if tpm {
            r.add("● TPM2 auto-unlock", GREEN);
        } else {
            r.add("○ no TPM enroll", GREY);
        }
        r.plain("   ");
        if !luks2 {
            // fallback is meaningless without a container.
            r.add("", "");
        } else if fallback {
            r.add(&format!("✓ {} keyslot(s)", u(d, "keyslots")), GREEN);
        } else {
            n_risk += 1;
            r.add("▲ NO fallback key — lockout risk", YELLOW);
        }
        out.push_str(&r.finish());

        // -- management verdict (the threat-model boundary) ----------------
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
            n_managed += 1;
        } else {
            n_unmanaged += 1;
        }
        let mut r = Row::new(on);
        r.add("manage   ", GREY);
        if managed {
            r.add("● managed", GREEN);
            r.add("  key local · decrypt local", DIM);
        } else if reason == "remote-decrypt" {
            r.add("⇄ forward-only", YELLOW);
            r.add("  no ciphertext transport — tpmnt doesn't decrypt it", DIM);
        } else {
            r.add("○ unmanaged", YELLOW);
            r.add("  foreign key — run `tpmnt adopt`", DIM);
        }
        out.push_str(&r.finish());

        // -- system integration: crypttab + mount --------------------------
        let mounted = b(d, "mounted");
        if mounted {
            n_mounted += 1;
        }
        let is_remote = d.get("host").and_then(|v| v.as_str()).is_some();
        let mut r = Row::new(on);
        r.add("system   ", GREY);
        // crypttab is a local-management artifact; it doesn't apply to a disk
        // whose crypttab lives on another machine.
        if is_remote {
            r.add("⇄ remote-managed", CYAN);
        } else if b(d, "crypttab") {
            r.add("✓ crypttab", GREEN);
        } else {
            r.add("○ no crypttab", GREY);
        }
        r.plain("   ");
        if mounted {
            r.add(
                &format!("✓ mounted {} ({})", s(d, "mountpoint"), s(d, "fstype")),
                GREEN,
            );
        } else {
            r.add(&format!("○ not mounted {}", s(d, "mountpoint")), GREY);
        }
        out.push_str(&r.finish());

        // -- power / cold-standby ------------------------------------------
        let powered = b(d, "powered");
        let cold = profile == "cold-standby";
        let mut r = Row::new(on);
        r.add("power    ", GREY);
        if powered {
            r.add("● powered (mapper open)", GREEN);
        } else if cold {
            r.add("◌ spun-down (cold)", CYAN);
        } else {
            r.add("○ closed", GREY);
        }
        if cold {
            r.plain("   ");
            r.add(
                &format!(
                    "standby {} · off {}",
                    fmt_idle(u(d, "standby_timeout_secs")),
                    fmt_idle(u(d, "poweroff_timeout_secs"))
                ),
                DIM,
            );
            r.plain(" ");
            // Monitoring is a local systemd unit; not tracked for remote disks.
            if is_remote {
                r.add("· remote", CYAN);
            } else if b(d, "monitored") {
                r.add("· monitored", GREEN);
            } else {
                r.add("· unmonitored", YELLOW);
            }
        }
        out.push_str(&r.finish());

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
                "distro_id": "fedora", "systemd_version": 255,
                "tpm_rm_present": true, "tpm_path": "/dev/tpmrm0",
                "initramfs": "dracut"
            },
            "disks": [{
                "name": "backup", "device": "/dev/disk/by-uuid/abcd",
                "physical_device": "/dev/sdb", "mapper": "tpmnt-backup",
                "uuid": "abcd", "fstype": "xfs", "luks2": true, "keyslots": 2,
                "tokens": ["systemd-tpm2"], "tpm2_token": true,
                "non_tpm_fallback": true, "crypttab": true,
                "mountpoint": "/mnt/backup", "mounted": false,
                "power_profile": "cold-standby",
                "standby_timeout_secs": 300, "poweroff_timeout_secs": 1800,
                "teardown": "direct", "monitored": true, "powered": false,
                "management": {
                    "managed": true, "reason": "managed",
                    "detail": "key generated/imported locally and decryption stays on this host",
                    "local_key": true, "local_decrypt": true
                }
            }]
        })
    }

    #[test]
    fn dashboard_renders_key_fields_uncolored() {
        // Force the no-color path so the assertions are escape-free and stable.
        std::env::set_var("NO_COLOR", "1");
        let out = render_dashboard(&sample());
        assert!(out.contains("backup"));
        assert!(out.contains("LUKS2"));
        assert!(out.contains("TPM2 auto-unlock"));
        assert!(out.contains("spun-down"));
        assert!(out.contains("standby 5min · off 30min"));
        assert!(out.contains("summary"));
        assert!(
            !out.contains('\x1b'),
            "NO_COLOR output must carry no escapes"
        );
    }

    #[test]
    fn dashboard_shows_management_verdict_and_footer() {
        std::env::set_var("NO_COLOR", "1");
        // Managed disk renders the managed row + footer count.
        let out = render_dashboard(&sample());
        assert!(out.contains("● managed"));
        assert!(out.contains("key local · decrypt local"));
        assert!(out.contains("1 managed"));

        // A foreign-key (unmanaged) disk points the operator at `adopt`.
        let mut v = sample();
        v["disks"][0]["management"] = json!({
            "managed": false, "reason": "foreign-key", "detail": "",
            "local_key": false, "local_decrypt": true
        });
        let out = render_dashboard(&v);
        assert!(out.contains("○ unmanaged"));
        assert!(out.contains("tpmnt adopt"));
        assert!(out.contains("1 unmanaged"));
    }

    #[test]
    fn dashboard_flags_lockout_risk() {
        std::env::set_var("NO_COLOR", "1");
        let mut v = sample();
        v["disks"][0]["non_tpm_fallback"] = json!(false);
        let out = render_dashboard(&v);
        assert!(out.contains("NO fallback key"));
        assert!(out.contains("without fallback key"));
    }

    #[test]
    fn dashboard_handles_no_disks() {
        std::env::set_var("NO_COLOR", "1");
        let out = render_dashboard(&json!({"disks": []}));
        assert!(out.contains("no disks configured"));
    }

    #[test]
    fn dashboard_surfaces_remote_host() {
        std::env::set_var("NO_COLOR", "1");
        let mut v = sample();
        v["disks"][0]["remote"] = json!("nas");
        v["disks"][0]["host"] = json!("alice@192.168.5.10");
        // Local-only fields are null for a remote disk.
        v["disks"][0]["crypttab"] = Value::Null;
        v["disks"][0]["monitored"] = Value::Null;
        let out = render_dashboard(&v);
        // The host is shown (the one place a disk's machine is surfaced)…
        assert!(out.contains("alice@192.168.5.10"));
        assert!(out.contains("[nas]"));
        // …crypttab reads as remote-managed, not a misleading "no crypttab"…
        assert!(out.contains("remote-managed"));
        assert!(!out.contains("no crypttab"));
        // …and the footer counts it.
        assert!(out.contains("1 remote"));
    }
}
