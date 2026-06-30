//! `tpmnt status` — per-disk reality check: LUKS2? TPM2 token? crypttab entry?
//! mounted? Emits both a human table and `--json`.

use serde_json::{json, Value};

use crate::error::Result;
use crate::luks;
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

pub fn run(ctx: &Context) -> Result<Value> {
    let mut rows = Vec::new();

    for disk in &ctx.config.disks {
        let device = disk.device_path();
        let info = luks::inspect(&ctx.runner, &device).unwrap_or_default();
        let mp = disk.mountpoint.to_string_lossy().to_string();
        let monitor_unit = ctx
            .paths
            .systemd_unit_dir()
            .join(format!("tpmnt-monitor-{}.service", disk.name));
        rows.push(json!({
            "name": disk.name,
            "device": device,
            "uuid": disk.uuid,
            "luks2": info.is_luks2,
            "tpm2_token": info.has_tpm2_token(),
            "non_tpm_fallback": info.has_non_tpm_fallback(),
            "crypttab": crypttab_has(ctx, &disk.name),
            "mountpoint": mp,
            "mounted": is_mounted(&mp),
            "power_profile": disk.power_profile,
            "idle_timeout_secs": disk.idle_timeout_secs(),
            "monitored": monitor_unit.exists(),
            "powered": power::is_powered(disk),
        }));
    }

    Ok(json!({
        "ok": true,
        "env": ctx.env,
        "disks": rows,
    }))
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
        "{:<12} {:<7} {:<6} {:<9} {:<8} {:<13} {}\n",
        "NAME", "LUKS2", "TOKEN", "CRYPTTAB", "MOUNTED", "PROFILE", "MOUNTPOINT"
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
            out.push_str(&format!(
                "{:<12} {:<7} {:<6} {:<9} {:<8} {:<13} {}\n",
                d.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
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
