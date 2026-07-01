//! `tpmnt power <name>` — manual one-shot disk spindown, and
//! `tpmnt monitor <name> [--once]` — the cold-standby idle watcher run by the
//! generated systemd unit. The actual logic lives in `crate::power`.

use std::thread::sleep;
use std::time::Duration;

use serde_json::Value;

use serde_json::json;

use crate::cli::{MonitorArgs, PowerArgs, ScheduleArgs};
use crate::error::{err, Code, Result};
use crate::power;

use super::Context;

fn find_disk<'a>(ctx: &'a Context, name: &str) -> Result<&'a crate::config::Disk> {
    ctx.config
        .disks
        .iter()
        .find(|d| d.name == name)
        .ok_or_else(|| {
            crate::error::Error::new(Code::EConfig, format!("no [[disk]] named '{name}'"))
                .with_hint("check `tpmnt status` for configured disk names")
        })
}

/// `tpmnt power`: one verb for the whole power lifecycle, so callers never touch
/// the underlying cryptsetup/mount/hdparm/udisks/nbd steps:
///   * a timeout flag *configures* the cold-standby windows (global or per-disk);
///   * `--on` brings the disk back up (rescan + rebuild forward + open + mount);
///   * otherwise (or `--off`) it spins the named disk down, honoring a one-shot
///     `--method` override of the configured power_off_method.
pub fn run(ctx: &Context, args: &PowerArgs) -> Result<Value> {
    if args.standby_timeout.is_some() || args.poweroff_timeout.is_some() {
        return set_timeouts(ctx, args);
    }

    let name = args.name.as_deref().ok_or_else(|| {
        crate::error::Error::new(Code::EConfig, "power needs a disk name".to_string()).with_hint(
            "pass a [[disk]] name to power on/off, or --standby-timeout/--poweroff-timeout to configure",
        )
    })?;
    let disk = find_disk(ctx, name)?;

    if args.on {
        return power::spinup(ctx, disk);
    }

    let method = match args.method.as_deref() {
        Some(s) => Some(crate::config::PowerOffMethod::parse(s).ok_or_else(|| {
            crate::error::Error::new(Code::EConfig, format!("invalid --method '{s}'"))
                .with_hint("use 'auto', 'standby', 'sleep', 'power-off', or 'remove'")
        })?),
        None => None,
    };
    power::spindown(ctx, disk, method)
}

/// Set the cold-standby standby/power-off idle windows and persist the config.
/// With --global (or no disk name) the values land in `[defaults]`; otherwise
/// they override just the named disk. Per-disk values take precedence at runtime.
fn set_timeouts(ctx: &Context, args: &PowerArgs) -> Result<Value> {
    // Validate durations up front so a typo never writes a bad config.
    for v in [&args.standby_timeout, &args.poweroff_timeout]
        .into_iter()
        .flatten()
    {
        if crate::config::parse_duration(v).is_none() {
            return err(
                Code::EConfig,
                format!("invalid duration '{v}' (use e.g. \"5min\", \"30s\", \"1h\")"),
            );
        }
    }

    let path = &ctx.global.config;
    let mut cfg = crate::config::Config::load(path)?;
    let dry = ctx.global.effective_dry_run();
    let global = args.global || args.name.is_none();

    let scope = if global {
        if let Some(s) = &args.standby_timeout {
            cfg.defaults.standby_timeout = s.clone();
        }
        if let Some(p) = &args.poweroff_timeout {
            cfg.defaults.poweroff_timeout = p.clone();
        }
        json!({"scope": "global"})
    } else {
        let name = args.name.as_deref().unwrap();
        let disk = cfg
            .disks
            .iter_mut()
            .find(|d| d.name == name)
            .ok_or_else(|| {
                crate::error::Error::new(Code::EConfig, format!("no [[disk]] named '{name}'"))
                    .with_hint("check `tpmnt status` for configured disk names")
            })?;
        if args.standby_timeout.is_some() {
            disk.standby_timeout = args.standby_timeout.clone();
        }
        if args.poweroff_timeout.is_some() {
            disk.poweroff_timeout = args.poweroff_timeout.clone();
        }
        json!({"scope": "disk", "name": name})
    };

    if !dry {
        cfg.save(path)?;
    }
    Ok(json!({
        "ok": true,
        "action": "set-power-timeouts",
        "scope": scope,
        "standby_timeout": args.standby_timeout,
        "poweroff_timeout": args.poweroff_timeout,
        "config": path.display().to_string(),
        "dry_run": dry,
    }))
}

/// Select the disks a `schedule` run applies to: the named ones, or every disk
/// that has a `[disk.schedule]` when no names are given.
fn schedule_disks<'a>(ctx: &'a Context, names: &[String]) -> Result<Vec<&'a crate::config::Disk>> {
    if names.is_empty() {
        return Ok(ctx
            .config
            .disks
            .iter()
            .filter(|d| d.schedule.is_some())
            .collect());
    }
    names.iter().map(|n| find_disk(ctx, n)).collect()
}

/// Apply on/off schedules. `--once` runs a single tick across the selected disks
/// (used by tests and ad-hoc runs); otherwise it loops like the systemd unit,
/// re-evaluating every 30s so a busy disk is re-checked as its grace elapses.
pub fn schedule(ctx: &Context, args: &ScheduleArgs) -> Result<Value> {
    let disks = schedule_disks(ctx, &args.names)?;
    if disks.is_empty() {
        return err(
            Code::EConfig,
            "no scheduled disks; add a [disk.schedule] block or name a disk".to_string(),
        );
    }

    let tz = args.timezone.as_deref();
    if args.once {
        let ticks: Vec<Value> = disks
            .iter()
            .map(|d| power::schedule_tick(ctx, d, tz))
            .collect::<Result<_>>()?;
        return Ok(json!({"ok": true, "action": "schedule", "disks": ticks}));
    }

    loop {
        for d in &disks {
            let tick = power::schedule_tick(ctx, d, tz)?;
            if ctx.global.debug {
                eprintln!("{tick}");
            }
        }
        sleep(Duration::from_secs(30));
    }
}

/// Idle watcher. `--once` does a single tick (deterministic, for the self-test);
/// otherwise it loops, sleeping a fraction of the idle window between checks.
pub fn monitor(ctx: &Context, args: &MonitorArgs) -> Result<Value> {
    let disk = find_disk(ctx, &args.name)?;

    if !disk.is_cold_standby() && !args.once {
        // A monitor loop only makes sense for cold-standby; bail loudly.
        return err(
            Code::EConfig,
            format!(
                "disk '{}' is not cold-standby; nothing to monitor",
                args.name
            ),
        );
    }

    if args.once {
        return power::monitor_tick(ctx, disk);
    }

    // Loop forever (the systemd unit owns the lifecycle). Poll at a fraction of
    // the (shorter) standby window, clamped to a sane [5s, 60s] range so both the
    // standby and power-off thresholds are caught promptly.
    let poll = (disk.standby_timeout_secs(&ctx.config.defaults) / 5).clamp(5, 60);
    loop {
        let tick = power::monitor_tick(ctx, disk)?;
        if ctx.global.debug {
            eprintln!("{tick}");
        }
        sleep(Duration::from_secs(poll));
    }
}
