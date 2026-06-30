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

/// Manual spindown: unmount + close + power off the backing disk now.
pub fn run(ctx: &Context, args: &PowerArgs) -> Result<Value> {
    let disk = find_disk(ctx, &args.name)?;
    power::spindown(ctx, disk)
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
    // the idle window, clamped to a sane [5s, 60s] range.
    let poll = (disk.idle_timeout_secs() / 5).clamp(5, 60);
    loop {
        let tick = power::monitor_tick(ctx, disk)?;
        if ctx.global.debug {
            eprintln!("{tick}");
        }
        sleep(Duration::from_secs(poll));
    }
}
