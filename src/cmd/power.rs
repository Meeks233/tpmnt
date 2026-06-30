//! `tpmnt power <name>` — manual one-shot disk spindown, and
//! `tpmnt monitor <name> [--once]` — the cold-standby idle watcher run by the
//! generated systemd unit. The actual logic lives in `crate::power`.

use std::thread::sleep;
use std::time::Duration;

use serde_json::Value;

use crate::cli::{MonitorArgs, PowerArgs};
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
