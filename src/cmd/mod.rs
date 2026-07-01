//! Subcommand implementations. Each returns a JSON result value on success;
//! `main` renders it as text or JSON and, under `--plan`, emits the recorded
//! command plan instead of applying.

pub mod adopt;
pub mod apply;
pub mod destroy;
pub mod enroll;
pub mod init;
pub mod migrate;
pub mod mount_remote;
pub mod offline;
pub mod power;
pub mod recover;
pub mod remote;
pub mod rename;
pub mod rollback;
pub mod status;

use crate::cli::GlobalOpts;
use crate::config::Config;
use crate::env::EnvInfo;
use crate::exec::Runner;
use crate::paths::Paths;

/// Shared state threaded through every subcommand.
pub struct Context {
    pub global: GlobalOpts,
    pub config: Config,
    pub runner: Runner,
    pub paths: Paths,
    pub env: EnvInfo,
}

/// Ensure the udev rule hiding NBD ciphertext-transport devices from udisks is
/// installed, and (when it was just written) reload udev so an already-attached
/// `/dev/nbdN` is re-evaluated and dropped from the desktop file manager. Called
/// during reconcile for transport-backed disks. Returns the file change for
/// --plan/--dry-run reporting.
pub fn ensure_nbd_hidden(
    ctx: &Context,
    dry: bool,
) -> crate::error::Result<crate::reconcile::FileChange> {
    let change = crate::reconcile::reconcile_nbd_udisks_hide(&ctx.paths.udev_rules_dir(), dry)?;
    if change.action != "noop" && !dry {
        // Reload rules and re-trigger block devices so the new rule takes effect
        // on already-present nbd devices without a reboot. Best-effort: a missing
        // udevadm (rare) shouldn't fail the whole reconcile.
        let _ = ctx.runner.run(
            &["udevadm", "control", "--reload-rules"],
            "reload udev rules",
        );
        let _ = ctx.runner.run(
            &[
                "udevadm",
                "trigger",
                "--subsystem-match=block",
                "--sysname-match=nbd*",
            ],
            "re-trigger nbd devices so udisks re-reads UDISKS_IGNORE",
        );
    }
    Ok(change)
}

impl Context {
    pub fn new(global: GlobalOpts, config: Config) -> Self {
        let runner = Runner::new(global.effective_dry_run(), global.debug);
        Context {
            global,
            config,
            runner,
            paths: Paths::from_env(),
            env: EnvInfo::detect(),
        }
    }
}
