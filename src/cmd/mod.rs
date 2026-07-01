//! Subcommand implementations. Each returns a JSON result value on success;
//! `main` renders it as text or JSON and, under `--plan`, emits the recorded
//! command plan instead of applying.

pub mod apply;
pub mod enroll;
pub mod init;
pub mod migrate;
pub mod mount_remote;
pub mod power;
pub mod remote;
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
