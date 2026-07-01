//! tpmnt — unified, declarative, AI-native LUKS2 + TPM2 manager (MVP).

mod blockdev;
mod cli;
mod cmd;
mod config;
mod discover;
mod env;
mod error;
mod exec;
mod keystore;
mod luks;
mod manage;
mod paths;
mod pin;
mod power;
mod reconcile;
mod secret;
mod vault;

use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use serde_json::{json, Value};

use cli::{Cli, Command};
use cmd::Context;
use config::Config;
use error::{Error, Result};

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Subcommands that don't need a Context.
    if let Command::GenMan(args) = &cli.command {
        return match gen_man(&args.out_dir) {
            Ok(p) => {
                println!("wrote {p}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&cli, e),
        };
    }

    let config = match Config::load(&cli.global.config) {
        Ok(c) => c,
        Err(e) => return fail(&cli, e),
    };

    if matches!(cli.command, Command::PrintConfig) {
        print!("{}", config.to_toml());
        return ExitCode::SUCCESS;
    }

    let json_mode = cli.global.json;
    let plan_mode = cli.global.plan;
    let ctx = Context::new(cli.global.clone(), config);

    let result: Result<Value> = match &cli.command {
        Command::Init(a) => cmd::init::run(&ctx, a),
        Command::Adopt(a) => cmd::adopt::run(&ctx, a),
        Command::Rename(a) => cmd::rename::run(&ctx, a),
        Command::Recover(a) => cmd::recover::run(&ctx, a),
        Command::Offline(a) => cmd::offline::run(&ctx, a),
        Command::Destroy(a) => cmd::destroy::run(&ctx, a),
        Command::Enroll(a) => cmd::enroll::run(&ctx, a),
        Command::Apply => cmd::apply::run(&ctx),
        Command::Connect(a) => cmd::connect::run(&ctx, a),
        Command::Discover(a) => cmd::discover::run(&ctx, a),
        Command::Status | Command::Dashboard => cmd::status::run(&ctx),
        Command::Migrate(a) => cmd::migrate::run(&ctx, a),
        Command::Rollback(a) => cmd::rollback::run(&ctx, a),
        Command::Remote(a) => cmd::remote::run(&ctx, a),
        Command::MountRemote(a) => cmd::mount_remote::run(&ctx, a),
        Command::UmountRemote(a) => cmd::mount_remote::umount(&ctx, a),
        Command::Pin(a) => cmd::pin::run(&ctx, a),
        Command::Vault(a) => cmd::vault::run(&ctx, a),
        Command::Power(a) => cmd::power::run(&ctx, a),
        Command::Schedule(a) => cmd::power::schedule(&ctx, a),
        Command::Monitor(a) => cmd::power::monitor(&ctx, a),
        Command::PrintConfig | Command::GenMan(_) => unreachable!("handled above"),
    };

    match result {
        Ok(value) => {
            if plan_mode {
                let plan = json!({
                    "ok": true,
                    "plan": {
                        "commands": *ctx.runner.trace.borrow(),
                        "result": value,
                    }
                });
                println!("{}", serde_json::to_string_pretty(&plan).unwrap());
            } else if json_mode {
                println!("{}", serde_json::to_string_pretty(&value).unwrap());
            } else {
                render_human(&cli.command, &value);
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&cli, e),
    }
}

/// Human-friendly rendering per command (JSON is the machine contract).
fn render_human(command: &Command, value: &Value) {
    match command {
        Command::Status => print!("{}", cmd::status::render_table(value)),
        Command::Dashboard => print!("{}", cmd::status::render_dashboard(value)),
        Command::Remote(_) => print!("{}", cmd::remote::render_table(value)),
        Command::Adopt(_) => print!("{}", cmd::adopt::render(value)),
        Command::Rename(_) => print!("{}", cmd::rename::render(value)),
        Command::Recover(_) => print!("{}", cmd::recover::render(value)),
        Command::Connect(_) => print!("{}", cmd::connect::render(value)),
        Command::Discover(_) => print!("{}", cmd::discover::render(value)),
        Command::Pin(_) => print!("{}", cmd::pin::render(value)),
        Command::Vault(_) => print!("{}", cmd::vault::render(value)),
        _ => {
            let action = value.get("action").and_then(|v| v.as_str());
            if let Some(a) = action {
                println!("ok: {a}");
            } else {
                println!("ok");
            }
            if let Some(disks) = value.get("disks").and_then(|v| v.as_array()) {
                for d in disks {
                    if let Some(n) = d.get("name").and_then(|v| v.as_str()) {
                        println!("  - {n}");
                    }
                }
            }
            if let Some(warnings) = value.get("warnings").and_then(|v| v.as_array()) {
                for w in warnings.iter().filter_map(|v| v.as_str()) {
                    println!("  warning: {w}");
                }
            }
            if let Some(w) = value.get("warning").and_then(|v| v.as_str()) {
                println!("  warning: {w}");
            }
        }
    }
}

/// Emit a structured error and map to the documented exit code.
fn fail(cli: &Cli, e: Error) -> ExitCode {
    if cli.global.json || cli.global.plan {
        println!("{}", serde_json::to_string_pretty(&e.to_json()).unwrap());
    } else {
        eprintln!("error: {e}");
    }
    ExitCode::from(e.code.exit_code() as u8)
}

fn gen_man(out_dir: &std::path::Path) -> Result<String> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| Error::new(error::Code::EInternal, format!("mkdir: {e}")))?;
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buf = Vec::new();
    man.render(&mut buf)
        .map_err(|e| Error::new(error::Code::EInternal, format!("render man: {e}")))?;
    let path = out_dir.join("tpmnt.1");
    std::fs::write(&path, buf)
        .map_err(|e| Error::new(error::Code::EInternal, format!("write man: {e}")))?;
    Ok(path.display().to_string())
}
