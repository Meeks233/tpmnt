//! `tpmnt remote` — list the SSH remotes this machine controls, and the disks
//! that live on each. This is the one place the remote layer is made explicit;
//! ordinary disk operations resolve the host transparently.

use serde_json::{json, Value};

use crate::cli::RemoteArgs;
use crate::error::{Code, Error, Result};

use super::Context;

pub fn run(ctx: &Context, args: &RemoteArgs) -> Result<Value> {
    if let Some(name) = &args.name {
        if !ctx.config.remotes.iter().any(|r| &r.name == name) {
            return Err(
                Error::new(Code::EConfig, format!("no [[remote]] named {name:?}"))
                    .with_hint("run `tpmnt remote` to list configured remotes"),
            );
        }
    }

    let mut out = Vec::new();
    for r in &ctx.config.remotes {
        if let Some(name) = &args.name {
            if &r.name != name {
                continue;
            }
        }

        // Disks associated with this remote (its remembered, uuid-keyed disks).
        let disks: Vec<Value> = ctx
            .config
            .disks
            .iter()
            .filter(|d| d.remote.as_deref() == Some(r.name.as_str()))
            .map(|d| {
                json!({
                    "name": d.name,
                    "uuid": d.uuid,
                    "mountpoint": d.mountpoint,
                })
            })
            .collect();

        let reachable = if args.probe {
            let prefix = r.ssh_prefix();
            json!(ctx
                .runner
                .probe_on(&prefix, &["true"], "probe remote reachability")
                .map(|o| o.ok())
                .unwrap_or(false))
        } else {
            Value::Null
        };

        out.push(json!({
            "name": r.name,
            "host": r.host,
            "jump": r.jump,
            "reachable": reachable,
            "disks": disks,
        }));
    }

    Ok(json!({ "ok": true, "remotes": out }))
}

/// Human-readable rendering of the remote list.
pub fn render_table(value: &Value) -> String {
    let mut out = String::new();
    let remotes = value.get("remotes").and_then(|v| v.as_array());
    match remotes {
        Some(rs) if !rs.is_empty() => {
            for r in rs {
                let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let host = r.get("host").and_then(|v| v.as_str()).unwrap_or("?");
                let reach = match r.get("reachable").and_then(|v| v.as_bool()) {
                    Some(true) => "  [reachable]",
                    Some(false) => "  [unreachable]",
                    None => "",
                };
                out.push_str(&format!("{name}  →  {host}{reach}\n"));
                let disks = r.get("disks").and_then(|v| v.as_array());
                match disks {
                    Some(ds) if !ds.is_empty() => {
                        for d in ds {
                            out.push_str(&format!(
                                "    · {} ({})  {}\n",
                                d.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                                d.get("uuid").and_then(|v| v.as_str()).unwrap_or("?"),
                                d.get("mountpoint").and_then(|v| v.as_str()).unwrap_or(""),
                            ));
                        }
                    }
                    _ => out.push_str("    (no disks)\n"),
                }
            }
        }
        _ => out.push_str("(no remotes configured)\n"),
    }
    out
}
