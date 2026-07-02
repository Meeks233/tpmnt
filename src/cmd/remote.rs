//! `tpmnt remote` — list the SSH remotes this machine controls, and the disks
//! that live on each, or `remote add` to register a new one. This is the one
//! place the remote layer is made explicit; ordinary disk operations resolve the
//! host transparently.

use serde_json::{json, Value};

use crate::cli::{
    RemoteAction, RemoteAddArgs, RemoteArgs, RemoteListArgs, RemoteRemoveArgs, RemoteRenameArgs,
    RemoteToggleArgs,
};
use crate::config::{Config, Remote};
use crate::error::{Code, Error, Result};

use super::Context;

pub fn run(ctx: &Context, args: &RemoteArgs) -> Result<Value> {
    match &args.action {
        Some(RemoteAction::Add(add)) => add_remote(ctx, add),
        Some(RemoteAction::Remove(rm)) => remove_remote(ctx, rm),
        Some(RemoteAction::Rename(rn)) => rename_remote(ctx, rn),
        Some(RemoteAction::Enable(t)) => toggle_remote(ctx, t, true),
        Some(RemoteAction::Disable(t)) => toggle_remote(ctx, t, false),
        // Bare `tpmnt remote` (no subcommand) and `remote list` both list.
        Some(RemoteAction::List(list)) => list_remotes(ctx, list),
        None => list_remotes(ctx, &RemoteListArgs::default()),
    }
}

/// `tpmnt remote rename <old> <new>` — rename a remote and re-point every disk
/// that lives on it. The remote's name is purely a logical label (crypttab/mounts
/// don't reference it), so this is safe even while its disks are connected — only
/// the config binding and the runtime state file move. Common fix for a remote
/// first registered under an ad-hoc name (e.g. the SSH user) before you wanted its
/// real hostname.
fn rename_remote(ctx: &Context, args: &RemoteRenameArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let (old, new) = (args.old.as_str(), args.new.as_str());

    if !ctx.config.remotes.iter().any(|r| r.name == old) {
        return Err(
            Error::new(Code::EConfig, format!("no [[remote]] named {old:?}"))
                .with_hint("run `tpmnt remote` to list configured remotes"),
        );
    }
    if old == new {
        return Err(Error::new(
            Code::EConfig,
            format!("remote is already named {new:?}"),
        ));
    }
    if ctx.config.remotes.iter().any(|r| r.name == new) {
        return Err(Error::new(
            Code::EConfig,
            format!("a [[remote]] named {new:?} already exists"),
        )
        .with_hint("choose a name not already in use"));
    }

    let mut cfg = ctx.config.clone();
    for r in cfg.remotes.iter_mut() {
        if r.name == old {
            r.name = new.to_string();
        }
    }
    let repointed: Vec<String> = cfg
        .disks
        .iter_mut()
        .filter(|d| d.remote.as_deref() == Some(old))
        .map(|d| {
            d.remote = Some(new.to_string());
            d.name.clone()
        })
        .collect();

    if !dry {
        // Carry the runtime state (last-connected + give-up streak) to the new name.
        let (from, to) = (ctx.paths.remote_state(old), ctx.paths.remote_state(new));
        if from.exists() {
            if let Some(parent) = to.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::rename(&from, &to);
        }
        cfg.save(&ctx.global.config)?;
    }

    Ok(json!({
        "ok": true,
        "action": "remote-rename",
        "dry_run": dry,
        "old": old,
        "new": new,
        "repointed_disks": repointed,
    }))
}

/// `tpmnt remote enable|disable <name>…` — flip a remote's persistent `enabled`
/// flag. A disabled remote is skipped by `up`/discovery (no probing/connecting)
/// and greyed out in the dashboard; enabling also clears its reconnect give-up
/// streak so it starts fresh. Names come from the CLI or an interactive
/// multi-select of the remotes currently in the opposite state.
fn toggle_remote(ctx: &Context, args: &RemoteToggleArgs, enable: bool) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let interactive = crate::tui::interactive(ctx.global.non_interactive);
    let verb = if enable { "enable" } else { "disable" };

    // Interactive list offers remotes currently in the opposite state.
    let targets = if !args.names.is_empty() {
        args.names.clone()
    } else if !interactive {
        return Err(
            Error::new(Code::EConfig, format!("no remote named to {verb}")).with_hint(format!(
                "name the remote(s) to {verb}, or run in an interactive terminal to multi-select"
            )),
        );
    } else {
        let cands: Vec<&Remote> = ctx
            .config
            .remotes
            .iter()
            .filter(|r| r.enabled != enable)
            .collect();
        let items: Vec<crate::tui::Item> = cands
            .iter()
            .map(|r| crate::tui::Item::new(r.name.clone(), r.host.clone()))
            .collect();
        if items.is_empty() {
            return Ok(
                json!({ "ok": true, "action": "remote-toggle", "enable": enable,
                              "dry_run": dry, "changed": [], "note": "nothing to change" }),
            );
        }
        let chosen = crate::tui::multiselect(&format!("Select remote(s) to {verb}:"), &items)?;
        chosen.into_iter().map(|i| cands[i].name.clone()).collect()
    };

    // Validate + apply against a fresh copy of the config.
    let mut cfg = ctx.config.clone();
    let mut changed = Vec::new();
    for name in &targets {
        let r = cfg
            .remotes
            .iter_mut()
            .find(|r| &r.name == name)
            .ok_or_else(|| {
                Error::new(Code::EConfig, format!("no [[remote]] named {name:?}"))
                    .with_hint("run `tpmnt remote` to list configured remotes")
            })?;
        if r.enabled != enable {
            r.enabled = enable;
            changed.push(name.clone());
        }
    }

    if !dry {
        if enable {
            for name in &changed {
                crate::remote_state::reset_remote(&ctx.paths, name);
            }
        }
        cfg.save(&ctx.global.config)?;
    }

    Ok(json!({
        "ok": true,
        "action": "remote-toggle",
        "enable": enable,
        "dry_run": dry,
        "changed": changed,
    }))
}

fn list_remotes(ctx: &Context, args: &RemoteListArgs) -> Result<Value> {
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

/// `tpmnt remote add <host>` — register a new SSH remote in the config.
///
/// If the user doesn't pass `--name`, the remote's own hostname (as reported by
/// `ssh <host> hostname`) becomes the name, so the natural `tpmnt up --remote
/// <hostname>` call works without the user having to invent a label. The probe is
/// read-only, so it runs even under --dry-run (only the config write is skipped).
fn add_remote(ctx: &Context, args: &RemoteAddArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();

    // Build the remote first (with a placeholder name) so we can derive its SSH
    // prefix for the hostname probe using the exact jump/identity the user gave.
    let mut remote = Remote {
        name: String::new(),
        enabled: true,
        host: args.host.clone(),
        jump: args.jump.clone(),
        identity: args.identity.clone(),
    };

    let (name, derived) = match &args.name {
        Some(n) => (n.clone(), false),
        None => (derive_hostname(ctx, &remote)?, true),
    };
    remote.name = name.clone();

    if ctx.config.remotes.iter().any(|r| r.name == name) {
        return Err(Error::new(
            Code::EConfig,
            format!("a [[remote]] named {name:?} already exists"),
        )
        .with_hint("pass --name to choose a different label, or remove the existing entry"));
    }

    let mut cfg = ctx.config.clone();
    cfg.remotes.push(remote);
    if !dry {
        cfg.save(&ctx.global.config)?;
    }

    Ok(json!({
        "ok": true,
        "action": "remote-add",
        "dry_run": dry,
        "name": name,
        "host": args.host,
        "jump": args.jump,
        "name_from_hostname": derived,
    }))
}

/// `tpmnt remote remove <name>…` — drop SSH remote(s) from the config.
///
/// Names are taken from the CLI, or from an interactive multi-select when none
/// are given. A remote that still has disks referencing it is refused (removing
/// it would orphan those disks — they'd silently be treated as local), so the
/// user is told to destroy/move them first. Removal also deletes the remote's
/// runtime state file (its last-connected stamp).
fn remove_remote(ctx: &Context, args: &RemoteRemoveArgs) -> Result<Value> {
    let dry = ctx.global.effective_dry_run();
    let interactive = crate::tui::interactive(ctx.global.non_interactive);

    let targets = resolve_remote_targets(ctx, &args.names, interactive)?;
    if targets.is_empty() {
        return Ok(json!({
            "ok": true, "action": "remote-remove", "dry_run": dry,
            "removed": [], "note": "nothing selected",
        }));
    }

    // Compute the new config (validating existence + orphan guard) before writing.
    let mut cfg = ctx.config.clone();
    let removed = apply_remote_removal(&mut cfg, &targets)?;

    if !dry {
        for name in &removed {
            let _ = std::fs::remove_file(ctx.paths.remote_state(name));
        }
        cfg.save(&ctx.global.config)?;
    }

    Ok(json!({
        "ok": true,
        "action": "remote-remove",
        "dry_run": dry,
        "removed": removed,
    }))
}

/// Resolve remote names to remove: explicit CLI names, or an interactive
/// multi-select. Non-interactive with no names is an error; no remotes
/// configured yields an empty list.
fn resolve_remote_targets(
    ctx: &Context,
    names: &[String],
    interactive: bool,
) -> Result<Vec<String>> {
    if !names.is_empty() {
        return Ok(names.to_vec());
    }
    if !interactive {
        return Err(
            Error::new(Code::EConfig, "no remote named to remove".to_string()).with_hint(
                "name the remote(s) to remove, or run in an interactive terminal to multi-select",
            ),
        );
    }
    let items: Vec<crate::tui::Item> = ctx
        .config
        .remotes
        .iter()
        .map(|r| {
            let n = disks_on(&ctx.config, &r.name).len();
            crate::tui::Item::new(r.name.clone(), format!("{}   ({n} disk(s))", r.host))
        })
        .collect();
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let chosen = crate::tui::multiselect("Select remote(s) to remove:", &items)?;
    Ok(chosen
        .into_iter()
        .map(|i| ctx.config.remotes[i].name.clone())
        .collect())
}

/// Persist `enabled = val` for a single remote in the on-disk config. Shared with
/// `connect`, which auto-disables a remote after repeated reconnect give-ups.
pub(crate) fn set_remote_enabled(ctx: &Context, name: &str, val: bool) -> Result<()> {
    let path = &ctx.global.config;
    let mut cfg = Config::load(path)?;
    let mut changed = false;
    for r in cfg.remotes.iter_mut() {
        if r.name == name && r.enabled != val {
            r.enabled = val;
            changed = true;
        }
    }
    if changed {
        cfg.save(path)?;
    }
    Ok(())
}

/// Names of the disks that reference `remote`.
fn disks_on<'a>(cfg: &'a Config, remote: &str) -> Vec<&'a str> {
    cfg.disks
        .iter()
        .filter(|d| d.remote.as_deref() == Some(remote))
        .map(|d| d.name.as_str())
        .collect()
}

/// Validate and apply removal of `names` from `cfg.remotes` in memory. Errors if
/// a name is unknown or still has disks (nothing is mutated on error). Returns
/// the removed names on success.
fn apply_remote_removal(cfg: &mut Config, names: &[String]) -> Result<Vec<String>> {
    for name in names {
        if !cfg.remotes.iter().any(|r| &r.name == name) {
            return Err(
                Error::new(Code::EConfig, format!("no [[remote]] named {name:?}"))
                    .with_hint("run `tpmnt remote` to list configured remotes"),
            );
        }
        let disks = disks_on(cfg, name);
        if !disks.is_empty() {
            return Err(Error::new(
                Code::EConfig,
                format!(
                    "remote {name:?} still has {} disk(s): {}",
                    disks.len(),
                    disks.join(", ")
                ),
            )
            .with_hint(
                "destroy or move those disks first (removing the remote would orphan them)",
            ));
        }
    }
    cfg.remotes.retain(|r| !names.iter().any(|n| n == &r.name));
    Ok(names.to_vec())
}

/// Ask the remote for its own hostname (`hostname`, trimmed). A blank or failed
/// answer is a hard error — we won't register a nameless remote.
fn derive_hostname(ctx: &Context, remote: &Remote) -> Result<String> {
    let prefix = remote.ssh_prefix();
    let out = ctx
        .runner
        .probe_on(
            &prefix,
            &["hostname"],
            "read remote hostname for --name default",
        )
        .map_err(|e| {
            Error::new(
                Code::ETargetUnreachable,
                format!("could not reach {} to read its hostname: {e}", remote.host),
            )
            .with_hint("check SSH access, or pass --name to set the remote's name explicitly")
        })?;
    let name = out.stdout.trim().to_string();
    if !out.ok() || name.is_empty() {
        return Err(Error::new(
            Code::ETargetUnreachable,
            format!("{} did not report a hostname", remote.host),
        )
        .with_hint("pass --name to set the remote's name explicitly"));
    }
    Ok(name)
}

/// Human-readable rendering of the remote list — or of a `remote add` result.
pub fn render_table(value: &Value) -> String {
    if value.get("action").and_then(|v| v.as_str()) == Some("remote-add") {
        let name = value.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let host = value.get("host").and_then(|v| v.as_str()).unwrap_or("?");
        let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
        let via = if value.get("name_from_hostname").and_then(|v| v.as_bool()) == Some(true) {
            "  (name from remote hostname)"
        } else {
            ""
        };
        let head = if dry {
            "would add remote"
        } else {
            "added remote"
        };
        return format!("{head}: {name}  →  {host}{via}\n");
    }

    if value.get("action").and_then(|v| v.as_str()) == Some("remote-remove") {
        let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
        let removed: Vec<&str> = value
            .get("removed")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if removed.is_empty() {
            let note = value
                .get("note")
                .and_then(|v| v.as_str())
                .unwrap_or("nothing removed");
            return format!("remote remove: ({note})\n");
        }
        let head = if dry {
            "would remove remote(s)"
        } else {
            "removed remote(s)"
        };
        return format!("{head}: {}\n", removed.join(", "));
    }

    if value.get("action").and_then(|v| v.as_str()) == Some("remote-rename") {
        let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
        let old = value.get("old").and_then(|v| v.as_str()).unwrap_or("?");
        let new = value.get("new").and_then(|v| v.as_str()).unwrap_or("?");
        let disks: Vec<&str> = value
            .get("repointed_disks")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let pre = if dry { "would rename " } else { "renamed " };
        let mut s = format!("{pre}remote: {old} → {new}\n");
        if !disks.is_empty() {
            s.push_str(&format!("  re-pointed disk(s): {}\n", disks.join(", ")));
        }
        return s;
    }

    if value.get("action").and_then(|v| v.as_str()) == Some("remote-toggle") {
        let enable = value.get("enable").and_then(|v| v.as_bool()) == Some(true);
        let dry = value.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
        let changed: Vec<&str> = value
            .get("changed")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let verb = if enable { "enabled" } else { "disabled" };
        if changed.is_empty() {
            return format!("remote {verb}: (no change)\n");
        }
        let pre = if dry { "would set " } else { "" };
        return format!("{pre}remote {verb}: {}\n", changed.join(", "));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_add_notes_hostname_derived_name() {
        let v = json!({
            "action": "remote-add",
            "dry_run": false,
            "name": "homelab",
            "host": "alice@10.0.0.5",
            "name_from_hostname": true,
        });
        let out = render_table(&v);
        assert_eq!(
            out,
            "added remote: homelab  →  alice@10.0.0.5  (name from remote hostname)\n"
        );
    }

    #[test]
    fn render_add_dry_run_and_explicit_name() {
        let v = json!({
            "action": "remote-add",
            "dry_run": true,
            "name": "shed",
            "host": "bob@10.0.0.9",
            "name_from_hostname": false,
        });
        let out = render_table(&v);
        assert_eq!(out, "would add remote: shed  →  bob@10.0.0.9\n");
    }

    fn cfg_two_remotes() -> Config {
        toml::from_str(
            r#"
[[remote]]
name = "nas"
host = "u@nas"
[[remote]]
name = "shed"
host = "u@shed"
[[disk]]
name = "coldstore"
uuid = "u1"
mountpoint = "/mnt/coldstore"
remote = "nas"
transport = "nbd"
"#,
        )
        .unwrap()
    }

    #[test]
    fn apply_remote_removal_drops_an_unused_remote() {
        let mut cfg = cfg_two_remotes();
        let removed = apply_remote_removal(&mut cfg, &["shed".into()]).unwrap();
        assert_eq!(removed, vec!["shed".to_string()]);
        assert!(cfg.remotes.iter().all(|r| r.name != "shed"));
        assert!(cfg.remotes.iter().any(|r| r.name == "nas"));
    }

    #[test]
    fn apply_remote_removal_refuses_remote_with_disks() {
        let mut cfg = cfg_two_remotes();
        let err = apply_remote_removal(&mut cfg, &["nas".into()]).unwrap_err();
        assert_eq!(err.to_string(), err.to_string()); // has a message
                                                      // Nothing mutated on error.
        assert!(cfg.remotes.iter().any(|r| r.name == "nas"));
        assert!(err.to_string().contains("coldstore"));
    }

    #[test]
    fn apply_remote_removal_rejects_unknown_remote() {
        let mut cfg = cfg_two_remotes();
        let err = apply_remote_removal(&mut cfg, &["ghost".into()]).unwrap_err();
        assert!(err.to_string().contains("ghost"));
        // A partial batch where a later name is unknown mutates nothing.
        let err2 = apply_remote_removal(&mut cfg, &["shed".into(), "ghost".into()]).unwrap_err();
        assert!(err2.to_string().contains("ghost"));
        assert!(cfg.remotes.iter().any(|r| r.name == "shed"), "atomic");
    }

    #[test]
    fn disks_on_lists_referencing_disks() {
        let cfg = cfg_two_remotes();
        assert_eq!(disks_on(&cfg, "nas"), vec!["coldstore"]);
        assert!(disks_on(&cfg, "shed").is_empty());
    }

    /// The pure part of a rename: the remote is relabeled and every disk on it is
    /// re-pointed. (The command wrapper adds validation + the state-file move.)
    #[test]
    fn rename_relabels_remote_and_repoints_disks() {
        let mut cfg = cfg_two_remotes();
        for r in cfg.remotes.iter_mut() {
            if r.name == "nas" {
                r.name = "windows11".into();
            }
        }
        let repointed: Vec<String> = cfg
            .disks
            .iter_mut()
            .filter(|d| d.remote.as_deref() == Some("nas"))
            .map(|d| {
                d.remote = Some("windows11".into());
                d.name.clone()
            })
            .collect();
        assert_eq!(repointed, vec!["coldstore".to_string()]);
        assert!(cfg.remotes.iter().any(|r| r.name == "windows11"));
        assert!(cfg.remotes.iter().all(|r| r.name != "nas"));
        assert_eq!(cfg.disks[0].remote.as_deref(), Some("windows11"));
    }

    #[test]
    fn render_rename_lists_repointed_disks() {
        let v = json!({
            "action": "remote-rename", "dry_run": false,
            "old": "alice", "new": "windows11", "repointed_disks": ["coldstore"],
        });
        let out = render_table(&v);
        assert!(out.contains("renamed remote: alice → windows11"));
        assert!(out.contains("re-pointed disk(s): coldstore"));
    }
}
