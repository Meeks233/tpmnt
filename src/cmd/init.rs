//! `tpmnt init <device>` — greenfield, fully-managed initialization of a
//! (possibly blank) disk: preflight guard, partition, LUKS2 format, key
//! material (auto passphrase + recovery key), key escrow with a safety gate,
//! TPM2 enroll (reused), filesystem, then register + mount. Safe-by-default,
//! fully scriptable, AI-native (every decision has a flag + default + bypass).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::cli::InitArgs;
use crate::config::{Config, Disk};
use crate::error::{err, Code, Error, Result};
use crate::keystore::{self, SecureDir};
use crate::reconcile;
use crate::secret;

use super::Context;

/// A TOML end-state for `--from-config`. Every field optional; CLI flags win.
#[derive(Debug, Default, Deserialize)]
struct InitSpec {
    device: Option<String>,
    name: Option<String>,
    mountpoint: Option<PathBuf>,
    wipe: Option<bool>,
    no_partition: Option<bool>,
    partition: Option<String>,
    cipher: Option<String>,
    kdf: Option<String>,
    sector_size: Option<u32>,
    label: Option<String>,
    key_format: Option<String>,
    no_recovery_key: Option<bool>,
    escrow: Option<Vec<String>>,
    no_backup: Option<bool>,
    no_tpm: Option<bool>,
    pcrs: Option<String>,
    with_pin: Option<bool>,
    fstype: Option<String>,
    no_format: Option<bool>,
    no_register: Option<bool>,
    power_profile: Option<String>,
    #[serde(alias = "idle_timeout")]
    standby_timeout: Option<String>,
    power_off_method: Option<String>,
    remote: Option<String>,
}

/// The fully-resolved init request (CLI flags merged over `--from-config`).
struct Resolved {
    device: String,
    /// When set, `device` names a block device on this [[remote]]. Its ciphertext
    /// is forwarded here and all crypto runs locally (remote stays untrusted).
    remote: Option<String>,
    name: String,
    mountpoint: PathBuf,
    wipe: bool,
    no_partition: bool,
    partition: Option<String>,
    cipher: String,
    kdf: String,
    sector_size: Option<u32>,
    label: Option<String>,
    manual_passphrase: Option<String>,
    key_format: String,
    no_recovery_key: bool,
    i_understand_no_recovery: bool,
    escrow: Vec<String>,
    local_plaintext: bool,
    no_backup: bool,
    emit_secrets: bool,
    no_tpm: bool,
    pcrs: Vec<u32>,
    with_pin: bool,
    fstype: String,
    no_format: bool,
    no_register: bool,
    power_profile: crate::config::PowerProfile,
    standby_timeout: Option<String>,
    power_off_method: crate::config::PowerOffMethod,
}

pub fn run(ctx: &Context, args: &InitArgs) -> Result<Value> {
    if args.explain {
        return Ok(explain());
    }
    let r = resolve(args)?;
    if r.local_plaintext && !args.i_understand_plaintext_keys {
        return err(
            Code::EBackupRefused,
            "--local-plaintext requires --i-understand-plaintext-keys",
        );
    }
    let dry = ctx.global.effective_dry_run();

    // 0. REMOTE FORWARDING ---------------------------------------------------
    // A remote disk is untrusted: never ask the far side to decrypt. Forward its
    // raw LUKS ciphertext here over NBD-over-SSH and run every cryptsetup step
    // locally. `op_device` is what we actually operate on (a local /dev/nbdN);
    // `r.device` stays the remote path we record in the config.
    let mut attachment: Option<crate::blockdev::Attachment> = None;
    let op_device = match &r.remote {
        Some(rname) => {
            let remote = ctx
                .config
                .remotes
                .iter()
                .find(|rm| &rm.name == rname)
                .ok_or_else(|| {
                    Error::new(Code::EConfig, format!("unknown --remote '{rname}'"))
                        .with_hint("add a matching [[remote]] entry to the config")
                })?;
            let att = crate::blockdev::attach_nbd_over_ssh(
                &ctx.runner,
                remote,
                &r.device,
                crate::blockdev::REMOTE_NBD_PORT + 1000,
            )?;
            let dev = att.local_device.clone();
            attachment = Some(att);
            dev
        }
        None => r.device.clone(),
    };

    // 1. PREFLIGHT / GUARD ---------------------------------------------------
    let preflight = preflight(ctx, &op_device)?;
    let has_data = preflight
        .get("has_data")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if has_data && !r.no_partition && r.partition.is_none() {
        if !r.wipe {
            return Err(Error::new(
                Code::EDeviceHasData,
                format!("{} already has partitions/data", r.device),
            )
            .with_hint(
                "pass --wipe --yes to destroy it, or --partition <devpart>/--no-partition",
            ));
        }
        if !ctx.global.yes {
            return Err(Error::new(
                Code::EDeviceHasData,
                format!("refusing to --wipe {} without confirmation", r.device),
            )
            .with_hint("add --yes to confirm destruction"));
        }
    }

    // The block target we LUKS-format: a fresh partition, an explicit one, or
    // the whole device.
    let target = resolve_target(ctx, &r, &op_device, dry)?;

    // PIN (optional, or MANDATORY under [defaults].require_pin). The same PIN
    // gates TPM2 unlock (NEWPIN below) and encrypts the unified recovery vault,
    // so a single remembered value covers both. Resolved from $TPMNT_PIN or a
    // prompt; when set from a prompt we export it so the shared enroll path
    // (which reads $TPMNT_PIN as NEWPIN) picks up the very same value.
    let want_pin = r.with_pin || ctx.config.defaults.require_pin;
    let pin: Option<String> = if want_pin {
        let p = crate::pin::resolve(None, ctx.global.non_interactive)?;
        std::env::set_var("TPMNT_PIN", &p);
        Some(p)
    } else {
        None
    };
    let effective_with_pin = want_pin;

    // 3. LUKS2 FORMAT + 4. KEY MATERIAL -------------------------------------
    let secure = if dry { None } else { Some(SecureDir::new()?) };
    let auto_mode = r.manual_passphrase.is_none();
    let passphrase = match &r.manual_passphrase {
        Some(p) => p.clone(),
        None => secret::generate_passphrase(&r.key_format)?,
    };

    let mut primary_kf = PathBuf::new();
    if let Some(sd) = &secure {
        primary_kf = sd.write_key("primary", &passphrase)?;
    }

    luks_format(ctx, &r, &target, &primary_kf)?;

    // Recovery key keyslot (default on).
    let mut recovery_key: Option<String> = None;
    if !r.no_recovery_key {
        let rk = secret::generate_recovery_key()?;
        if let Some(sd) = &secure {
            let rk_kf = sd.write_key("recovery", &rk)?;
            ctx.runner
                .run(
                    &[
                        "cryptsetup",
                        "luksAddKey",
                        &target,
                        &rk_kf.to_string_lossy(),
                        "--key-file",
                        &primary_kf.to_string_lossy(),
                        "--batch-mode",
                    ],
                    "add recovery-key keyslot",
                )?
                .require("luksAddKey (recovery)")?;
        }
        recovery_key = Some(rk);
    } else if !r.i_understand_no_recovery {
        return err(
            Code::EBackupRefused,
            "--no-recovery-key requires --i-understand-no-recovery",
        );
    }

    // Open the mapper so we can mkfs/mount. (Skipped under dry-run.)
    let mapper = format!("tpmnt-{}", r.name);
    if !dry {
        ctx.runner
            .run(
                &[
                    "cryptsetup",
                    "open",
                    &target,
                    &mapper,
                    "--key-file",
                    &primary_kf.to_string_lossy(),
                ],
                "open the new LUKS2 mapping",
            )?
            .require("cryptsetup open")?;
    }

    let luks_uuid = if dry {
        "<dry-run>".to_string()
    } else {
        ctx.runner
            .probe(&["cryptsetup", "luksUUID", &target], "read LUKS UUID")?
            .stdout
            .trim()
            .to_string()
    };

    // 6. AUTO-DECRYPT (TPM2) -------------------------------------------------
    // Skipped under dry-run: the partition does not exist yet, so the enroll
    // probe cannot run. The result simply notes the intended TPM enrollment.
    let mut tpm_token = false;
    let mut tpm_warnings: Vec<Value> = Vec::new();
    if !r.no_tpm && !dry {
        let pass = passphrase.clone();
        let enroll =
            super::enroll::enroll_device(ctx, &target, &r.pcrs, effective_with_pin, false, || {
                Ok(pass)
            })?;
        tpm_token = enroll
            .get("tpm2_token_present")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if let Some(w) = enroll.get("warnings").cloned() {
            tpm_warnings.push(w);
        }
    } else if !r.no_tpm {
        tpm_token = true; // planned
    }

    // 5. KEY ESCROW / BACKUP (safety-gated) ---------------------------------
    let bundle = build_bundle(&BundleInput {
        name: &r.name,
        device: &r.device,
        target: &target,
        luks_uuid: &luks_uuid,
        mapper: &mapper,
        mountpoint: &r.mountpoint,
        passphrase: if auto_mode { Some(&passphrase) } else { None },
        recovery_key: recovery_key.as_deref(),
    });
    let bundle_json = serde_json::to_string_pretty(&bundle).unwrap();

    let mut escrow_result = match run_escrow(ctx, &r, &bundle_json, dry) {
        Ok(res) => res,
        Err(e) => {
            // Don't leave an unbacked-up volume open after an escrow failure.
            cleanup_mapper(ctx, &mapper);
            detach_forward(ctx, &attachment);
            return Err(e);
        }
    };

    // PIN VAULT — the unified, TPM-independent recovery store. When a PIN is in
    // play, drop this disk's bundle into the single vault too, so a broken TPM is
    // always recoverable with just the PIN. Counts as a captured backup below.
    if let Some(pin) = &pin {
        match crate::vault::upsert(
            &ctx.runner,
            &ctx.config.defaults.key_backup,
            pin,
            &r.name,
            &bundle,
            dry,
        ) {
            Ok(path) => escrow_result
                .written
                .push(json!({ "type": "vault", "path": path })),
            Err(e) => {
                cleanup_mapper(ctx, &mapper);
                detach_forward(ctx, &attachment);
                return Err(e);
            }
        }
    }

    // SAFETY GATE: in auto mode, refuse to finish with no captured backup.
    if auto_mode && !dry {
        let captured = !escrow_result.written.is_empty() || (r.emit_secrets && ctx.global.json);
        if !captured && !r.no_backup {
            cleanup_mapper(ctx, &mapper);
            detach_forward(ctx, &attachment);
            return Err(Error::new(
                Code::EBackupRefused,
                "auto mode produced a key with no backup target written",
            )
            .with_hint(
                "configure key_backup, pass --escrow age:<pubkey>, --emit-secrets with --json, \
                 or acknowledge with --i-understand-no-backup",
            ));
        }
    }

    // 7. FILESYSTEM ----------------------------------------------------------
    let mut fs_uuid: Option<String> = None;
    if !r.no_format {
        mkfs(ctx, &r.fstype, &mapper)?;
        if !dry {
            let out = ctx.runner.probe(
                &[
                    "blkid",
                    "-s",
                    "UUID",
                    "-o",
                    "value",
                    &format!("/dev/mapper/{mapper}"),
                ],
                "read filesystem UUID",
            )?;
            let u = out.stdout.trim().to_string();
            if !u.is_empty() {
                fs_uuid = Some(u);
            }
        }
    }

    // 8. REGISTER + MOUNT ----------------------------------------------------
    let mut registered = false;
    if !r.no_register {
        // For a remote disk, record the remote path + forwarding transport (not
        // the ephemeral local /dev/nbdN). This makes it a MANAGED remote:
        // ciphertext lives there, keys + decryption stay here.
        let (rec_device, rec_transport) = match &r.remote {
            Some(_) => (r.device.clone(), Some(crate::config::Transport::Nbd)),
            None => (target.clone(), None),
        };
        let disk = Disk {
            name: r.name.clone(),
            uuid: luks_uuid.clone(),
            device: Some(rec_device),
            mapper: None,
            mountpoint: r.mountpoint.clone(),
            fstype: r.fstype.clone(),
            pcrs: r.pcrs.clone(),
            with_pin: effective_with_pin,
            power_profile: r.power_profile,
            standby_timeout: r.standby_timeout.clone(),
            power_off_method: r.power_off_method,
            teardown: crate::config::Teardown::Direct,
            schedule: None,
            remote: r.remote.clone(),
            transport: rec_transport,
        };
        if !dry {
            register_disk(ctx, &disk)?;
            std::fs::create_dir_all(&r.mountpoint).ok();
        }
        reconcile::reconcile_disk(
            &ctx.paths.crypttab(),
            &ctx.paths.fstab(),
            &ctx.paths.systemd_unit_dir(),
            &disk,
            ctx.config.defaults.mount_backend,
            dry,
        )?;
        // For a transport-backed disk, hide the raw /dev/nbdN ciphertext device
        // from udisks so the file manager shows only the named decrypted mount.
        if disk.transport.is_some() {
            super::ensure_nbd_hidden(ctx, dry)?;
        }
        // Mount now (the mapper is already open), with the SAME options reconcile
        // wrote to fstab — so the live mount matches steady state (noatime for
        // cold-standby, compress=zstd for btrfs) instead of bare defaults.
        if !r.no_format {
            let opts = reconcile::mount_options(&disk);
            ctx.runner
                .run(
                    &[
                        "mount",
                        "-o",
                        &opts,
                        &format!("/dev/mapper/{mapper}"),
                        &r.mountpoint.to_string_lossy(),
                    ],
                    "mount the freshly initialized filesystem",
                )?
                .require("mount")?;
        }
        registered = true;
    }

    // RESULT -----------------------------------------------------------------
    let mut result = json!({
        "ok": true,
        "dry_run": dry,
        "device": r.device,
        "partition": target,
        "luks_uuid": luks_uuid,
        "fs_uuid": fs_uuid,
        "mapper_name": mapper,
        "tpm_token": tpm_token,
        "recovery_key_fingerprint": escrow_result.recovery_fpr,
        "escrow_targets_written": escrow_result.written,
        "mountpoint": r.mountpoint,
        "registered": registered,
        "preflight": preflight,
        "warnings": tpm_warnings,
        "next_steps": next_steps(&r, &escrow_result),
    });
    if r.emit_secrets {
        result["secrets"] = json!({
            "passphrase": if auto_mode { Some(passphrase) } else { None },
            "recovery_key": recovery_key,
            "bundle": bundle,
        });
    }
    Ok(result)
}

// --- resolution ------------------------------------------------------------

fn resolve(args: &InitArgs) -> Result<Resolved> {
    let spec: InitSpec = match &args.from_config {
        Some(p) => {
            let s = std::fs::read_to_string(p)
                .map_err(|e| Error::new(Code::EConfig, format!("read {}: {e}", p.display())))?;
            toml::from_str(&s)
                .map_err(|e| Error::new(Code::EConfig, format!("invalid --from-config: {e}")))?
        }
        None => InitSpec::default(),
    };

    let device = args.device.clone().or(spec.device).ok_or_else(|| {
        Error::new(
            Code::ENoDevice,
            "no device given (positional or in --from-config)",
        )
    })?;

    let name = args
        .name
        .clone()
        .or(spec.name)
        .unwrap_or_else(|| basename(&device));

    let mountpoint = args
        .mountpoint
        .clone()
        .or(spec.mountpoint)
        .unwrap_or_else(|| PathBuf::from(format!("/mnt/{name}")));

    let manual_passphrase = if args.passphrase_stdin {
        Some(read_stdin_line()?)
    } else if let Some(f) = &args.passphrase_file {
        Some(
            std::fs::read_to_string(f)
                .map_err(|e| Error::new(Code::ENoPassphrase, format!("read {}: {e}", f.display())))?
                .trim_end_matches('\n')
                .to_string(),
        )
    } else {
        None
    };

    let pcrs = super::enroll::parse_pcrs(args.pcrs.as_deref().or(spec.pcrs.as_deref()))?;

    Ok(Resolved {
        device,
        remote: args.remote.clone().or(spec.remote),
        name,
        mountpoint,
        wipe: args.wipe || spec.wipe.unwrap_or(false),
        no_partition: args.no_partition || spec.no_partition.unwrap_or(false),
        partition: args.partition.clone().or(spec.partition),
        cipher: args
            .cipher
            .clone()
            .or(spec.cipher)
            .unwrap_or_else(|| "aes-xts-plain64".into()),
        kdf: args
            .kdf
            .clone()
            .or(spec.kdf)
            .unwrap_or_else(|| "argon2id".into()),
        sector_size: args.sector_size.or(spec.sector_size),
        label: args.label.clone().or(spec.label),
        manual_passphrase,
        key_format: args.key_format.clone().pipe_if_default(spec.key_format),
        no_recovery_key: args.no_recovery_key || spec.no_recovery_key.unwrap_or(false),
        i_understand_no_recovery: args.i_understand_no_recovery,
        escrow: if !args.escrow.is_empty() {
            args.escrow.clone()
        } else {
            spec.escrow.unwrap_or_default()
        },
        local_plaintext: args.local_plaintext,
        no_backup: args.i_understand_no_backup || spec.no_backup.unwrap_or(false),
        emit_secrets: args.emit_secrets,
        no_tpm: args.no_tpm || spec.no_tpm.unwrap_or(false),
        pcrs,
        with_pin: args.with_pin || spec.with_pin.unwrap_or(false),
        fstype: args
            .fstype
            .clone()
            .or(spec.fstype)
            .unwrap_or_else(|| "btrfs".into()),
        no_format: args.no_format || spec.no_format.unwrap_or(false),
        no_register: args.no_register || spec.no_register.unwrap_or(false),
        power_profile: {
            let raw = args.power_profile.clone().or(spec.power_profile);
            match raw {
                Some(s) => crate::config::PowerProfile::parse(&s).ok_or_else(|| {
                    Error::new(Code::EConfig, format!("invalid --power-profile '{s}'"))
                        .with_hint("use 'always-on' or 'cold-standby'")
                })?,
                None => crate::config::PowerProfile::default(),
            }
        },
        standby_timeout: args.standby_timeout.clone().or(spec.standby_timeout),
        power_off_method: {
            let raw = args.power_off_method.clone().or(spec.power_off_method);
            match raw {
                Some(s) => crate::config::PowerOffMethod::parse(&s).ok_or_else(|| {
                    Error::new(Code::EConfig, format!("invalid --power-off-method '{s}'"))
                        .with_hint("use 'auto', 'standby', 'sleep', or 'power-off'")
                })?,
                None => crate::config::PowerOffMethod::default(),
            }
        },
    })
}

/// Helper to let `--from-config` override the clap default of `key_format`.
trait PipeIfDefault {
    fn pipe_if_default(self, spec: Option<String>) -> String;
}
impl PipeIfDefault for String {
    fn pipe_if_default(self, spec: Option<String>) -> String {
        if self == "diceware" {
            spec.unwrap_or(self)
        } else {
            self
        }
    }
}

fn basename(device: &str) -> String {
    device.rsplit('/').next().unwrap_or(device).to_string()
}

fn read_stdin_line() -> Result<String> {
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Error::new(Code::ENoPassphrase, format!("stdin: {e}")))?;
    Ok(line.trim_end_matches('\n').to_string())
}

// --- preflight -------------------------------------------------------------

fn preflight(ctx: &Context, device: &str) -> Result<Value> {
    if !Path::new(device).exists() {
        return Err(
            Error::new(Code::ENoDevice, format!("device does not exist: {device}"))
                .with_hint("check the path or by-id symlink"),
        );
    }
    // lsblk JSON: device + any children indicate existing partitions.
    let lsblk = ctx.runner.probe(
        &[
            "lsblk",
            "-J",
            "-b",
            "-o",
            "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,RM",
            device,
        ],
        "inspect device topology",
    )?;
    let parsed: Value = serde_json::from_str(&lsblk.stdout).unwrap_or(json!({}));
    let dev0 = parsed
        .get("blockdevices")
        .and_then(|b| b.as_array())
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or(json!({}));

    let children = dev0
        .get("children")
        .and_then(|c| c.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let top_fstype = dev0.get("fstype").and_then(|v| v.as_str()).unwrap_or("");
    let is_luks = ctx
        .runner
        .probe(&["cryptsetup", "isLuks", device], "probe for LUKS header")?
        .ok();
    let mounted = is_any_mounted(device);

    let has_data = children > 0 || !top_fstype.is_empty() || is_luks || mounted;

    Ok(json!({
        "device": device,
        "size_bytes": dev0.get("size"),
        "model": dev0.get("model"),
        "removable": dev0.get("rm"),
        "partitions": children,
        "top_fstype": top_fstype,
        "is_luks": is_luks,
        "mounted": mounted,
        "has_data": has_data,
    }))
}

fn is_any_mounted(device: &str) -> bool {
    let base = device.trim_start_matches("/dev/");
    std::fs::read_to_string("/proc/mounts")
        .map(|s| {
            s.lines().any(|l| {
                l.split_whitespace()
                    .next()
                    .map(|src| src.trim_start_matches("/dev/").starts_with(base))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

// --- partition + format ----------------------------------------------------

/// Resolve (and create, unless dry-run) the block target to LUKS-format.
/// `device` is the local block device to operate on (a forwarded /dev/nbdN for a
/// remote disk, else the disk itself).
fn resolve_target(ctx: &Context, r: &Resolved, device: &str, dry: bool) -> Result<String> {
    if let Some(p) = &r.partition {
        return Ok(p.clone());
    }
    if r.no_partition {
        // Whole-device LUKS: clear any stale signature/partition table first so
        // the old (e.g. VeraCrypt) header can't be mistaken for live data.
        if r.wipe {
            ctx.runner
                .run(&["wipefs", "-a", device], "wipe existing signatures")?
                .require("wipefs")?;
        }
        return Ok(device.to_string());
    }
    // DEFAULT: fresh GPT with one Linux-LUKS partition spanning the disk.
    if r.wipe {
        ctx.runner
            .run(&["wipefs", "-a", device], "wipe existing signatures")?
            .require("wipefs")?;
        ctx.runner
            .run(&["sgdisk", "--zap-all", device], "zap existing GPT/MBR")?
            .require("sgdisk --zap-all")?;
    }
    ctx.runner
        .run(
            &["sgdisk", "-n", "1:0:0", "-t", "1:8309", device],
            "create one Linux-LUKS partition spanning the disk",
        )?
        .require("sgdisk -n")?;
    ctx.runner
        .run(&["partprobe", device], "reload the partition table")?;
    if dry {
        return Ok(partition_path(device));
    }
    // Find the new partition via lsblk (robust across sd*/nvme*/loop*).
    let out = ctx.runner.probe(
        &["lsblk", "-nro", "NAME,TYPE", device],
        "locate new partition",
    )?;
    for line in out.stdout.lines() {
        let mut it = line.split_whitespace();
        let name = it.next().unwrap_or("");
        let ty = it.next().unwrap_or("");
        if ty == "part" {
            return Ok(format!("/dev/{name}"));
        }
    }
    Ok(partition_path(device))
}

/// Heuristic partition path: append "p1" when the device name ends in a digit
/// (nvme/loop/mmcblk), else "1" (sd*/vd*/hd*).
fn partition_path(device: &str) -> String {
    let ends_digit = device
        .chars()
        .last()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false);
    if ends_digit {
        format!("{device}p1")
    } else {
        format!("{device}1")
    }
}

fn luks_format(ctx: &Context, r: &Resolved, target: &str, primary_kf: &Path) -> Result<()> {
    let kf = primary_kf.to_string_lossy().into_owned();
    let mut argv: Vec<String> = vec![
        "cryptsetup".into(),
        "luksFormat".into(),
        "--type".into(),
        "luks2".into(),
        "--cipher".into(),
        r.cipher.clone(),
        "--pbkdf".into(),
        r.kdf.clone(),
        "--batch-mode".into(),
    ];
    // Only force a sector size when explicitly requested; otherwise let
    // cryptsetup auto-select (4096 on 4Kn drives) and align correctly. Forcing
    // 4096 on a partition whose size isn't 4096-aligned fails luksFormat.
    if let Some(ss) = r.sector_size {
        argv.push("--sector-size".into());
        argv.push(ss.to_string());
    }
    if r.cipher.contains("xts") {
        argv.push("--key-size".into());
        argv.push("512".into());
    }
    if let Some(l) = &r.label {
        argv.push("--label".into());
        argv.push(l.clone());
    }
    argv.push(target.to_string());
    // In dry-run the keyfile doesn't exist; pass the placeholder path anyway —
    // the step is recorded but skipped.
    argv.push("--key-file".into());
    argv.push(if kf.is_empty() {
        "<securedir>/primary".into()
    } else {
        kf
    });

    let argv_ref: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    ctx.runner
        .run(&argv_ref, "luksFormat the new LUKS2 container")?
        .require("luksFormat")?;
    Ok(())
}

fn mkfs(ctx: &Context, fstype: &str, mapper: &str) -> Result<()> {
    let dev = format!("/dev/mapper/{mapper}");
    let argv: Vec<&str> = match fstype {
        "xfs" => vec!["mkfs.xfs", "-q", &dev],
        "ext4" => vec!["mkfs.ext4", "-q", "-F", &dev],
        // `-m dup` keeps two copies of metadata on a single disk so btrfs can
        // self-heal metadata bit rot (the default on btrfs-progs >= 5.15; forced
        // here for older tools). Data checksums still only *detect* data rot on a
        // lone disk — that's the point for cold archival.
        "btrfs" => vec!["mkfs.btrfs", "-q", "-f", "-m", "dup", &dev],
        other => {
            return Err(
                Error::new(Code::EConfig, format!("unsupported fstype: {other}"))
                    .with_hint("use xfs, ext4, btrfs, or --no-format"),
            )
        }
    };
    ctx.runner
        .run(&argv, "create the filesystem")?
        .require("mkfs")?;
    Ok(())
}

fn cleanup_mapper(ctx: &Context, mapper: &str) {
    let _ = ctx.runner.run(
        &["cryptsetup", "close", mapper],
        "close mapping after failure",
    );
}

/// Tear down a remote ciphertext forward on the failure path (no-op if local).
fn detach_forward(ctx: &Context, attachment: &Option<crate::blockdev::Attachment>) {
    if let Some(att) = attachment {
        let _ = crate::blockdev::detach(&ctx.runner, att);
    }
}

// --- escrow ----------------------------------------------------------------

struct BundleInput<'a> {
    name: &'a str,
    device: &'a str,
    target: &'a str,
    luks_uuid: &'a str,
    mapper: &'a str,
    mountpoint: &'a Path,
    passphrase: Option<&'a str>,
    recovery_key: Option<&'a str>,
}

fn build_bundle(i: &BundleInput) -> Value {
    json!({
        "tpmnt_key_bundle": 1,
        "name": i.name,
        "device": i.device,
        "partition": i.target,
        "luks_uuid": i.luks_uuid,
        "mapper_name": i.mapper,
        "mountpoint": i.mountpoint,
        "passphrase": i.passphrase,
        "recovery_key": i.recovery_key,
    })
}

struct EscrowResult {
    written: Vec<Value>,
    recovery_fpr: Option<String>,
}

/// Write the plaintext bundle to key_backup (unless --i-understand-no-backup)
/// and encrypt to each --escrow target. An EXPLICIT escrow target that fails is
/// fatal (E_ESCROW_FAILED) and the caller cleans up.
fn run_escrow(ctx: &Context, r: &Resolved, bundle_json: &str, dry: bool) -> Result<EscrowResult> {
    let mut written = Vec::new();
    let dir = &ctx.config.defaults.key_backup;

    // Local bundle (default target). Sealed to the host's TPM via systemd-creds
    // unless the operator explicitly opted into cleartext with --local-plaintext.
    if !r.no_backup {
        if r.local_plaintext {
            let path = dir.join(format!("{}.json", r.name));
            if !dry {
                std::fs::create_dir_all(dir).map_err(|e| {
                    Error::new(Code::EEscrowFailed, format!("mkdir key_backup: {e}"))
                })?;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
                std::fs::write(&path, bundle_json)
                    .map_err(|e| Error::new(Code::EEscrowFailed, format!("write bundle: {e}")))?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
            }
            written.push(json!({ "type": "plaintext", "path": path }));
        } else {
            let path = keystore::seal(&ctx.runner, dir, &r.name, bundle_json.as_bytes(), dry)?;
            written.push(json!({ "type": "sealed", "path": path }));
        }
    }

    // Encrypted escrow targets.
    for spec in &r.escrow {
        let (kind, arg) = spec.split_once(':').ok_or_else(|| {
            Error::new(Code::EEscrowFailed, format!("bad --escrow spec: {spec:?}"))
                .with_hint("use age:<pubkey> | gpg:<recipient> | pass:<store-path>")
        })?;
        let out_path = dir.join(format!("{}.{}", r.name, ext_for(kind)));
        if dry {
            written.push(json!({ "type": kind, "path": out_path, "planned": true }));
            continue;
        }
        std::fs::create_dir_all(dir).ok();
        let out_str = out_path.to_string_lossy().into_owned();
        let res = match kind {
            "age" => ctx.runner.run_stdin(
                &["age", "-r", arg, "-a", "-o", &out_str],
                bundle_json.as_bytes(),
                "encrypt key bundle with age",
            ),
            "gpg" => ctx.runner.run_stdin(
                &[
                    "gpg",
                    "--batch",
                    "--yes",
                    "--encrypt",
                    "--armor",
                    "--recipient",
                    arg,
                    "--output",
                    &out_str,
                ],
                bundle_json.as_bytes(),
                "encrypt key bundle with gpg",
            ),
            "pass" => ctx.runner.run_stdin(
                &["pass", "insert", "--multiline", "--force", arg],
                bundle_json.as_bytes(),
                "store key bundle in pass",
            ),
            other => {
                return Err(Error::new(
                    Code::EEscrowFailed,
                    format!("unknown escrow kind: {other}"),
                ))
            }
        };
        match res.and_then(|o| o.require("escrow target")) {
            Ok(_) => written.push(json!({ "type": kind, "path": out_path })),
            Err(e) => {
                return Err(Error::new(
                    Code::EEscrowFailed,
                    format!("escrow target {spec:?} failed: {}", e.message),
                )
                .with_hint("fix the recipient/pubkey or remove the target"));
            }
        }
    }

    // Recovery-key fingerprint (sha256 of the keyfile), if a recovery key exists.
    let recovery_fpr = if dry {
        None
    } else {
        recovery_fingerprint(ctx, r)
    };

    Ok(EscrowResult {
        written,
        recovery_fpr,
    })
}

fn ext_for(kind: &str) -> &'static str {
    match kind {
        "age" => "age",
        "gpg" => "asc",
        _ => "enc",
    }
}

/// Fingerprint via the secure recovery keyfile if present (best-effort).
fn recovery_fingerprint(ctx: &Context, r: &Resolved) -> Option<String> {
    if r.no_recovery_key {
        return None;
    }
    let kf = if Path::new("/dev/shm").is_dir() {
        PathBuf::from("/dev/shm")
    } else {
        std::env::temp_dir()
    }
    .join(format!("tpmnt-keys-{}", std::process::id()))
    .join("recovery");
    if !kf.exists() {
        return None;
    }
    let out = ctx
        .runner
        .probe(
            &["sha256sum", &kf.to_string_lossy()],
            "fingerprint recovery key",
        )
        .ok()?;
    out.stdout
        .split_whitespace()
        .next()
        .map(|h| h[..16.min(h.len())].to_string())
}

// --- register --------------------------------------------------------------

fn register_disk(ctx: &Context, disk: &Disk) -> Result<()> {
    let path = &ctx.global.config;
    let mut cfg = Config::load(path)?;
    if !cfg.disks.iter().any(|d| d.name == disk.name) {
        cfg.disks.push(disk.clone());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, cfg.to_toml()).map_err(|e| {
        Error::new(
            Code::EConfig,
            format!("write config {}: {e}", path.display()),
        )
    })?;
    Ok(())
}

fn next_steps(r: &Resolved, escrow: &EscrowResult) -> Vec<String> {
    let mut steps = Vec::new();
    let has = |t: &str| {
        escrow
            .written
            .iter()
            .any(|w| w.get("type").and_then(|v| v.as_str()) == Some(t))
    };
    if has("plaintext") {
        steps.push(
            "Copy the plaintext key bundle off this machine to secure offline storage.".into(),
        );
    }
    if has("sealed") {
        steps.push(
            "Local key bundle is sealed to this host's TPM; it can't be read on another machine. \
             Add an offline --escrow target (age/gpg) for disaster recovery, and retrieve it here \
             with `tpmnt recover <name>`."
                .into(),
        );
    }
    if has("vault") {
        steps.push(
            "Key also stored in the PIN vault: if the TPM ever can't unlock this disk, run \
             `tpmnt recover <name> --from vault` (or just `tpmnt recover <name>`, which falls back \
             to the vault) and enter your PIN to recover the raw LUKS key."
                .into(),
        );
    }
    if r.no_tpm {
        steps.push("No TPM enrolled; the volume will prompt for a passphrase at boot.".into());
    } else {
        steps.push("Verify cold unlock with `tpmnt status` after a reboot.".into());
    }
    steps
}

// --- explain ---------------------------------------------------------------

fn explain() -> Value {
    json!({
        "ok": true,
        "command": "init",
        "defaults": [
            { "step": "preflight", "default": "refuse if device has data", "bypass": "--wipe --yes" },
            { "step": "partition", "default": "fresh GPT, one partition", "bypass": "--no-partition | --partition <devpart>" },
            { "step": "luks", "default": "luks2 aes-xts-plain64 / argon2id / auto sector / 512-bit", "bypass": "--cipher --kdf --sector-size --label" },
            { "step": "key", "default": "auto diceware passphrase", "bypass": "--key-format base64 | --passphrase-file | --passphrase-stdin" },
            { "step": "recovery", "default": "add a recovery key", "bypass": "--no-recovery-key --i-understand-no-recovery" },
            { "step": "escrow", "default": "sealed (systemd-creds/TPM2) bundle to key_backup", "bypass": "--escrow age:|gpg:|pass: | --local-plaintext | --i-understand-no-backup | --emit-secrets" },
            { "step": "pin_vault", "default": "with a PIN (--with-pin or [defaults].require_pin): also store the bundle in the unified PIN vault for TPM-independent recovery", "bypass": "omit --with-pin (and require_pin=false)" },
            { "step": "tpm", "default": "enroll TPM2 (warn on PCR-only)", "bypass": "--no-tpm | --pcrs | --with-pin" },
            { "step": "filesystem", "default": "mkfs.btrfs (data+metadata checksums for bit-rot detection; dup metadata; zstd compression)", "bypass": "--fstype xfs|ext4 | --no-format" },
            { "step": "register", "default": "add [[disk]] + apply + mount", "bypass": "--no-register | --mountpoint | --name" }
        ],
        "errors": [
            "E_DEVICE_HAS_DATA", "E_ESCROW_FAILED", "E_BACKUP_REFUSED", "E_NO_TPM", "E_NOT_LUKS2"
        ]
    })
}
