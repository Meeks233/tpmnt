//! Command-line surface. clap derive with --help everywhere, global AI-native
//! flags, and subcommands. Kept declarative; behavior lives in `cmd/`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "tpmnt",
    version,
    about = "Unified, declarative, AI-native LUKS2 + TPM2 enroll/auto-decrypt/auto-mount manager",
    long_about = None,
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug, Clone)]
pub struct GlobalOpts {
    /// Path to the declarative TOML config.
    #[arg(long, global = true, default_value = crate::config::DEFAULT_PATH, env = "TPMNT_CONFIG")]
    pub config: PathBuf,

    /// Emit a structured JSON result instead of human text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Print the ordered execution plan (as JSON) and exit without touching anything.
    #[arg(long, global = true)]
    pub plan: bool,

    /// Compute and show what would change, applying nothing.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Emit per-command structured trace (argv, exit, stdout, stderr, duration) to stderr.
    #[arg(long, short = 'v', global = true)]
    pub debug: bool,

    /// Assume "yes" to confirmation prompts (required for destructive ops in non-interactive use).
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// Never prompt; fail instead of asking. Implies machine-driven use.
    #[arg(long, global = true)]
    pub non_interactive: bool,
}

impl GlobalOpts {
    /// `--plan` implies `--dry-run` (plan never mutates).
    pub fn effective_dry_run(&self) -> bool {
        self.dry_run || self.plan
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Greenfield: fully-managed initialization of a (possibly blank) disk.
    Init(InitArgs),
    /// Enroll TPM2 on an existing LUKS2 device (asks for the passphrase once).
    Enroll(EnrollArgs),
    /// Idempotently reconcile the system (crypttab/fstab/units) to the config.
    Apply,
    /// Report per-disk LUKS2/token/crypttab/mount state.
    Status,
    /// Fancy, TUI-style dashboard of every disk's tpmnt-managed state.
    #[command(alias = "dash")]
    Dashboard,
    /// On a new machine: re-enroll the local TPM for each configured disk.
    Migrate,
    /// Restore a backed-up header and revert config edits for a device.
    Rollback(RollbackArgs),
    /// List the SSH remotes this machine controls and the disks on each.
    Remote(RemoteArgs),
    /// Client-side: mount a remote tpmnt-managed dir over sshfs (+ ProxyJump).
    #[command(alias = "client")]
    MountRemote(MountRemoteArgs),
    /// Client-side: stop+disable a remote mount unit and unmount it.
    UmountRemote(UmountRemoteArgs),
    /// Spin a disk down now: unmount + close mapping + power off the platters.
    Power(PowerArgs),
    /// Apply disks' on/off schedule now: power up inside the window, down outside.
    Schedule(ScheduleArgs),
    /// Idle watcher for a cold-standby disk (run by its systemd unit).
    #[command(hide = true)]
    Monitor(MonitorArgs),
    /// Print the equivalent TOML config (for reproducible re-apply).
    PrintConfig,
    /// Generate the man page to the given directory.
    #[command(hide = true)]
    GenMan(GenManArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// The target block device (e.g. /dev/sdb). Optional with --from-config.
    pub device: Option<String>,

    /// Allow destroying existing data/partitions (must also pass --yes).
    #[arg(long)]
    pub wipe: bool,

    /// Do not partition; LUKS-format the whole block device (or --partition).
    #[arg(long)]
    pub no_partition: bool,
    /// Use this existing partition instead of creating one.
    #[arg(long)]
    pub partition: Option<String>,

    /// LUKS cipher (default aes-xts-plain64).
    #[arg(long)]
    pub cipher: Option<String>,
    /// LUKS KDF (default argon2id).
    #[arg(long)]
    pub kdf: Option<String>,
    /// LUKS sector size in bytes (default 4096).
    #[arg(long)]
    pub sector_size: Option<u32>,
    /// LUKS2 label.
    #[arg(long)]
    pub label: Option<String>,

    /// Read the primary passphrase from this file (manual mode).
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// Read the primary passphrase from stdin (manual mode).
    #[arg(long)]
    pub passphrase_stdin: bool,
    /// Auto-generated key format: "diceware" or "base64" (default diceware).
    #[arg(long, default_value = "diceware")]
    pub key_format: String,

    /// Do not add a recovery key (must pass --i-understand-no-recovery).
    #[arg(long)]
    pub no_recovery_key: bool,
    /// Acknowledge skipping the recovery key.
    #[arg(long)]
    pub i_understand_no_recovery: bool,

    /// Escrow target(s): age:<pubkey> | gpg:<recipient> | pass:<store-path>.
    /// Repeatable. The plaintext bundle dir (key_backup) is always written too
    /// unless --i-understand-no-backup.
    #[arg(long = "escrow")]
    pub escrow: Vec<String>,
    /// Finish even if no key bundle could be backed up (loud, recorded).
    #[arg(long)]
    pub i_understand_no_backup: bool,
    /// Include the generated secrets in --json output (default: only locations).
    #[arg(long)]
    pub emit_secrets: bool,

    /// Do not enroll TPM2 (passphrase/recovery-only; crypttab uses `none`).
    #[arg(long)]
    pub no_tpm: bool,
    /// PCRs to bind, comma/plus separated. Empty = TPM-only (warns).
    #[arg(long)]
    pub pcrs: Option<String>,
    /// Require a PIN in addition to the TPM.
    #[arg(long)]
    pub with_pin: bool,

    /// Filesystem type to create (default xfs).
    #[arg(long)]
    pub fstype: Option<String>,
    /// Do not create a filesystem (LUKS container only).
    #[arg(long)]
    pub no_format: bool,

    /// Usage scenario: "always-on" (default) or "cold-standby" (auto power-off).
    #[arg(long)]
    pub power_profile: Option<String>,
    /// Idle window before a cold-standby disk powers off (e.g. "5min", "30s").
    #[arg(long)]
    pub idle_timeout: Option<String>,
    /// Power-down method: "auto" (default), "standby", "sleep", or "power-off".
    #[arg(long)]
    pub power_off_method: Option<String>,

    /// Do not register in the config or mount (disk work only).
    #[arg(long)]
    pub no_register: bool,
    /// Mountpoint (default /mnt/<name>).
    #[arg(long)]
    pub mountpoint: Option<PathBuf>,
    /// Logical disk name (default derived from device basename).
    #[arg(long)]
    pub name: Option<String>,

    /// Drive the entire init from a TOML describing the desired end state.
    #[arg(long)]
    pub from_config: Option<PathBuf>,

    /// Print a human+machine description of every default and its bypass flag.
    #[arg(long)]
    pub explain: bool,
}

#[derive(Args, Debug)]
pub struct RemoteArgs {
    /// Only show this named remote (default: all).
    pub name: Option<String>,
    /// Probe each remote over SSH and report reachability (adds a round-trip).
    #[arg(long)]
    pub probe: bool,
}

#[derive(Args, Debug)]
pub struct MountRemoteArgs {
    /// Name of a [[remote_mount]] config entry (optional when flags are given).
    pub name: Option<String>,

    /// List configured remote mounts and live state (JSON/table).
    #[arg(long)]
    pub list: bool,

    /// Remote target: user@addr[:port].
    #[arg(long)]
    pub host: Option<String>,
    /// Remote (already-decrypted) path to export.
    #[arg(long)]
    pub remote_path: Option<String>,
    /// Local mountpoint.
    #[arg(long)]
    pub mountpoint: Option<PathBuf>,

    /// Jump/bastion host(s): user@host[:port]. Repeatable or comma-separated.
    #[arg(long = "jump", alias = "proxy-jump")]
    pub jump: Vec<String>,
    /// SSH identity file.
    #[arg(long)]
    pub identity: Option<PathBuf>,
    /// Remote sftp-server path for sshd without an sftp Subsystem.
    #[arg(long)]
    pub sftp_server: Option<String>,
    /// Escape hatch: full ssh command for exotic setups.
    #[arg(long)]
    pub ssh_command: Option<String>,

    /// Drive a remote mount entirely from a TOML end-state.
    #[arg(long)]
    pub from_config: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct PowerArgs {
    /// Name of the [[disk]] to spin down.
    pub name: String,
}

#[derive(Args, Debug)]
pub struct ScheduleArgs {
    /// Names of the [[disk]] entries to evaluate. Empty = all scheduled disks.
    pub names: Vec<String>,
    /// Run a single tick and exit (default: loop forever, like the systemd unit).
    #[arg(long)]
    pub once: bool,
    /// Override the timezone for this run: a fixed offset ("+08:00") or an IANA
    /// zone name ("Asia/Shanghai"). Overrides each disk's configured timezone.
    #[arg(long)]
    pub timezone: Option<String>,
}

#[derive(Args, Debug)]
pub struct MonitorArgs {
    /// Name of the cold-standby [[disk]] to watch.
    pub name: String,
    /// Run a single idle check and exit (default: loop forever).
    #[arg(long)]
    pub once: bool,
}

#[derive(Args, Debug)]
pub struct UmountRemoteArgs {
    /// Name of the remote mount to tear down.
    pub name: String,
}

#[derive(Args, Debug)]
pub struct EnrollArgs {
    /// The LUKS2 block device (e.g. /dev/sdb1 or a by-uuid path).
    pub device: String,

    /// PCRs to bind the TPM2 policy to, comma/plus separated (e.g. "7,14" or "7+14").
    /// Empty string or omitted = TPM-only (warns). Accepting a raw string lets
    /// `--pcrs ""` work as an explicit "no PCRs" signal for AI/scripted use.
    #[arg(long)]
    pub pcrs: Option<String>,

    /// Require a PIN in addition to the TPM (recommended for data disks).
    #[arg(long)]
    pub with_pin: bool,

    /// Read the existing passphrase from this file (instead of $PASSWORD or prompt).
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RollbackArgs {
    /// The device whose header backup should be restored.
    pub device: String,
}

#[derive(Args, Debug)]
pub struct GenManArgs {
    /// Output directory for the generated man page.
    pub out_dir: PathBuf,
}
