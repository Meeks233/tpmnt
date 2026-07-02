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
    Init(Box<InitArgs>),
    /// Authenticate and retrieve a disk's generated key; optionally open it.
    Recover(RecoverArgs),
    /// Temporarily detach a disk (grace unmount + close); data & config kept.
    Offline(OfflineArgs),
    /// Permanently remove a disk's local management (needs --yes); no format.
    Destroy(DestroyArgs),
    /// Enable disk(s): mark them managed again and bring them online (reconcile +
    /// open + mount). Reverses `disable`. Omit names to multi-select.
    Enable(ToggleArgs),
    /// Disable disk(s): keep config + keys but stop managing them — unmount/close
    /// now and remove crypttab/units so they never auto-unlock at boot. Reversible
    /// with `enable`. Omit names to multi-select.
    Disable(ToggleArgs),
    /// Detach disk(s) from tpmnt into manual mode: enroll a passphrase you supply,
    /// wipe tpmnt's TPM2 auto-unlock, and drop all local management. Data is kept;
    /// you then unlock it yourself with that passphrase (+PIN).
    Detach(DetachArgs),
    /// Take ownership of existing disk(s): rotate in a locally-managed key.
    Adopt(AdoptArgs),
    /// Rename a disk's logical (mount) name; re-points crypttab/fstab and, if the
    /// disk is currently mounted, remounts it live under the new name.
    Rename(RenameArgs),
    /// Enroll TPM2 on an existing LUKS2 device (asks for the passphrase once).
    Enroll(EnrollArgs),
    /// Idempotently reconcile the system (crypttab/fstab/units) to the config.
    Apply,
    /// Re-locate each disk by its LUKS UUID and rebind the config if it moved
    /// (local↔remote or between remotes). Runs automatically inside `apply`.
    #[command(alias = "scan", alias = "locate")]
    Discover(DiscoverArgs),
    /// Pull disk(s) online on demand: try each at its last-known endpoint first,
    /// and only fall back to a single global discovery sweep if that endpoint
    /// doesn't answer (never a per-remote storm). Default: all disks, name some,
    /// or `--remote <name>` to bring up exactly the disks present on one remote now.
    #[command(alias = "up")]
    Connect(ConnectArgs),
    /// Report per-disk LUKS2/token/crypttab/mount state.
    Status,
    /// Fancy, TUI-style dashboard of every disk's tpmnt-managed state.
    #[command(alias = "dash")]
    Dashboard,
    /// On a new machine: re-enroll the local TPM for each configured disk. With a
    /// PIN vault present, one PIN unlocks every disk (no per-disk $PASSWORD).
    Migrate(MigrateArgs),
    /// Restore a backed-up header and revert config edits for a device.
    Rollback(RollbackArgs),
    /// List the SSH remotes this machine controls (default), or `remote add
    /// <host>` to register a new one (its name defaults to the remote's hostname).
    Remote(RemoteArgs),
    /// Client-side: mount a remote tpmnt-managed dir over sshfs (+ ProxyJump).
    #[command(alias = "client")]
    MountRemote(MountRemoteArgs),
    /// Client-side: stop+disable a remote mount unit and unmount it.
    UmountRemote(UmountRemoteArgs),
    /// Power a disk down (default), back up (--on), or set its idle timeouts.
    /// Spin-down = unmount + close + power off; --on = rescan + open + mount.
    Power(PowerArgs),
    /// Apply disks' on/off schedule now: power up inside the window, down outside.
    Schedule(ScheduleArgs),
    /// Idle watcher for a cold-standby disk (run by its systemd unit).
    #[command(hide = true)]
    Monitor(MonitorArgs),
    /// Turn a mandatory unlock PIN on/off for already-encrypted disk(s) by
    /// re-enrolling their TPM2 token. The other entry point is at creation time:
    /// `init --with-pin` or `[defaults].require_pin`.
    Pin(PinArgs),
    /// Manage the unified PIN vault (the TPM-independent recovery store):
    /// `list` its disks, `rekey` its PIN, or `sync` it from sealed bundles.
    Vault(VaultArgs),
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
    /// Repeatable. A sealed local bundle (key_backup) is always written too
    /// unless --i-understand-no-backup.
    #[arg(long = "escrow")]
    pub escrow: Vec<String>,
    /// Store the local key bundle in CLEARTEXT (old behavior) instead of sealing
    /// it to the TPM with systemd-creds. Requires --i-understand-plaintext-keys.
    #[arg(long)]
    pub local_plaintext: bool,
    /// Acknowledge writing the local key bundle in cleartext.
    #[arg(long)]
    pub i_understand_plaintext_keys: bool,
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

    /// Filesystem to create: "btrfs" (default — data checksums catch cold-storage
    /// bit rot, dup metadata, zstd compression), "xfs", or "ext4".
    #[arg(long)]
    pub fstype: Option<String>,
    /// Do not create a filesystem (LUKS container only).
    #[arg(long)]
    pub no_format: bool,

    /// Treat <device> as living on this [[remote]]: the remote is untrusted and
    /// is never asked to decrypt. Its raw ciphertext is forwarded here over
    /// NBD-over-SSH and every cryptsetup step runs locally; the disk is
    /// registered as a managed remote (transport=nbd).
    #[arg(long)]
    pub remote: Option<String>,

    /// Usage scenario: "cold-standby" (default, auto power-off) or "always-on".
    #[arg(long)]
    pub power_profile: Option<String>,
    /// Idle window before a cold-standby disk's platters spin down to standby
    /// (mapping kept open; wakes on next access). Default "5min". The old
    /// `--idle-timeout` name is accepted as an alias. tpmnt never auto-powers-off
    /// past standby — full power-off is a manual `tpmnt power … --method` action.
    #[arg(long, alias = "idle-timeout")]
    pub standby_timeout: Option<String>,
    /// Power-down method: "auto" (default), "standby", "sleep", "power-off", or
    /// "remove" (remove the disk from its host OS; reversible on next spin-up).
    #[arg(long)]
    pub power_off_method: Option<String>,

    /// Do not register in the config or mount (disk work only).
    #[arg(long)]
    pub no_register: bool,
    /// Mountpoint (default /mnt/<name>). Stable and location-independent — it does
    /// NOT change when the disk moves local↔remote; don't encode local/remote in it.
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
pub struct OfflineArgs {
    /// Name of the [[disk]] to detach.
    pub name: String,
    /// Lazily detach a busy mount (`umount -l`) instead of failing on busy.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ToggleArgs {
    /// Name(s) of the [[disk]] entries to act on. Omit to pick from a
    /// multi-select list in an interactive terminal.
    pub names: Vec<String>,
    /// Lazily detach a busy mount (`umount -l`) when disabling.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct DetachArgs {
    /// Name(s) of the [[disk]] entries to detach into manual mode. Omit to pick
    /// from a multi-select list in an interactive terminal.
    pub names: Vec<String>,

    /// Read the NEW manual passphrase (that you'll unlock the disk with after
    /// detaching) from this file. Otherwise $PASSWORD or an interactive prompt.
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// Read the new manual passphrase from stdin.
    #[arg(long)]
    pub passphrase_stdin: bool,

    /// Also add a TPM2+PIN keyslot so the disk can be unlocked by TPM2+PIN in
    /// addition to the manual passphrase (still not tpmnt-managed).
    #[arg(long)]
    pub with_pin: bool,

    /// Keep tpmnt's existing TPM2 auto-unlock token instead of wiping it (default
    /// is to wipe it so the disk truly requires your manual passphrase).
    #[arg(long)]
    pub keep_tpm: bool,

    /// Lazily detach a busy mount (`umount -l`) during teardown.
    #[arg(long)]
    pub force: bool,

    /// Local port for the NBD-over-SSH tunnel when a remote disk's ciphertext must
    /// be forwarded here to re-enroll its header.
    #[arg(long, default_value_t = 21813)]
    pub local_port: u16,
}

#[derive(Args, Debug)]
pub struct DestroyArgs {
    /// Name(s) of the [[disk]] entries to stop managing. Omit to pick from a
    /// multi-select list in an interactive terminal. Confirm with the global
    /// --yes (or answer the interactive prompt).
    pub names: Vec<String>,
    /// Lazily detach a busy mount (`umount -l`) during teardown.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct AdoptArgs {
    /// Name(s) of the [[disk]] entries to take ownership of. With --device this
    /// is the single logical name to register the not-yet-configured disk under.
    pub names: Vec<String>,

    /// Register and take over an EXISTING disk not yet in the config: give its
    /// device path here (e.g. /dev/sda). Requires exactly one name. For a disk on
    /// another machine, also pass --remote (its ciphertext is forwarded here).
    #[arg(long)]
    pub device: Option<String>,
    /// The [[remote]] a newly-registered --device lives on (untrusted; only its
    /// LUKS ciphertext is forwarded here, decryption stays local).
    #[arg(long)]
    pub remote: Option<String>,
    /// Mountpoint for a newly-registered disk (default /mnt/<name>). Stable and
    /// location-independent — unchanged when the disk moves local↔remote.
    #[arg(long)]
    pub mountpoint: Option<PathBuf>,
    /// LUKS UUID for a newly-registered disk (default: read from its header).
    #[arg(long)]
    pub uuid: Option<String>,
    /// Filesystem of a newly-registered disk, recorded for fstab (default: the
    /// config's default fstype). The existing data is never reformatted.
    #[arg(long)]
    pub fstype: Option<String>,
    /// After taking ownership, open + mount the disk locally now. For a remote
    /// disk the ciphertext forward is left live so the mount persists.
    #[arg(long)]
    pub mount: bool,

    /// Read the disk's current ("old") key from this file.
    #[arg(long)]
    pub old_key_file: Option<PathBuf>,
    /// Read the disk's current ("old") key from stdin.
    #[arg(long)]
    pub old_key_stdin: bool,

    /// For remote disks: steady-state ciphertext transport recorded in config
    /// ("nbd" default, or "nvme-tcp"). Ciphertext forwarding during adopt always
    /// uses NBD-over-SSH regardless.
    #[arg(long)]
    pub transport: Option<String>,
    /// Local port for the NBD-over-SSH tunnel when forwarding a remote disk.
    #[arg(long, default_value_t = 21809)]
    pub local_port: u16,

    /// Remove the old key after the managed key is added, so only tpmnt-owned
    /// keys remain (default: keep the old key as an extra fallback).
    #[arg(long)]
    pub rotate_out_old: bool,

    /// New managed key format: "diceware" (default) or "base64".
    #[arg(long, default_value = "diceware")]
    pub key_format: String,
    /// Do not add a recovery key (needs --i-understand-no-recovery).
    #[arg(long)]
    pub no_recovery_key: bool,
    /// Acknowledge skipping the recovery key.
    #[arg(long)]
    pub i_understand_no_recovery: bool,

    /// Do not enroll TPM2 (managed key + recovery only).
    #[arg(long)]
    pub no_tpm: bool,
    /// PCRs to bind, comma/plus separated. Empty = TPM-only (warns).
    #[arg(long)]
    pub pcrs: Option<String>,
    /// Require a PIN in addition to the TPM.
    #[arg(long)]
    pub with_pin: bool,

    /// Store the new key bundle in CLEARTEXT instead of sealing it to the TPM.
    /// Requires --i-understand-plaintext-keys.
    #[arg(long)]
    pub local_plaintext: bool,
    /// Acknowledge writing the local key bundle in cleartext.
    #[arg(long)]
    pub i_understand_plaintext_keys: bool,
    /// Include the generated secrets in --json output (default: only locations).
    #[arg(long)]
    pub emit_secrets: bool,
}

#[derive(Args, Debug)]
pub struct RenameArgs {
    /// Current logical name of the [[disk]] to rename.
    pub old: String,
    /// New logical name. Must not already be in use.
    pub new: String,
    /// Lazily detach a busy mount (`umount -l`) if the disk is mounted.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct RecoverArgs {
    /// Name of the [[disk]] whose key bundle to retrieve.
    pub name: String,

    /// Reveal the recovered secrets (passphrase + recovery key). Without this,
    /// only proof-of-retrievability metadata is printed — never the key.
    #[arg(long)]
    pub show: bool,

    /// Manually open the LUKS mapping now using the recovered key (for when TPM
    /// auto-unlock is broken). Local disks only.
    #[arg(long)]
    pub open: bool,

    /// Alternate bundle source: creds:<file> (sealed) | plaintext:<file> | vault
    /// (the PIN-encrypted unified store). Default: the sealed <name>.cred under
    /// key_backup, automatically falling back to the PIN vault if the TPM seal
    /// can't be read (the "my TPM broke" recovery path).
    #[arg(long)]
    pub from: Option<String>,

    /// Read the recovery PIN from this file (for the vault path). Otherwise
    /// $TPMNT_PIN or an interactive prompt.
    #[arg(long)]
    pub pin_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct DiscoverArgs {
    /// Disks to re-locate (default: all configured disks).
    pub names: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// Disks to bring online (default: every configured disk). With --remote, this
    /// narrows the action to a subset of that remote's disks instead.
    pub names: Vec<String>,

    /// Bring up the disks that live on this [[remote]]: probe the remote once and
    /// connect exactly the configured disks actually present there now, silently
    /// skipping any that have since been removed (the "was abc, now acd → bring up
    /// ac" case). Scoped to this one remote — never a network-wide sweep.
    #[arg(long)]
    pub remote: Option<String>,

    /// Base local port for the NBD-over-SSH ciphertext forward. Each remote disk
    /// connected in one run uses a distinct port counting up from this.
    #[arg(long, default_value_t = 21815)]
    pub local_port: u16,
}

#[derive(Args, Debug)]
pub struct RemoteArgs {
    #[command(subcommand)]
    pub action: Option<RemoteAction>,
}

#[derive(Subcommand, Debug)]
pub enum RemoteAction {
    /// List configured remotes and the disks on each (this is the default when no
    /// subcommand is given).
    List(RemoteListArgs),
    /// Register a new SSH remote. Its name defaults to the hostname the remote
    /// itself reports (via `ssh <host> hostname`), so `tpmnt up --remote <hostname>`
    /// just works; override with --name.
    Add(RemoteAddArgs),
    /// Remove SSH remote(s) from the config. Omit names to pick from a
    /// multi-select list. Refuses a remote that still has disks (destroy/move
    /// them first, so they aren't orphaned).
    #[command(alias = "rm", alias = "delete")]
    Remove(RemoteRemoveArgs),
    /// Rename a remote's logical name, re-pointing every disk that lives on it.
    /// Handy when a remote was first registered under an ad-hoc name (e.g. the SSH
    /// user) and you want its real hostname instead.
    Rename(RemoteRenameArgs),
    /// Enable remote(s): `up`/discovery consider their disks again. Reverses
    /// `disable`. Omit names to multi-select.
    Enable(RemoteToggleArgs),
    /// Disable remote(s): `up`/discovery skip their disks (no probing/connecting),
    /// and the dashboard greys them out. Reversible with `enable`. Omit names to
    /// multi-select.
    Disable(RemoteToggleArgs),
}

#[derive(Args, Debug, Default)]
pub struct RemoteListArgs {
    /// Only show this named remote (default: all).
    pub name: Option<String>,
    /// Probe each remote over SSH and report reachability (adds a round-trip).
    #[arg(long)]
    pub probe: bool,
}

#[derive(Args, Debug)]
pub struct RemoteAddArgs {
    /// SSH destination: user@addr[:port].
    pub host: String,

    /// Logical name for the remote, referenced by `disk.remote` and `up --remote`.
    /// Default: the hostname the remote reports over SSH.
    #[arg(long)]
    pub name: Option<String>,

    /// Jump/bastion host(s): user@host[:port]. Repeatable or comma-separated.
    #[arg(long = "jump", alias = "proxy-jump")]
    pub jump: Vec<String>,

    /// SSH identity (private key) file.
    #[arg(long)]
    pub identity: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RemoteRemoveArgs {
    /// Name(s) of the [[remote]] entries to remove. Omit to pick from a
    /// multi-select list in an interactive terminal.
    pub names: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RemoteToggleArgs {
    /// Name(s) of the [[remote]] entries to enable/disable. Omit to pick from a
    /// multi-select list in an interactive terminal.
    pub names: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RemoteRenameArgs {
    /// Current name of the [[remote]] to rename.
    pub old: String,
    /// New name. Must not already be in use by another remote.
    pub new: String,
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
    /// Name of the [[disk]] to act on — spin it down (default), bring it back up
    /// (--on), or configure its timeouts (a timeout flag). Optional only with
    /// --global.
    pub name: Option<String>,

    /// Bring the disk back up now: rescan it back if it was powered off, rebuild
    /// its ciphertext forward, open (TPM2) and mount it. The inverse of the
    /// default spin-down.
    #[arg(long, conflicts_with = "off")]
    pub on: bool,
    /// Spin the disk down now (the default action; accepted for symmetry with
    /// --on).
    #[arg(long)]
    pub off: bool,
    /// One-shot power-down method override, ignoring the disk's configured
    /// `power_off_method`: "auto", "standby", "sleep", "power-off" (truly cut
    /// power to the drive/dock — reversible via --on), or "remove" (drop the
    /// device from its host OS). Only meaningful for the spin-down action.
    #[arg(long)]
    pub method: Option<String>,

    /// Set the cold-standby standby window (idle time before the platters spin
    /// down, mapping kept). Writes config instead of spinning down now. Applies to
    /// the named disk, or to the global [defaults] with --global.
    #[arg(long)]
    pub standby_timeout: Option<String>,
    /// Apply --standby-timeout to the global [defaults] rather than a single disk.
    #[arg(long)]
    pub global: bool,
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
pub struct MigrateArgs {
    /// Read the PIN (to unlock the unified vault) from this file. Otherwise
    /// $TPMNT_PIN or an interactive prompt. Ignored when no vault exists, in
    /// which case each disk falls back to $PASSWORD.
    #[arg(long)]
    pub pin_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RollbackArgs {
    /// The device whose header backup should be restored.
    pub device: String,
}

#[derive(Args, Debug)]
pub struct PinArgs {
    #[command(subcommand)]
    pub action: PinAction,
}

#[derive(Subcommand, Debug)]
pub enum PinAction {
    /// Enable a mandatory PIN: re-enroll the TPM2 token WITH a PIN (and store the
    /// key in the PIN vault). Scope: one disk, --all managed disks, or --global.
    Enable(PinScope),
    /// Disable the mandatory PIN: re-enroll the TPM2 token WITHOUT a PIN.
    Disable(PinScope),
}

#[derive(Args, Debug)]
pub struct PinScope {
    /// Disk name to act on. Omit when using --all or --global.
    pub name: Option<String>,

    /// Apply to every managed disk (leaves [defaults].require_pin as-is).
    #[arg(long)]
    pub all: bool,
    /// Apply to every managed disk AND set/clear [defaults].require_pin, so the
    /// policy also governs future disks created by init/adopt.
    #[arg(long)]
    pub global: bool,

    /// Read the PIN from this file (enable). Else $TPMNT_PIN or a prompt.
    #[arg(long)]
    pub pin_file: Option<PathBuf>,

    /// Local port for the NBD-over-SSH tunnel when a remote disk's ciphertext
    /// must be forwarded here to re-enroll its header.
    #[arg(long, default_value_t = 21811)]
    pub local_port: u16,
}

#[derive(Args, Debug)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub action: VaultAction,

    /// Read the current PIN from this file (else $TPMNT_PIN or a prompt).
    #[arg(long, global = true)]
    pub pin_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum VaultAction {
    /// List the disks whose keys are stored in the vault (no secrets shown).
    List,
    /// Change the vault's PIN: decrypt with the current PIN, re-encrypt with a new one.
    Rekey {
        /// Read the NEW PIN from this file (else an interactive prompt).
        #[arg(long)]
        new_pin_file: Option<PathBuf>,
    },
    /// (Re)build the vault from the local sealed `.cred` bundles of managed disks.
    Sync,
}

#[derive(Args, Debug)]
pub struct GenManArgs {
    /// Output directory for the generated man page.
    pub out_dir: PathBuf,
}
