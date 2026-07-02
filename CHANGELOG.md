# Changelog

All notable changes to tpmnt are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.3.1] - 2026-07-02

### Added

- **Signed apt & dnf/zypper software repositories on GitHub Pages.** Stable `v*` releases now
  publish signed `reprepro` (apt) and `createrepo_c` (rpm) repositories to a `gh-pages` branch,
  so users can add a source once and `apt install tpmnt` / `dnf install tpmnt`. GPG signing runs
  in CI from repo secrets. See `docs/packaging.md` for maintainer setup and the README for install
  instructions. The rolling `edge` channel stays in Release assets and is not published to the repo.

## [0.3.0] - 2026-07-01

### Added

- **On-demand connect (`tpmnt connect [name…]`, alias `up`).** A pull-based bring-online: for each
  disk it tries the **last-known endpoint** first (establish the ciphertext forward, open via TPM2,
  mount) without probing anyone else. Only if that endpoint doesn't answer does it fall back to a
  single global discovery sweep, rebind, and retry. Rejects only when the disk is reachable nowhere.

### Changed

- **Distribution is now dependency-based packages, not standalone binaries.** Releases ship `.deb`
  (apt) and `.rpm` (dnf/zypper) that declare the runtime tools tpmnt orchestrates, so features work
  out of the box. `Depends`/`Requires` cover the core enroll→unlock→mount path plus the default
  cold-standby spindown (**hdparm**) and the mandatory PIN vault (**gnupg**); `Recommends` cover
  feature-specific tools (sg3_utils for USB spindown, xfsprogs/e2fsprogs, nbd/sshfs/openssh for
  remote disks, udisks2, parted, procps). The pure static-binary release path was dropped.
- **Auto-discovery is now lazy and batched — no more per-remote flooding.** `discover` (and the
  discovery baked into `apply`/`migrate`) no longer probes every remote for every disk. It
  inventories this host once (`blkid -o export`), trusts a disk's last-known remote binding without
  probing, and only when a disk expected *here* has genuinely vanished does it perform a **single
  global sweep** (one `blkid` per remote, all UUIDs compared at once). Cost drops from `N × M` probes
  to at most `1 + M` for N disks across M remotes.

### Fixed

- **`adopt` now takes true TPM2 ownership.** A disk carrying a foreign/stale TPM2 token is force
  re-enrolled to *this* host's TPM. The wipe runs as its own `systemd-cryptenroll --wipe-slot=tpm2`
  step — a combined `--wipe-slot=tpm2 --tpm2-device=auto` no-ops ("already enrolled") when the stale
  token binds the same PCR set, which previously left auto-unlock broken ("Object is remote").
- **Local disks survive re-enumeration.** `adopt` registers a local disk with no pinned `/dev/sdX`;
  it resolves via the stable `/dev/disk/by-uuid/<uuid>` symlink, and `discover` drops any stale pin.
- **Spin-up self-heals stale state.** A dead dm-crypt mapping (backing device vanished / disk
  re-enumerated → `device: (null)`) is detected and re-opened instead of mounting a corpse; a stale
  removal record left by a since-migrated disk is discarded instead of chasing a rescan that hangs.

## [0.2.0] - 2026-07-01

### Added

- **Auto-discovery (`tpmnt discover`, aliases `scan`/`locate`).** A disk is tracked by its stable
  LUKS2 UUID, not a path or host. Discovery probes every candidate location (locally via `blkid`,
  then each `[[remote]]` over SSH) and rebinds the config to wherever the disk actually is —
  local ↔ remote ↔ another remote — always keeping decryption on the trusted local host (a remote
  disk gets `transport = nbd` so its ciphertext is forwarded here). Runs automatically at the start
  of `apply`.
- **Mandatory PIN + unified key vault.** One PIN gates TPM2 unlock *and* encrypts a single,
  portable, TPM-independent recovery file (`key_backup/vault.gpg`) holding every managed disk's key.
  - `[defaults].require_pin` forces a PIN (and vault write) on every `init`/`adopt`.
  - `tpmnt pin enable|disable [<name>] [--all] [--global]` — the post-encryption entry point:
    re-enrolls the TPM2 token with/without a PIN (`--wipe-slot=tpm2`), reconciles `tpm2-pin=yes`
    into crypttab, and stores the key in the vault. Works on remote managed disks (ciphertext
    forwarded, re-enrollment runs locally).
  - `tpmnt vault list|rekey|sync` — inspect the vault, rotate its PIN, or (re)build it from the
    local sealed bundles.
  - `tpmnt recover --from vault`, plus automatic vault fallback in the default `recover` when the
    TPM-sealed bundle can't be read ("my TPM broke" recovery).
  - `tpmnt migrate --pin-file` — one PIN unlocks every disk for re-enrollment on a new machine.
  - Vault encryption is delegated to `gpg --symmetric` (salted + iterated s2k, AES-256): never
    plaintext at rest, resistant to rainbow tables.

### Fixed

- `luks::header_backup` is now idempotent: a second TPM2 enrollment on a disk (as `pin enable`
  does) no longer crashes on `cryptsetup luksHeaderBackup` refusing to overwrite. The first
  (pristine, pre-management) header backup is preserved for `rollback`.
- `crypttab_line` now emits `tpm2-pin=yes` for PIN-enrolled disks, so systemd actually prompts for
  the PIN at unlock instead of failing silently.

### Packaging

- `gnupg` added to Debian `recommends` (needed for the PIN vault).

## [0.1.0]

- Initial release: `enroll`, `apply`, `status`, `migrate`, `rollback`; whole-disk `init` with key
  escrow; `mount-remote` over sshfs with SSH ProxyJump; `adopt` + threat-model classification;
  remote ciphertext transport (NBD-over-SSH / NVMe-TCP); cold-standby power profiles and scheduled
  power windows.
