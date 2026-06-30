# tpmnt

**Unified, declarative, AI-native CLI for LUKS2 + TPM2 "enroll once → auto-decrypt → auto-mount".**

The Linux disk-encryption stack is split across `systemd-cryptenroll` (register a TPM),
`crypttab` (decrypt), and `fstab` (mount) — with no single tool that does all three from one
declarative, portable config. `tpmnt` fills that gap. It is an **orchestrator**: it shells out to
the trusted system tools (`cryptsetup`, `systemd-cryptenroll`, `systemd-cryptsetup`) and owns the
declarative config + idempotent reconciliation around them. It never reimplements cryptography.

> Status: **Phases A–C complete** — `enroll`, `apply`, `status`, `migrate`, `rollback` (A);
> whole-disk `init` with key escrow (B); client-side `mount-remote` over sshfs with SSH ProxyJump
> (C). Verified by automated self-tests including a real cold TPM2 unlock with no passphrase, an
> age-encrypted escrow round-trip, and a self-healing remote mount through a bastion.

## Why

| Tool | enroll | decrypt | mount | declarative | migrate |
|---|:---:|:---:|:---:|:---:|:---:|
| `systemd-cryptenroll` | ✅ | ❌ | ❌ | ❌ | ❌ |
| `crypttab` / `fstab` | — | ✅ | ✅ | partial | ❌ |
| **tpmnt** | ✅ | ✅ | ✅ | ✅ (one TOML) | ✅ |

## Install

### Prebuilt static binary (recommended — zero library dependencies)

`tpmnt` is a single **static musl binary**: no shared libraries, no glibc version to match,
nothing to pull into your system. It runs as-is on any Linux distro (Debian, Ubuntu, Fedora,
Arch, …). Copy-paste to fetch the latest **stable** release into `/usr/local/bin`:

```sh
set -e
arch=$(uname -m); case "$arch" in
  x86_64)        target=x86_64-unknown-linux-musl ;;
  aarch64|arm64) target=aarch64-unknown-linux-musl ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac
url=$(curl -fsSL https://api.github.com/repos/Meeks233/tpmnt/releases/latest \
  | grep -o "https://[^\"]*-${target}\.tar\.gz" | head -n1)
curl -fsSL "$url" | tar -xz -C /tmp
sudo install -m 0755 /tmp/tpmnt-*-${target}/tpmnt /usr/local/bin/tpmnt
tpmnt --version
```

> Every commit also publishes a rolling `edge` build as a **pre-release**. The command above
> uses GitHub's `releases/latest` endpoint, which excludes pre-releases, so it only ever fetches
> a vetted, tagged stable release. To try the bleeding edge, grab a `tpmnt-edge-…` asset from the
> [`edge` pre-release](https://github.com/Meeks233/tpmnt/releases/tag/edge).

### Debian / Ubuntu (.deb)

Each stable release also ships a `.deb` (declares its system-tool deps via apt):

```sh
curl -fsSLO https://github.com/Meeks233/tpmnt/releases/latest/download/tpmnt-x86_64-unknown-linux-gnu.deb
sudo apt install ./tpmnt-x86_64-unknown-linux-gnu.deb
```

### Fedora / RHEL / openSUSE (COPR)

```sh
sudo dnf copr enable meeks/tpmnt
sudo dnf install tpmnt
```

### Ubuntu (PPA)

```sh
sudo add-apt-repository ppa:meeks/tpmnt
sudo apt update
sudo apt install tpmnt
```

### Arch Linux (AUR)

```sh
paru -S tpmnt        # build from source, or `tpmnt-bin` for the prebuilt binary
```

### Nix / NixOS

```sh
nix run github:Meeks233/tpmnt -- --help     # run without installing
nix profile install github:Meeks233/tpmnt   # install into your profile
```

> Recipes for all of the above live in [`packaging/`](packaging/) — one
> subdirectory per distro, each with build + publish instructions.

### From source

```sh
cargo install --path .
```

### Runtime dependencies (no dependency hell)

tpmnt is an **orchestrator**: the binary itself links nothing but libc (and *nothing at all* in
the static musl build). At runtime it shells out to standard system tools that ship with — or are
one `apt`/`dnf install` from — every distro. None are obscure or version-fragile:

- **always:** `cryptsetup`, `systemd` (provides `systemd-cryptenroll` / `systemd-cryptsetup`), a TPM2 at `/dev/tpmrm0`
- **`init`:** `gdisk` (sgdisk) + a filesystem tool (`mkfs.xfs` / `mkfs.ext4` / …)
- **`mount-remote`:** `sshfs` + `fusermount3`
- **optional:** `age` or `gpg` (encrypted key escrow), `hdparm` (power profiles)

## Quickstart

```sh
# 1. Enroll TPM2 on an existing LUKS2 disk (asks for the passphrase once).
sudo tpmnt enroll /dev/disk/by-uuid/<luks-uuid> --pcrs 7,14

# 2. Describe the desired end state in /etc/tpmnt/tpmnt.toml:
cat /etc/tpmnt/tpmnt.toml
# [[disk]]
# name       = "mycache"
# uuid       = "e7e6fc65-..."
# mountpoint = "/srv/mycache"
# fstype     = "xfs"
# pcrs       = [7, 14]

# 3. Reconcile the system (writes crypttab + fstab, creates the mountpoint).
sudo tpmnt apply

# 4. Inspect reality.
sudo tpmnt status            # human table
sudo tpmnt status --json     # machine-readable
sudo tpmnt dashboard         # fancy, TUI-style per-disk panels
```

After a reboot the disk unlocks via the TPM (no passphrase) and mounts automatically. A
passphrase/recovery keyslot is **always** kept as the portable trust root.

## Whole-disk init (Phase B)

`tpmnt init <device>` takes a (possibly blank) disk and does everything in one command:
preflight guard → GPT partition → LUKS2 format → auto-generated passphrase **and** recovery key →
**key escrow** → TPM2 enroll → filesystem → register + mount. Every step has a flag, a sane
default, and a bypass. Run `tpmnt init --explain` to see them all.

```sh
# Fully-managed: blank disk -> encrypted, TPM-unlocking, mounted, key escrowed to age.
sudo tpmnt init /dev/sdb \
  --wipe --yes --non-interactive \
  --name mycache --mountpoint /srv/mycache \
  --escrow age:age1qz...your-pubkey... \
  --pcrs 7,14 --with-pin
# Writes the plaintext key bundle to key_backup AND an age-encrypted copy; refuses to finish
# in auto mode unless at least one backup target was captured (E_BACKUP_REFUSED otherwise).
```

```sh
# Bring-your-own passphrase, NO TPM, no recovery key, no filesystem (LUKS container only):
sudo tpmnt init /dev/sdb \
  --wipe --yes --non-interactive \
  --passphrase-file ./secret.txt \
  --no-tpm --no-recovery-key --i-understand-no-recovery \
  --no-format --i-understand-no-backup
```

Safety gates: refuses any disk that already has data unless `--wipe --yes`
(`E_DEVICE_HAS_DATA`); refuses to leave an unbacked-up volume after a failed escrow target
(`E_ESCROW_FAILED`); `--plan` prints the full ordered JSON plan and touches nothing. Drive an
entire init from a single TOML with `--from-config <file>`.

## Remote mounts with jump hosts (Phase C)

`tpmnt mount-remote` mounts a remote, already-decrypted tpmnt directory onto **this** machine over
`sshfs`, managed by a self-healing systemd **--user** unit (no root, no fstab). Optional LAN jump
hosts via SSH ProxyJump.

```sh
# Direct mount of a remote decrypted dir, kept alive by a user service:
tpmnt mount-remote mycache \
  --host alice@192.168.5.10 --remote-path /home/alice/hdd/mycache \
  --mountpoint ~/hdd/mycache --identity ~/.ssh/id_ed25519
```

```sh
# Through a LAN bastion (ProxyJump). Repeat / comma-separate --jump for multi-hop:
tpmnt mount-remote mycache --jump me@192.168.5.2
tpmnt mount-remote mycache --jump me@192.168.5.2,me@10.0.0.9   # multi-hop chain

tpmnt mount-remote --list          # show configured remote mounts + live state
tpmnt umount-remote mycache        # stop+disable the unit and unmount
```

`--plan` reports the exact `sshfs` argv, the effective ProxyJump chain, and per-hop reachability
(with timeouts; it never hangs) without writing anything. The sftp path is auto-detected: tpmnt
probes the remote sftp Subsystem and transparently falls back to exec'ing `sftp-server` directly
when the remote sshd has no Subsystem (reported as `sftp_path_used`). When an explicit
`--identity` is combined with `--jump`, tpmnt carries the key to every hop via a constructed
ProxyCommand (plain `-J` does not propagate `-i`).

## Power profiles: cold-standby auto power-off (Phase D)

Each `[[disk]]` declares a **usage scenario**. A *cold-standby* (archival/backup) disk that has seen
no **real access** for an idle window is automatically powered down — the whole disk, not just spun
idle — to stop needless platter wear and save power. *always-on* disks (the default) are never
touched.

```toml
[[disk]]
name             = "archive"
uuid             = "…"
mountpoint       = "/srv/archive"
power_profile    = "cold-standby"   # default: "always-on"
idle_timeout     = "5min"           # also "30s", "10m", "1h", or bare seconds
power_off_method = "auto"           # auto | standby (hdparm -y) | sleep (hdparm -Y) | power-off (udisksctl)
```

```sh
sudo tpmnt apply              # installs tpmnt-monitor-archive.service + mounts the disk noatime
sudo systemctl enable --now tpmnt-monitor-archive.service
sudo tpmnt power archive      # manual one-shot: unmount → cryptsetup close → power down now
```

### Managing a distro-mounted disk (crypttab/automount)

For a disk the OS already opens under its own `luks-<uuid>` mapping (via `crypttab`), set two extra
keys so tpmnt drives the *existing* setup instead of its own:

```toml
[[disk]]
name             = "mycache"
uuid             = "e7e6fc65-…"
device           = "/dev/sda"
mapper           = "luks-e7e6fc65-…"   # manage the distro's existing mapping
mountpoint       = "/home/alice/hdd/mycache"
power_profile    = "cold-standby"
idle_timeout     = "5min"
power_off_method = "standby"
teardown         = "systemd"           # stop the .mount + systemd-cryptsetup@ units (clean)
```

With `teardown = "systemd"`, spindown stops the `.mount` and `systemd-cryptsetup@<mapper>` units
rather than running raw `umount`/`cryptsetup close`, so the disk re-opens **cleanly via TPM2** on
the next access. Pair it with a systemd **automount** (`noauto,x-systemd.automount` in fstab) for a
fully seamless cycle: idle → spindown (platters stop) → access → auto-unseal + remount in seconds.
Here `apply` is *not* used (it would rewrite crypttab/fstab); only `monitor`/`power` act on the disk.

`apply` writes a self-healing `tpmnt-monitor-<name>.service` per cold-standby disk and mounts it
`noatime`. The monitor judges idleness from **real block I/O counters** (`/sys/block/<dm>/stat`),
not atime — so background metadata never masks an idle disk, and an actual read/write resets the
window. On expiry it runs the spindown sequence: **unmount → `cryptsetup close` → power off the
backing disk** (`auto` picks `udisksctl power-off` for USB/removable, `hdparm -y` for rotational,
and skips non-spinnable devices). `default` is `always-on`, so existing configs are unchanged.

## Scheduled power on/off (time windows)

Where *cold-standby* reacts to **idleness**, a **schedule** reacts to the **clock**: a disk is kept
powered on during a daily window and powered off outside it. Add a `[disk.schedule]` to any disk:

```toml
[[disk]]
name       = "archive"
uuid       = "…"
mountpoint = "/mnt/archive"

[disk.schedule]
on       = "08:00"          # power on at 08:00
off      = "23:00"          # power off at 23:00 (off < on ⇒ overnight window)
timezone = "Asia/Shanghai"  # fixed offset ("+08:00") or IANA name; omit = host local time
```

```sh
sudo tpmnt apply                                   # installs tpmnt-schedule-archive.service
sudo systemctl enable --now tpmnt-schedule-archive.service
sudo tpmnt schedule archive backup --once          # apply one or several disks right now
sudo tpmnt schedule --once --timezone "+08:00"      # all scheduled disks; override the zone
```

Each tick computes the current wall-clock time in the chosen zone (named zones are resolved through
the **system tzdata**, no bundled database) and acts:

- **inside the window** → power the disk **up** (`cryptsetup open` via TPM2 → mount), idempotently.
- **outside the window** → power it **down** via the same data-safe sequence as `power`.

**Power-off never breaks data transfer.** It only ever does a *clean* unmount — never `-f`/`-l`. If
the disk is busy (an in-flight copy, a process holding the mount), tpmnt waits a **grace of 10% of
the on-window**, re-checking each tick. If the transfer finishes within the grace, it powers off
then; if the grace elapses and the disk is *still* in use — or the next on-window has begun, or the
disk was brought up manually — tpmnt **defers** (leaves it up) rather than forcing it off, until the
next cycle.

## AI-native interface

Every command supports:

- `--json` — structured result object (devices, uuids, token ids, mountpoints, fingerprints).
- `--plan` — print the ordered JSON command plan and **exit without touching anything**.
- `--dry-run` — compute changes, apply nothing.
- `--debug` / `-v` — line-delimited JSON trace of every external command (argv, exit, stdout,
  stderr, duration_ms).
- `--non-interactive` / `--yes` — never prompt; pass the existing passphrase via `$PASSWORD` or
  `--passphrase-file`.
- Stable machine-readable error taxonomy (`E_NOT_LUKS2`, `E_NO_TPM`, `E_NO_FALLBACK_KEYSLOT`,
  `E_NO_BACKUP`, …) with documented exit codes — never silent.

```sh
# Preview exactly what `apply` would do, as JSON, changing nothing:
sudo tpmnt apply --plan
```

## Commands

| Command | Purpose |
|---|---|
| `tpmnt init <device>` | Greenfield whole-disk init: partition → LUKS2 → keys → escrow → TPM2 → fs → register + mount. Safe-by-default, every step bypassable. `--explain` lists all defaults. |
| `tpmnt enroll <device>` | Back up the LUKS2 header, then enroll a TPM2 token via `systemd-cryptenroll`. Refuses TPM-only setups that have no passphrase fallback. |
| `tpmnt apply` | Idempotently reconcile crypttab + the mount backend (fstab or systemd `.mount`) to the TOML. |
| `tpmnt status` | Per disk: LUKS2? TPM2 token? crypttab entry? mounted? Plus environment detection. |
| `tpmnt dashboard` | Fancy, TUI-style panels of every disk's tpmnt-managed state (encryption posture, fallback-key lockout risk, mount, cold-standby power). Same JSON as `status` under `--json`. |
| `tpmnt migrate` | On a new machine: re-enroll the **local** TPM for each disk (unlocked via its portable passphrase), then rebuild crypttab/fstab. |
| `tpmnt rollback <device>` | Restore the backed-up header and revert tpmnt's config edits. |
| `tpmnt mount-remote <name>` | Mount a remote decrypted dir over sshfs via a self-healing systemd --user unit, with optional ProxyJump bastions. |
| `tpmnt umount-remote <name>` | Stop+disable the unit and unmount. |
| `tpmnt power <name>` | Spin a disk down now: unmount → `cryptsetup close` → power off the backing disk. |
| `tpmnt schedule <name…>` | Apply a disk's daily on/off window now: power **up** inside it, **down** outside. Never force-unmounts a busy disk (waits 10% of the window, then defers). `--timezone` overrides the configured zone; `--once` does a single tick. |
| `tpmnt print-config` | Emit the equivalent TOML for reproducible re-apply. |

### What "migrate" actually migrates

TPM2-sealed secrets are **bound to the machine's TPM and cannot move**. What you carry between
machines is the **declarative TOML**; on the new host `tpmnt migrate` re-enrolls the local TPM
after unlocking each disk via its passphrase/recovery keyslot. That keyslot is the portable trust
root and tpmnt refuses to remove it.

## Safety model

- **Header backup before every keyslot change** (`cryptsetup luksHeaderBackup`), restorable with
  `tpmnt rollback`.
- **Never TPM-only by force**: enrollment is refused unless a non-TPM fallback keyslot exists.
- **Loud warnings** on weak policies (PCR-only with no PIN — see `SECURITY.md`).
- **Idempotent + reversible**: re-running `apply` is a no-op; every edited file gets a `.bak`.
- LUKS1, missing TPM, and unparseable configs fail with explicit error codes, never silently.

## Self-test

`scripts/selftest.sh` builds a throwaway loopback LUKS2 container, enrolls the **host TPM**, and
proves an end-to-end **cold unlock with no passphrase** plus mount, idempotency, dry-run safety,
rollback, status correctness, and the LUKS1 rejection path. Sealed blobs live in the loopback
header, so the real TPM is never modified.

```sh
cargo build
sudo -E env BIN="$PWD/target/debug/tpmnt" bash scripts/selftest.sh       # Phase A: 26 passed
sudo -E env BIN="$PWD/target/debug/tpmnt" bash scripts/selftest-init.sh  # Phase B: 38 passed
BIN="$PWD/target/debug/tpmnt" bash scripts/selftest-mount.sh             # Phase C: 29 passed
```

`selftest-init.sh` builds a blank loopback "disk", runs a full `init` (GPT + LUKS2 + auto
passphrase + recovery key + TPM2 + xfs + age escrow + mount), proves cold unlock and an
independent recovery-key open, and checks every guard + bypass. `selftest-mount.sh` stands up
throwaway local sshd servers (with and without an sftp Subsystem, plus bastions) and validates
direct/jump/multi-hop mounts, the sftp fallback, self-heal, and the error taxonomy — no root, no
real LAN.

## Packaging

Releases are produced by CI (`.github/workflows/release.yml`): every push builds the
cross-platform binaries and publishes them to the rolling `edge` **pre-release**; pushing a
`v*` tag publishes a stable **release** with `.deb` and `.rpm` packages attached. To reproduce
locally:

```sh
./target/release/tpmnt gen-man man                      # regenerate man/tpmnt.1
cargo build --release --target x86_64-unknown-linux-musl # fully static, dependency-free binary
cargo install cargo-deb && cargo deb                     # build an installable .deb
```

Distro-repository recipes (COPR, PPA, AUR, Nix) live under [`packaging/`](packaging/), one
subdirectory per ecosystem with its own build + publish instructions.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
