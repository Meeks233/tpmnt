# tpmnt

**Unified, declarative, AI-native CLI for LUKS2 + TPM2 "enroll once → auto-decrypt → auto-mount".**

The Linux disk-encryption stack is split across `systemd-cryptenroll` (register a TPM),
`crypttab` (decrypt), and `fstab` (mount) — with no single tool that does all three from one
declarative, portable config. `tpmnt` fills that gap. It is an **orchestrator**: it shells out to
the trusted system tools (`cryptsetup`, `systemd-cryptenroll`, `systemd-cryptsetup`) and owns the
declarative config + idempotent reconciliation around them. It never reimplements cryptography.

> Status: **Phases A–D complete.** `enroll`, `apply`, `status`, `migrate`, `rollback` (A);
> whole-disk `init` with key escrow (B); client-side `mount-remote` over sshfs with SSH ProxyJump
> (C); cold-standby power + scheduling (D). **v0.2.0** adds two things: **auto-discovery** — a disk
> is tracked by its LUKS UUID, so tpmnt finds it and keeps it accessible wherever it moves
> (local ↔ remote ↔ another remote) with decryption always on the trusted local host; and a
> **mandatory PIN + unified key vault** — one PIN gates TPM2 unlock *and* a single, portable,
> TPM-independent recovery file holding every disk's key. Verified by automated self-tests and a
> real end-to-end loopback lifecycle (cold TPM2 unlock, PIN toggle, vault round-trip).

## Why

| Tool | enroll | decrypt | mount | declarative | migrate |
|---|:---:|:---:|:---:|:---:|:---:|
| `systemd-cryptenroll` | ✅ | ❌ | ❌ | ❌ | ❌ |
| `crypttab` / `fstab` | — | ✅ | ✅ | partial | ❌ |
| **tpmnt** | ✅ | ✅ | ✅ | ✅ (one TOML) | ✅ |

## Install

`tpmnt` is an orchestrator that shells out to standard system tools (cryptsetup, systemd, hdparm,
gnupg, …), so it installs as a proper **`.deb` / `.rpm`** that pulls those tools in as dependencies
— nothing to wire up by hand. Every stable `v*` tag attaches packages for `x86_64` and `aarch64`;
each push also refreshes a rolling [`edge` pre-release](https://github.com/Meeks233/tpmnt/releases/tag/edge).

### Package repository (apt / dnf) — easiest

Signed apt and dnf/zypper repositories are hosted on GitHub Pages (stable channel,
`amd64` + `arm64`). Add the source once, then update through your package manager.

**Debian / Ubuntu:**

```sh
curl -fsSL https://meeks233.github.io/tpmnt/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/tpmnt.gpg
echo "deb [signed-by=/usr/share/keyrings/tpmnt.gpg] https://meeks233.github.io/tpmnt stable main" | sudo tee /etc/apt/sources.list.d/tpmnt.list
sudo apt update && sudo apt install tpmnt
```

**Fedora / RHEL / openSUSE:**

```sh
sudo dnf config-manager --add-repo https://meeks233.github.io/tpmnt/tpmnt.repo
sudo dnf install tpmnt
# openSUSE: sudo zypper addrepo https://meeks233.github.io/tpmnt/tpmnt.repo && sudo zypper install tpmnt
```

### Debian / Ubuntu (.deb) — recommended

```sh
arch=$(dpkg --print-architecture); case "$arch" in
  amd64) t=x86_64-unknown-linux-gnu ;; arm64) t=aarch64-unknown-linux-gnu ;;
esac
curl -fsSLO "https://github.com/Meeks233/tpmnt/releases/latest/download/tpmnt-${t}.deb"
sudo apt install "./tpmnt-${t}.deb"   # apt resolves cryptsetup/hdparm/gnupg/… automatically
```

### Fedora / RHEL / openSUSE (.rpm) — recommended

```sh
arch=$(uname -m); case "$arch" in
  x86_64) t=x86_64-unknown-linux-gnu ;; aarch64) t=aarch64-unknown-linux-gnu ;;
esac
curl -fsSLO "https://github.com/Meeks233/tpmnt/releases/latest/download/tpmnt-${t}.rpm"
sudo dnf install "./tpmnt-${t}.rpm"   # dnf resolves the tool dependencies automatically
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

tpmnt is an **orchestrator**: the binary links nothing but libc. At runtime it shells out to
standard system tools — and the `.deb`/`.rpm` **declare them as package dependencies**, so your
package manager pulls them in. None are obscure or version-fragile:

- **always (Depends):** `cryptsetup`, `systemd` (`systemd-cryptenroll` / `systemd-cryptsetup`), `util-linux`, `gdisk`, `btrfs-progs`, `sudo`, a TPM2 at `/dev/tpmrm0`
- **cold-standby spindown (Depends):** `hdparm` (SATA ATA-standby); `sg3_utils` for USB-bridged disks (Recommends)
- **mandatory PIN vault (Depends):** `gnupg`
- **other filesystems (Recommends):** `xfsprogs`, `e2fsprogs`
- **remote disks / `mount-remote` (Recommends):** `openssh-client`, `sshfs` + `fuse3`, `nbd-client`; `qemu-utils` (Suggests) only on a host that *serves* its disk to others
- **power-off method / discovery:** `udisks2`, `parted`, `procps`; `blkid` (locate disks by UUID)
- **PIN vault:** `gpg` (encrypts the unified recovery vault under your PIN)
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
# Seals the key bundle to this host's TPM (systemd-creds) in key_backup AND writes an
# age-encrypted offline copy; refuses to finish in auto mode unless at least one backup
# target was captured (E_BACKUP_REFUSED otherwise).
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

## Key storage & recovery

Auto-generated LUKS keys are **never written to disk in cleartext by default**. The local key
bundle (primary passphrase + recovery key) is sealed with **`systemd-creds`**, which binds it to
this host's **TPM2** (falling back to the root-only host key when no TPM is present). Decryption
therefore requires the same machine *and* root — a convenient local credential with nothing to
remember. Portable `--escrow age:/gpg:/pass:` copies are for the disaster case where the host
itself is lost, which a host-bound seal deliberately can't cover.

```sh
# Prove the key is retrievable (no secret printed):
sudo tpmnt recover mycache

# Reveal the key material (root + this host's TPM required to unseal):
sudo tpmnt recover mycache --show

# TPM auto-unlock broke after a firmware update? Open the mapping manually with the stored key:
sudo tpmnt recover mycache --open
```

Recovery uses the stored **passphrase**, which opens the LUKS keyslot directly. Point
`--from creds:<file>` / `--from plaintext:<file>` / `--from vault` at an alternate bundle. To keep
the old cleartext behavior, `tpmnt init --local-plaintext --i-understand-plaintext-keys`.

### The unified PIN vault (TPM-independent recovery)

The host-sealed bundle above is convenient but, by design, unreadable if the **TPM state changes**
(firmware update, PCR drift) or the host is lost. The **PIN vault** is the complementary escrow: a
**single file** holding **every** managed disk's key bundle, encrypted under a **PIN** you choose —
so a broken TPM never means lost data. Type the PIN, get the raw LUKS key back.

- **One file, all keys** — `key_backup/vault.gpg`, keyed by disk name.
- **Not plaintext, not rainbow-table-able** — encrypted with `gpg --symmetric` using a
  **salted + iterated** s2k (the random salt defeats precomputed tables; the high iteration count
  slows brute force) and AES-256. tpmnt never implements crypto — it delegates to `gpg`, chosen over
  `age -p` because `gpg` takes the PIN from a file descriptor and so works in scripted/headless
  recovery, not only from a tty.
- **Written automatically** whenever a PIN is in play (`--with-pin`, or `[defaults].require_pin`), by
  both `init` and `adopt`.

```sh
# TPM can't unlock a disk anymore? Recover the raw key with just your PIN:
sudo tpmnt recover mycache --from vault --show
# Even the default recover auto-falls back to the vault when the TPM seal can't be read:
sudo TPMNT_PIN=… tpmnt recover mycache --show      # note on stderr: "recovering from the PIN vault"

# Inspect / maintain the vault (never reveals a key):
tpmnt vault list                     # which disks are stored (proof-of-retrievability)
tpmnt vault rekey --new-pin-file f   # change the PIN (decrypt with old, re-encrypt with new)
tpmnt vault sync                     # (re)build the vault from the local sealed bundles
```

On a **new machine**, `tpmnt migrate` uses the vault too: one PIN unlocks *every* disk for TPM
re-enrollment, instead of a per-disk `$PASSWORD`.

### Mandatory PIN

A PIN can be required both **at creation** and **after encryption** — `systemd-cryptenroll` can
re-enroll an existing LUKS2 TPM2 token at any time (it wipes the TPM2 slot and enrolls a fresh one,
authorized by the disk's managed passphrase). tpmnt exposes both entry points:

```sh
# 1. At creation — one disk, or globally as policy:
sudo tpmnt init /dev/sdb --with-pin …               # this disk needs a PIN
# [defaults] require_pin = true  in tpmnt.toml       # every init/adopt from now on requires one

# 2. After encryption — flip an already-encrypted disk, per-disk or in bulk:
sudo tpmnt pin enable mycache                        # add a PIN to one managed disk
sudo tpmnt pin enable --all                          # every managed disk
sudo tpmnt pin enable --global                       # + set [defaults].require_pin for future disks
sudo tpmnt pin disable mycache                       # remove it again (re-enroll without a PIN)
```

`pin enable` re-enrolls the TPM2 token **with** a PIN, writes `tpm2-pin=yes` into crypttab so
systemd prompts for it at unlock, and drops the key into the PIN vault. The **same PIN** gates the
TPM and encrypts the vault, so there's only one thing to remember. Remote managed disks are handled
identically — their ciphertext is forwarded here (NBD-over-SSH) so the re-enrollment runs locally.
The PIN comes from `--pin-file`, `$TPMNT_PIN`, or a prompt. (For a **root** disk, rebuild the
initramfs so the PIN prompt applies at boot.)

## Taking a disk offline vs. destroying it

Two lifecycle verbs, both **data-safe** (neither ever formats or overwrites the ciphertext):

```sh
# Temporarily detach — you'll bring it back later (e.g. to change the PSU):
sudo tpmnt offline mycache             # grace unmount + close; fails if busy
sudo tpmnt offline mycache --force     # lazily detach a busy mount (umount -l)

# Permanently retire — remove all local management, keep the encrypted data:
sudo tpmnt destroy mycache --yes       # --yes required, even for automation
```

`offline` leaves the config/crypttab/fstab in place, so a reboot, `tpmnt recover --open`, or the
next scheduled spinup brings the disk right back. `destroy` purges the local footprint (config
entry, crypttab/fstab lines, systemd units, sealed/escrow key bundles, header backup, state) but
**deliberately does not format the device** — LUKS ciphertext is safe at rest. It warns if it's
about to delete the only copy of the key (no offline `--escrow` present). Both refuse a busy mount
without `--force`, and both operate on remote disks over SSH transparently.

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

## Multiple remotes, one control plane

A single machine can drive disks that physically live on **several** SSH-reachable hosts. You
register each host once as a `[[remote]]`, then tag any `[[disk]]` with `remote = "<name>"`. That
disk's `uuid`/`device` are interpreted **on that host**, and tpmnt runs its inspection over SSH —
so `status`/`dashboard` cover local and remote disks in one view without you tracking where each
one sits. Which machine a disk is on is surfaced **only in the dashboard**; ordinary disk
operations don't require knowing it.

```toml
# Two controlled machines and their disks, in the same tpmnt.toml:
[[remote]]
name = "nas"
host = "alice@192.168.5.10"

[[remote]]
name = "shed"
host = "bob@10.0.0.9:2222"
jump = ["gw@bastion"]          # ProxyJump, comma-separate or repeat for multi-hop
identity = "~/.ssh/id_ed25519"

[[disk]]
name = "archive"
uuid = "…"                      # this UUID is resolved on `nas`
mountpoint = "/mnt/archive"
remote = "nas"
power_profile = "cold-standby"
```

```sh
tpmnt remote                 # list remotes and the disks remembered on each
tpmnt remote nas --probe     # + one SSH reachability round-trip per remote
tpmnt dashboard              # local + remote disks together; remote ones show ⇄ host
tpmnt status --plan          # see the exact ssh-wrapped commands, run nothing
```

A `remote` name that matches no `[[remote]]` is treated as **local** (a typo can't silently ssh
nowhere). Local-only concepts (crypttab, monitor units, `/sys` power state) report `null` for a
remote disk rather than a misleading `false`; its mount and mapper state are read live over SSH.

## Threat model: what "managed" means

tpmnt only claims to **manage** a disk when it can keep its central promise:

> the LUKS key was generated or imported **on this host**, and decryption happens **only on this
> host** — never on a remote.

Two independent facts decide it, and `status`/`dashboard` show the verdict per disk:

1. **Provenance** — is there a tpmnt key bundle for this disk in the local key store? tpmnt writes
   that bundle only when it generated the key (`init`) or rotated one in (`adopt`). Its presence is
   the proof the key is *ours*, not a foreign key we merely forward.
2. **Decrypt site** — does `cryptsetup open` run here? Always true for a local disk; for a remote
   disk, true only when a ciphertext **transport** is configured (its raw LUKS blocks are forwarded
   here and opened locally).

A disk that fails either test is reported as **unmanaged**, with a machine-readable reason:

| Verdict | Meaning |
|---|---|
| `managed` | key local, decryption local — tpmnt owns it end to end |
| `foreign-key` | decrypts locally but no locally-generated key on record — tpmnt won't hold a foreign key |
| `remote-decrypt` | a remote disk with no ciphertext transport — tpmnt **forwards blocks only** and never decrypts it |

```sh
tpmnt status            # MANAGED column: managed / foreign-key / remote-decrypt
tpmnt dashboard         # a `manage` row per disk + a managed/unmanaged summary
```

### Taking ownership: `tpmnt adopt`

Convert one or more existing disks (local **or** remote) to managed by rotating in a fresh,
locally-generated key. You supply the disk's current key once; every crypto step runs on this host:

```sh
# Local disk: add a managed key + recovery, enroll this host's TPM2, seal the bundle.
tpmnt adopt mydisk --old-key-file /path/to/oldkey

# Several disks at once, and remove the old key so ONLY tpmnt-owned keys remain.
echo -n "$OLDKEY" | tpmnt adopt arc backups --old-key-stdin --rotate-out-old

# Preview the exact command sequence, touch nothing:
tpmnt adopt arc --old-key-file oldkey --plan
```

For a **remote** disk, adopt forwards the disk's ciphertext to this host over **NBD-over-SSH**,
opens it locally, adds the managed key, then detaches — so the key and every decryption stay local.
It also records the disk's steady-state `transport` in the config.

### Remote ciphertext transport (performance)

A managed remote disk never decrypts on the remote. Instead its **raw LUKS ciphertext** is exported
and decrypted here — the industry pattern for untrusted remote storage (cf. `ragnar`,
"LUKS-over-NBD"). Because only ciphertext crosses the wire, confidentiality holds even over an
untrusted link; block-level access also makes it **far faster than sshfs** (local page cache,
readahead, filesystem run locally) and gains TRIM/discard, which SFTP cannot express.

| `transport` | When | How |
|---|---|---|
| `nbd` (default) | WAN / untrusted path | `qemu-nbd` serves ciphertext on the remote loopback; an `ssh -L` tunnel carries it; `nbd-client` attaches `/dev/nbdN`. The tunnel adds integrity + hides access patterns. |
| `nvme-tcp` | fast, trusted LAN | Lowest overhead / highest small-block IOPS (beats iSCSI); `nvme connect -t tcp` imports the remote `nvmet` export, then LUKS opens locally. |

```toml
[[disk]]
name = "archive"
uuid = "…"
mountpoint = "/mnt/archive"
remote = "nas"
transport = "nbd"     # forward ciphertext here, decrypt locally → managed
```

## Auto-discovery: a disk is where its UUID is

A disk is identified by its stable **LUKS2 UUID**, never by a device path or a host — because both
change when you physically move it. Pull an archive drive out of the NAS and plug it into your
laptop, or shuttle it from one remote to another: **you don't have to reconfigure anything**.
`tpmnt discover` rebinds the config to wherever a disk's UUID actually is — always keeping decryption
on **this** trusted host:

- found **locally** → `remote`/`transport` cleared, resolved via the stable `/dev/disk/by-uuid/…`;
- found on a **remote** → `remote`/`device` re-pointed, `transport = nbd` so its ciphertext is
  forwarded here and `cryptsetup open` still runs locally.

```sh
tpmnt discover              # re-locate every disk and rebind if it moved (idempotent)
tpmnt discover archive      # just one; aliases: `scan`, `locate`
tpmnt discover --plan       # probe read-only, show where each disk is, change nothing
```

**Lazy, batched probing — no server flooding.** Discovery does **not** proactively poll every remote.
It inventories **this** host once (a single `blkid`), and a disk pinned to a remote keeps its
last-known binding untrusted-but-unprobed. Only when a disk we expected *here* has genuinely vanished
does it fall back to a **single global sweep** — exactly one `blkid` per remote, all UUIDs compared at
once — instead of one lookup per (disk, remote). N disks across M remotes therefore cost at most
`1 + M` probes, never `N × M`.

Bringing a disk online is a **pull**, not a background watcher: `tpmnt connect [name…]` (alias `up`)
tries each disk at its last-known endpoint first, and only if that endpoint doesn't answer triggers
the one global sweep to find where it moved, then opens + mounts it here. A disk that isn't found
anywhere is left untouched (it's just unplugged); `connect` rejects only when it's reachable nowhere.

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
| `tpmnt adopt <name…>` | Take ownership of existing disk(s): rotate in a fresh locally-generated managed key (auth'd by the old key), enroll this host's TPM2, seal the bundle, optionally `--rotate-out-old`. Remote disks are forwarded here via NBD-over-SSH so keys/decryption stay local. Flips the disk to **managed**. |
| `tpmnt recover <name>` | Authenticate (root + this host's TPM) and retrieve a disk's generated key. `--show` reveals it; `--open` unlocks the mapping now. Sources: the sealed store (default), `--from vault` (PIN-encrypted), or `--from creds:/plaintext:<file>` — and the default **auto-falls back to the PIN vault** when the TPM seal can't be read. |
| `tpmnt pin enable\|disable [<name>]` | Turn a mandatory unlock PIN on/off for already-encrypted disk(s) by re-enrolling the TPM2 token. Scope: one disk, `--all` managed disks, or `--global` (also sets/clears `[defaults].require_pin`). Reconciles `tpm2-pin=yes` in crypttab and stores the key in the PIN vault. |
| `tpmnt vault list\|rekey\|sync` | Manage the unified PIN vault (the TPM-independent recovery store): `list` its disks (no secrets), `rekey` its PIN, or `sync` it from the local sealed bundles. |
| `tpmnt discover [name…]` | Re-locate each disk by its LUKS UUID and rebind the config if it moved (local ↔ remote ↔ another remote). Runs automatically inside `apply`. Aliases: `scan`, `locate`. |
| `tpmnt offline <name>` | Temporarily detach a disk: grace unmount → `cryptsetup close` (ciphertext at rest). Data **and** config are kept, so it can be brought back later. `--force` lazily detaches a busy mount. Remote disks are torn down over SSH. |
| `tpmnt destroy <name>` | Permanently drop a disk's local management (config, crypttab/fstab, units, key bundles, header backup). Requires `--yes` (even for AI). **Does not format** — the LUKS ciphertext is left intact; reformat later if you need the space. |
| `tpmnt enroll <device>` | Back up the LUKS2 header, then enroll a TPM2 token via `systemd-cryptenroll`. Refuses TPM-only setups that have no passphrase fallback. |
| `tpmnt apply` | Idempotently reconcile crypttab + the mount backend (fstab or systemd `.mount`) to the TOML. |
| `tpmnt connect [name…]` | Pull disk(s) online **on demand** (alias `up`): try each at its last-known endpoint first (forward + open + mount), and only if that endpoint doesn't answer fall back to a **single global discovery sweep** (one `blkid` per remote, compared at once — never a per-remote storm), rebind, and retry. Rejects only if the disk is nowhere reachable. |
| `tpmnt status` | Per disk: LUKS2? TPM2 token? crypttab entry? mounted? Plus environment detection. |
| `tpmnt dashboard` | Fancy, TUI-style panels of every disk's tpmnt-managed state (encryption posture, fallback-key lockout risk, mount, cold-standby power). Same JSON as `status` under `--json`. |
| `tpmnt migrate` | On a new machine: re-enroll the **local** TPM for each disk, then rebuild crypttab/fstab. With a PIN vault present, **one PIN unlocks every disk** (`--pin-file`); otherwise each falls back to its portable passphrase via `$PASSWORD`. |
| `tpmnt rollback <device>` | Restore the backed-up header and revert tpmnt's config edits. |
| `tpmnt remote [name]` | List the SSH remotes this machine controls and the disks on each. `--probe` reports per-remote reachability. |
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
./target/release/tpmnt gen-man man                        # regenerate man/tpmnt.1 (committed)
cargo install cargo-deb && cargo deb                      # build an installable .deb
cargo install cargo-generate-rpm && cargo generate-rpm --auto-req disabled   # build an .rpm
```

Distro-repository recipes (COPR, PPA, AUR, Nix) live under [`packaging/`](packaging/), one
subdirectory per ecosystem with its own build + publish instructions.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
