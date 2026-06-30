# tpmnt security model

tpmnt automates LUKS2 + TPM2 auto-unlock. Auto-unlock is a deliberate trade of *convenience* for
*a weaker threat model* than a passphrase you type. This document states exactly what you get.

## The portable trust root (always preserved)

Every disk tpmnt touches keeps at least one **non-TPM keyslot** (a passphrase or recovery key).
tpmnt **refuses to enroll** a TPM token if removing the last non-TPM keyslot would leave the
volume TPM-only (`E_NO_FALLBACK_KEYSLOT`). This guarantees:

- you can always open the volume on a dead/cleared/replaced TPM, and
- you can re-enroll on a new machine (`tpmnt migrate`), because TPM secrets are machine-bound and
  cannot be copied.

**Back this keyslot up off-machine.** It is the only thing that survives a motherboard failure.

## PCR / PIN trade-offs

A TPM unseals the LUKS key only when its policy is satisfied. Two knobs control how strong that
policy is:

| Configuration | Convenience | Resistance to attack | Notes |
|---|---|---|---|
| **TPM-only** (`pcrs = []`, no PIN) | Highest (silent boot) | **Weakest** | The TPM releases the key to *anything* that asks. An attacker who steals the drive **and** the machine, or who boots a malicious OS, can have the TPM unseal the key. tpmnt prints a loud warning for this. |
| **PCR-bound** (`pcrs = [7]`, or `[7,14]`) | High | Medium | The key is released only when measured boot state matches. PCR 7 = Secure Boot state; PCR 14 = MOK/shim. Defeats casual "boot another OS" attacks, but PCR values can sometimes be replayed and break on legitimate firmware/bootloader updates (you must re-enroll). |
| **PIN** (`with_pin = true`) | Lower (type a PIN at boot) | **Strongest** | Adds a knowledge factor. The TPM rate-limits PIN attempts in hardware, so a short PIN is meaningfully strong. Recommended for laptops and any disk holding sensitive data. |
| **PCR + PIN** | Lower | Strongest | Belt and suspenders. |

### Recommendations

- **Data disks on a server you physically control:** PCR-bound (`[7]`) is a reasonable default.
- **Laptops / anything portable / sensitive:** use `with_pin = true` (optionally + PCRs).
- **Never ship TPM-only to production** without understanding that the key is released on demand.
  This is why tpmnt warns loudly and records the warning in `--json` output.

Further reading: oddlama, *Bypassing disk encryption with TPM2 unlock*
(https://oddlama.org/blog/bypassing-disk-encryption-with-tpm2-unlock/).

## What tpmnt does to stay safe

- **Header backup before any keyslot change** (`cryptsetup luksHeaderBackup`); `tpmnt rollback`
  restores it.
- **Idempotent, reversible config edits**: crypttab/fstab/unit edits are tagged and `.bak`'d; a
  re-run is a no-op.
- **No silent failures**: LUKS1, missing TPM, weak policy, and bad config each map to a stable,
  documented error/warning code.
- **Secrets are never written to the trace.** `--debug` records command argv, exit, and stderr,
  but passphrases are passed via environment/stdin and are not logged.

## Key escrow model (`tpmnt init`)

`tpmnt init` auto-generates the LUKS key material, so it must also guarantee that material is
recoverable — an auto-generated key that is never captured is unrecoverable on TPM loss. The model:

- **Always two non-TPM keyslots by default:** a strong auto-generated passphrase (diceware ≥256-bit
  or base64, `--key-format`) **and** a separate printable recovery key. Either opens the volume
  independently of the TPM.
- **A key bundle** (passphrase + recovery key + UUID + fingerprints) is written to the configured
  `key_backup` directory as `0600`, and can additionally be encrypted to one or more escrow
  targets: `--escrow age:<pubkey>`, `--escrow gpg:<recipient>`, or `--escrow pass:<store-path>`.
  Encryption is delegated to those trusted tools; tpmnt never rolls its own.
- **The "never finish without a backed-up key" guarantee:** in auto-generated-key mode, `init`
  **refuses to complete** (`E_BACKUP_REFUSED`) unless the bundle was captured by at least one
  target — a written escrow file, or `--emit-secrets` to a `--json` stream the operator captures.
  If an *explicit* escrow target fails, `init` aborts with `E_ESCROW_FAILED` and closes the mapping
  rather than leaving an unbacked-up, mounted volume. Opt out only with `--i-understand-no-backup`.
- **Secrets at rest:** the plaintext bundle and keyfiles are `0600`; keyfiles are generated in a
  private `0700` tmpfs dir (`/dev/shm` when available) and removed when `init` exits. Secrets appear
  in `--json` only with the explicit `--emit-secrets` opt-in; otherwise only fingerprints/locations.

**Copy at least one escrow bundle off-machine.** The escrow dir lives on the same host as the disk.

## Remote mounts over SSH (`tpmnt mount-remote`)

`mount-remote` only ever touches a directory the remote host has **already decrypted** — the LUKS
key never leaves the machine that holds the disk. Transport is `sshfs`, so:

- **Traffic is SSH-encrypted end-to-end** between this client and the final target. A LAN bastion
  added with `--jump` (SSH ProxyJump) only **forwards the already-encrypted stream**: it never sees
  the plaintext data and never sees any LUKS key or passphrase.
- The per-mount unit is a **systemd `--user` service** (no root, no `fstab`), self-healing via
  `Restart=on-failure` + sshfs `reconnect`.
- `~/.ssh/config` is honored; an alias's own `ProxyJump` is not overridden unless `--jump` is given.
  Reachability is checked with `BatchMode`/`ConnectTimeout` so a preview never hangs.

## Power profiles (`cold-standby` auto power-off)

A `cold-standby` disk is spun down after an idle window by **unmounting it and running
`cryptsetup close`** before powering the platters off. Dropping the dm-crypt mapping is a security
*improvement*, not just a power saving: once closed, the volume key for that disk is **evicted from
kernel memory** and the disk returns to **ciphertext-at-rest**. A powered-down cold-standby disk
therefore exposes no plaintext data and holds no usable key — it must be TPM/passphrase-unlocked
again on the next access. Idleness is judged from real block-I/O counters (not atime), and the disk
is mounted `noatime`, so reads never silently keep an archival disk awake. `always-on` disks are
never closed by tpmnt.

## Boot-time caveat (root vs. data disks)

On Debian/Ubuntu with `initramfs-tools`, `tpm2-device=` is ignored for the **root** disk during
early boot — use `dracut` if you want TPM auto-unlock of root. **Secondary/data disks are
unaffected**: they unlock post-boot via `crypttab` regardless of initramfs flavor. `tpmnt status`
reports your initramfs and `tpmnt apply` warns when this applies.

## Reporting

This is pre-1.0 software that manipulates disk encryption. Review the planned command output with
`--plan` before running against real disks, and keep your recovery key off-machine.
