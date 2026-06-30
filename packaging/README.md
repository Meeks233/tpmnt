# Packaging

Distro packaging for tpmnt. The prebuilt static-musl binary and the `.deb`/`.rpm`
attached to each [GitHub release](https://github.com/Meeks233/tpmnt/releases) cover
most users; these recipes target the native repositories of each distro.

| Dir | Target | Install command |
|---|---|---|
| [`copr/`](copr/) | Fedora / RHEL / openSUSE (dnf) | `dnf copr enable meeks/tpmnt && dnf install tpmnt` |
| [`ppa/`](ppa/) | Ubuntu (Launchpad PPA) | `add-apt-repository ppa:meeks/tpmnt && apt install tpmnt` |
| [`aur/`](aur/) | Arch Linux (AUR) | `paru -S tpmnt` (or `tpmnt-bin`) |
| [`nix/`](nix/) | Nix / NixOS | `nix profile install github:Meeks233/tpmnt` |

Each subdirectory has its own README with build and publish instructions. tpmnt
is a Rust program, so the two network-less builders (COPR/mock and Launchpad)
vendor crate dependencies and build offline; AUR and Nix use their native crate
fetching (`cargo` and `cargoLock` respectively).

## Common runtime dependencies

tpmnt orchestrates system tools rather than linking libraries. Per-distro package
names for the tools it shells out to:

| Role | Fedora | Ubuntu/Debian | Arch | Nix |
|---|---|---|---|---|
| LUKS | `cryptsetup` | `cryptsetup` | `cryptsetup` | `cryptsetup` |
| GPT (`sgdisk`) | `gdisk` | `gdisk` | `gptfdisk` | `gptfdisk` |
| remote mount | `fuse-sshfs` | `sshfs` | `sshfs` | `sshfs` |
| key escrow (opt) | `age` | `age` | `age` | `age` |
| power profiles (opt) | `hdparm` | `hdparm` | `hdparm` | `hdparm` |
