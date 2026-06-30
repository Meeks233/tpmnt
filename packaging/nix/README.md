# Nix packaging

The repo is a flake. `packaging/nix/package.nix` is the derivation; the top-level
`flake.nix` builds it from the local checkout (no hashes to maintain).

## Run / install (end users)

```sh
# run without installing:
nix run github:Meeks233/tpmnt -- --help

# install into a profile:
nix profile install github:Meeks233/tpmnt

# pin a release:
nix run github:Meeks233/tpmnt/v0.1.0 -- status
```

The binary is wrapped so `cryptsetup`, `sgdisk` (gptfdisk) and `sshfs` are on its
PATH. `age` / `hdparm` (optional features) are not pulled in; install them
alongside if you use key escrow or power profiles.

## Develop

```sh
nix develop          # shell with cargo, rustc, clippy, rustfmt
cargo build --release
```

## nixpkgs submission

`package.nix` doubles as a nixpkgs template: call it with `src = null` and it
fetches the tagged release via `fetchFromGitHub`. Replace `lib.fakeHash` with the
value `nix build` reports, drop the `src`/`version` arguments to match nixpkgs
conventions (hardcode `version` and the fetch `rev`), and place it at
`pkgs/by-name/tp/tpmnt/package.nix`.
