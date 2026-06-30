# PPA packaging (Ubuntu / Launchpad)

Builds a Debian **source** package for upload to a [Launchpad PPA](https://launchpad.net/).
tpmnt is a Rust program and Launchpad builders have **no network**, so
`build-source.sh` vendors every crate into the upstream tarball and
`debian/rules` builds with `cargo --offline`.

## Files

| File | Purpose |
|---|---|
| `debian/` | Debian packaging metadata (control, rules, changelog, copyright, source format). |
| `build-source.sh` | Vendors crates, assembles the orig tarball, and runs `debuild -S`. |

## One-time setup

1. Create a PPA on Launchpad (e.g. `ppa:meeks/tpmnt`) and upload your GPG public
   key to Launchpad.
2. Ensure your local GPG key matches the `Maintainer` in `debian/changelog`.

## Build & upload

On a Debian/Ubuntu machine with `dpkg-dev debhelper devscripts cargo rustc`:

```sh
# Edit debian/changelog for the target series (e.g. noble) and version, then:
packaging/ppa/build-source.sh
dput ppa:meeks/tpmnt build/tpmnt_0.1.0-1~ppa1_source.changes
```

To publish for several Ubuntu series, repeat with a per-series changelog entry
(`...~ppa1~noble1`, `...~ppa1~jammy1`, …) — Launchpad requires distinct versions
per series.

## Install (end users)

```sh
sudo add-apt-repository ppa:meeks/tpmnt
sudo apt update
sudo apt install tpmnt
```

> Prefer not to add a PPA? Every stable GitHub release also attaches a standalone
> `.deb` — see the top-level README.
