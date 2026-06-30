# COPR packaging (Fedora / RHEL / openSUSE)

Builds an RPM via [COPR](https://copr.fedorainfracloud.org/). tpmnt is a Rust
program and COPR/mock build roots have **no network**, so the crate dependencies
are vendored ahead of time and the build runs `cargo build --offline`.

## Files

| File | Purpose |
|---|---|
| `tpmnt.spec` | The RPM spec. Builds offline from `Source0` (source) + `Source1` (vendored crates). |
| `make-srpm.sh` | Produces the source tarball, the vendor tarball, and (with `--srpm`) an SRPM. |

## One-time COPR project setup

1. Create a project at <https://copr.fedorainfracloud.org/> (e.g. `meeks/tpmnt`),
   enabling the Fedora / EPEL / openSUSE chroots you want.
2. Add a package using **one** of the two methods below.

### Method A — Custom (recommended, auto-rebuilds on new tags)

COPR's *Custom* source method runs a script **with network** to generate the
SRPM, then builds that SRPM offline in mock. Use this script body:

```sh
git clone --depth 1 --branch "v0.1.0" https://github.com/Meeks233/tpmnt .
dnf install -y cargo rust rpm-build xz
packaging/copr/make-srpm.sh --srpm
mv build/*.src.rpm "$COPR_RESULTDIR" 2>/dev/null || true
```

Set the spec/result glob to `*.src.rpm`. Bump the `--branch` tag per release.

### Method B — Upload an SRPM

On a networked Fedora machine:

```sh
git clone --branch v0.1.0 https://github.com/Meeks233/tpmnt && cd tpmnt
dnf install -y cargo rust rpm-build xz
packaging/copr/make-srpm.sh --srpm        # -> build/tpmnt-0.1.0-1.*.src.rpm
```

Then upload `build/tpmnt-*.src.rpm` via COPR's **Upload** build method (web UI
or `copr-cli build meeks/tpmnt build/tpmnt-*.src.rpm`).

## Install (end users)

```sh
sudo dnf copr enable meeks/tpmnt
sudo dnf install tpmnt
```

## Releasing a new version

1. Bump `Version:` and add a `%changelog` entry in `tpmnt.spec`.
2. Tag the release; re-run Method A (auto) or Method B.
