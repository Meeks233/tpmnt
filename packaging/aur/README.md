# AUR packaging (Arch Linux)

Two packages are provided:

| Dir | AUR name | Builds |
|---|---|---|
| `./` | `tpmnt` | from source via `cargo` (compiles on the user's machine). |
| `tpmnt-bin/` | `tpmnt-bin` | from the prebuilt static **musl** release binary (no Rust toolchain). |

Both install the binary, man page, and licenses; they `conflict`/`provides`
`tpmnt`, so install only one.

## Install (end users)

```sh
# from source:
git clone https://aur.archlinux.org/tpmnt.git && cd tpmnt && makepkg -si
# or prebuilt:
git clone https://aur.archlinux.org/tpmnt-bin.git && cd tpmnt-bin && makepkg -si
```

Or with an AUR helper: `paru -S tpmnt` (or `tpmnt-bin`).

## Publishing / updating (maintainer)

The `sha256sums` are `SKIP` placeholders — pin them before publishing:

```sh
cd packaging/aur            # or packaging/aur/tpmnt-bin
updpkgsums                  # downloads sources, rewrites sha256sums in PKGBUILD
makepkg --printsrcinfo > .SRCINFO
namcap PKGBUILD             # optional lint
```

Then push `PKGBUILD` + `.SRCINFO` to the AUR git remote
(`ssh://aur@aur.archlinux.org/tpmnt.git`). On a new release, bump `pkgver`, reset
`pkgrel=1`, re-run `updpkgsums` and `--printsrcinfo`.
