# Packaging & software-source hosting

This document is the **maintainer-side** guide for the signed apt / dnf repositories
that `tpmnt` publishes to GitHub Pages. End-user install instructions live in the
[README](../README.md#installation).

## How it works

The `pages` job in [`.github/workflows/release.yml`](../.github/workflows/release.yml)
runs **only on stable `v*` tags** (the rolling `edge` channel is deliberately kept out
of the repositories — it stays in the GitHub Release assets). On each stable release it:

1. Downloads the `.deb` and `.rpm` artifacts already built by the `deb` / `rpm` jobs
   (`amd64` + `arm64`).
2. Imports the signing key from repo secrets into a throwaway keyring.
3. Builds an **apt** repo with `reprepro` (signed `Release`/`InRelease`).
4. Signs each `.rpm` (`rpm --addsign`), builds **rpm** repodata with `createrepo_c`,
   and detached-signs `repomd.xml` for `repo_gpgcheck=1`.
5. Assembles the site and **force-pushes** it to the orphan `gh-pages` branch
   (full rebuild every release — simplest and idempotent while the package count is small).

Published layout (served at `https://meeks233.github.io/tpmnt`):

```
/gpg.key            armored public key
/tpmnt.repo         dnf/zypper repo file (baseurl -> /rpm)
/index.html         copy-paste install instructions
/dists/ /pool/      apt repository (root, so the sources.list line needs no subpath)
/rpm/               rpm repository (repodata/ + the .rpm files)
```

## One-time setup (do these once, by hand)

### 1. Generate a dedicated signing key

Use a **dedicated key** for the repository — never a personal identity key. A signing
**subkey** under a repo-specific primary key is ideal so the primary can stay offline.

```sh
# Non-interactive generation of a repo signing key:
gpg --batch --gen-key <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: tpmnt package signing
Name-Email: shadowblaze_kai@icloud.com
Expire-Date: 2y
EOF

gpg --list-secret-keys --keyid-format=long   # note the key id
```

> `%no-protection` creates a passphrase-less key. That's acceptable for a CI-only signing
> key stored in a secret; if you prefer a passphrase, drop that line and set
> `GPG_PASSPHRASE` accordingly.

### 2. Put the key into repo secrets

The CI accepts the private key **armored or base64-of-armored** (it tries base64 first,
then falls back to raw armor). base64 avoids any newline mangling in the secrets UI:

```sh
gpg --export-secret-keys --armor <KEYID> | base64 -w0    # copy this
```

In **Settings → Secrets and variables → Actions**, add:

| Secret            | Value                                                        |
|-------------------|-------------------------------------------------------------|
| `GPG_PRIVATE_KEY` | output of the command above (base64) — or the raw armored block |
| `GPG_PASSPHRASE`  | the key's passphrase, or an **empty string** if it has none |

The default `GITHUB_TOKEN` is used to push `gh-pages`; no extra token needed.

### 3. Enable GitHub Pages

In **Settings → Pages**, set **Source = Deploy from a branch**, **Branch = `gh-pages` / `(root)`**.
The `gh-pages` branch is created by the first successful stable release run, so either push
a `v*` tag first or create an empty `gh-pages` branch and re-run.

## Releasing

Push a stable tag as usual — the existing pipeline builds packages, publishes the Release,
then the `pages` job rebuilds and republishes the repositories:

```sh
git tag v0.3.1 && git push origin v0.3.1
```

Because the branch is force-pushed each time, `gh-pages` always reflects exactly the
latest stable release's packages; old versions are not retained (full-rebuild trade-off —
acceptable while the package set is small).

## Key rotation

1. Generate a new key (step 1) and update `GPG_PRIVATE_KEY` / `GPG_PASSPHRASE` (step 2).
2. Re-run the latest stable release (re-run the workflow or re-push the tag). The new
   `gpg.key` is republished with the repo.
3. Users re-import the key (the README commands are idempotent; apt users re-run the
   `gpg --dearmor` line, dnf users just `dnf clean all`).

Rotate before expiry (`Expire-Date` above) or immediately if the secret is ever exposed.

## Notes / gotchas

- Signing runs entirely in one workflow step so the `gpg-agent` passphrase cache (preset
  via `gpg-preset-passphrase`) survives across the apt and rpm signing calls.
- Users are pointed at `signed-by=` keyrings — **never** the deprecated `apt-key`.
- The throwaway `GNUPGHOME` is deleted before the site is published; no key material
  ever lands in the `gh-pages` output.
