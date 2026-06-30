#!/usr/bin/env bash
# Build a signed Debian *source* package for upload to a Launchpad PPA.
#
# Launchpad builders have no network, so this vendors every crate into the
# upstream orig tarball; debian/rules then builds with `cargo --offline`.
#
#   packaging/ppa/build-source.sh             # build source pkg into ./build
#   packaging/ppa/build-source.sh noble jammy # rebuild changelog per series
#
# Requirements: cargo, dpkg-dev, debhelper, devscripts (debuild), and a GPG key
# matching the Maintainer in debian/changelog (for the upload signature).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
name=tpmnt
version="$(dpkg-parsechangelog -l "$here/debian/changelog" -S Version 2>/dev/null \
  | sed 's/-[^-]*$//' || grep -oP '\(\K[0-9.]+' "$here/debian/changelog" | head -n1)"

out="$root/build"
rm -rf "$out/$name-$version"
mkdir -p "$out"
work="$out/$name-$version"

echo ">> exporting $name $version"
git -C "$root" archive --format=tar --prefix="$name-$version/" HEAD | tar -x -C "$out"

echo ">> vendoring crates (offline build)"
(
  cd "$work"
  mkdir -p .cargo
  cargo vendor --locked vendor > .cargo/config.toml
)

echo ">> packing orig tarball"
tar -C "$out" --exclude="$name-$version/debian" \
  -czf "$out/${name}_${version}.orig.tar.gz" "$name-$version"

echo ">> overlaying debian/"
cp -r "$here/debian" "$work/debian"

echo ">> building source package"
(
  cd "$work"
  # -S source only, -sa include orig, -d skip build-dep check on non-Debian hosts.
  debuild -S -sa -d
)

echo
echo ">> source package in $out/"
echo "   upload with:  dput ppa:meeks/tpmnt $out/${name}_${version}-*_source.changes"
