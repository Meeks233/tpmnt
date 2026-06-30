#!/usr/bin/env bash
# Build the tpmnt source tarball, a vendored-crates tarball, and an SRPM that
# mock/COPR can build fully offline. Run from a checkout of the tag you want to
# package (the version is read from packaging/copr/tpmnt.spec).
#
#   packaging/copr/make-srpm.sh            # build into ./build
#   packaging/copr/make-srpm.sh --srpm     # also run rpmbuild -bs to emit an SRPM
#
# Requirements (run on a normal networked machine, NOT inside mock):
#   cargo, tar, xz, and for --srpm: rpmbuild + the spec's BuildRequires available
#   only at SRPM *build* time is not needed — rpmbuild -bs just packs the sources.
#
# COPR usage: point a "Custom" source build at this script (it has network), or
# upload the resulting SRPM via COPR's "Upload" build method.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
spec="$here/tpmnt.spec"
name=tpmnt
version="$(rpmspec -q --qf '%{version}\n' "$spec" 2>/dev/null | head -n1 \
  || grep -oP '^Version:\s*\K\S+' "$spec")"

out="${1:-$root/build}"
[ "${1:-}" = "--srpm" ] && out="$root/build"
mkdir -p "$out"

echo ">> packaging $name-$version"

# 1. Pristine source tarball laid out as %{name}-%{version}/ (matches Source0).
git -C "$root" archive --format=tar --prefix="$name-$version/" HEAD \
  | gzip -9 > "$out/$name-$version.tar.gz"

# 2. Vendor every crate dependency into a tarball (matches Source1).
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
tar -xf "$out/$name-$version.tar.gz" -C "$tmp"
( cd "$tmp/$name-$version" && cargo vendor --locked vendor >/dev/null )
tar -C "$tmp/$name-$version" -cJf "$out/$name-$version-vendor.tar.xz" vendor

echo ">> wrote:"
echo "   $out/$name-$version.tar.gz"
echo "   $out/$name-$version-vendor.tar.xz"

if [ "${1:-}" = "--srpm" ]; then
  rpmbuild -bs "$spec" \
    --define "_sourcedir $out" \
    --define "_srcrpmdir $out"
  echo ">> SRPM in $out/"
fi
