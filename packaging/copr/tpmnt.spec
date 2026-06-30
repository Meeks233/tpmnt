# tpmnt — Fedora/RHEL/openSUSE RPM spec for COPR.
#
# tpmnt is a Rust program. COPR/mock build roots have NO network access, so the
# crate dependencies are vendored ahead of time into a second source tarball
# (Source1) and the build runs fully offline. Generate both tarballs + an SRPM
# with `packaging/copr/make-srpm.sh`, then either upload the SRPM to COPR or use
# COPR's "Custom" source method to run that script (see packaging/copr/README.md).

%global debug_package %{nil}

Name:           tpmnt
Version:        0.1.0
Release:        1%{?dist}
Summary:        Unified, declarative CLI for LUKS2 + TPM2 enroll-once auto-decrypt and auto-mount

License:        MIT OR Apache-2.0
URL:            https://github.com/Meeks233/tpmnt
Source0:        %{url}/archive/refs/tags/v%{version}/%{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc

# tpmnt is an orchestrator: at runtime it shells out to these system tools.
Requires:       cryptsetup
Requires:       systemd
Requires:       gdisk
Requires:       fuse-sshfs
Recommends:     age
Recommends:     hdparm

# Linux-only and only the arches we ship release binaries for.
ExclusiveArch:  x86_64 aarch64

%description
tpmnt unifies LUKS2 + TPM2 "enroll once -> auto-decrypt -> auto-mount" behind one
declarative TOML config and an AI-native CLI (--json / --plan / --dry-run). It is
an orchestrator, not a crypto library: it drives cryptsetup, systemd-cryptenroll,
systemd-cryptsetup, sgdisk, mkfs and sshfs, owning the idempotent crypttab/fstab/
systemd-mount reconciliation around them. Features whole-disk init with key escrow,
remote sshfs mounts through SSH jump hosts, and per-disk cold-standby power profiles.

%prep
%autosetup -n %{name}-%{version}
# Unpack the vendored crate registry and pin cargo to it (offline build).
tar -xf %{SOURCE1}
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

%build
cargo build --release --offline --locked

%install
install -Dm0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}
install -Dm0644 man/%{name}.1          %{buildroot}%{_mandir}/man1/%{name}.1

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md SECURITY.md
%{_bindir}/%{name}
%{_mandir}/man1/%{name}.1*

%changelog
* Wed Jul 01 2026 Meeks <shadowblaze_kai@icloud.com> - 0.1.0-1
- Initial COPR package.
