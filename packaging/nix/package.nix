# tpmnt derivation. Used by the repo's flake.nix (with src = self) and suitable
# as a starting point for a nixpkgs submission (call with src = null to fetch the
# tagged release from GitHub).
{ lib
, rustPlatform
, fetchFromGitHub
, installShellFiles
, makeWrapper
, cryptsetup
, gptfdisk
, sshfs
, src ? null
, version ? "0.1.0"
}:

let
  realSrc =
    if src != null then src
    else fetchFromGitHub {
      owner = "Meeks233";
      repo = "tpmnt";
      rev = "v${version}";
      # `nix build` prints the correct value to paste here on first build.
      hash = lib.fakeHash;
    };
in
rustPlatform.buildRustPackage {
  pname = "tpmnt";
  inherit version;
  src = realSrc;

  cargoLock.lockFile = "${realSrc}/Cargo.lock";

  nativeBuildInputs = [ installShellFiles makeWrapper ];

  # tpmnt's tests need root + a TPM/loopback device; not runnable in the sandbox.
  doCheck = false;

  postInstall = ''
    installManPage man/tpmnt.1
    # tpmnt orchestrates these system tools; put them on its PATH.
    wrapProgram $out/bin/tpmnt \
      --prefix PATH : ${lib.makeBinPath [ cryptsetup gptfdisk sshfs ]}
  '';

  meta = {
    description = "Unified, declarative CLI for LUKS2 + TPM2 enroll-once auto-decrypt and auto-mount";
    homepage = "https://github.com/Meeks233/tpmnt";
    license = with lib.licenses; [ mit asl20 ];
    mainProgram = "tpmnt";
    platforms = lib.platforms.linux;
  };
}
