{
  description = "Unified, declarative CLI for LUKS2 + TPM2 enroll-once auto-decrypt and auto-mount";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = nixpkgs.lib.genAttrs systems;
      version = "0.1.0";
    in
    {
      packages = forAll (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        rec {
          tpmnt = pkgs.callPackage ./packaging/nix/package.nix {
            src = self;
            inherit version;
          };
          default = tpmnt;
        });

      apps = forAll (system: rec {
        tpmnt = {
          type = "app";
          program = "${self.packages.${system}.tpmnt}/bin/tpmnt";
        };
        default = tpmnt;
      });

      devShells = forAll (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.cargo pkgs.rustc pkgs.clippy pkgs.rustfmt ];
          };
        });
    };
}
