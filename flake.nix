{
  description = "radish - a radicle client and node in Zig";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    zig-overlay = {
      url = "github:mitchellh/zig-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, zig-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        zig = zig-overlay.packages.${system}.master;
      in
      {
        devShells.default = pkgs.mkShell {
          # git: used by storage tests to build repos in radish's clone layout.
          # radicle-node provides `rad`/`radicle-node` for integration tests
          # against the real reference implementation.
          packages = [ zig pkgs.git pkgs.radicle-node ];
        };

        packages.default = pkgs.stdenv.mkDerivation {
          pname = "radish";
          version = "0.0.0";
          src = ./.;
          nativeBuildInputs = [ zig ];
          XDG_CACHE_HOME = "$TMPDIR/zig-cache";
          buildPhase = ''
            zig build -Doptimize=ReleaseSafe --prefix $out
          '';
          dontInstall = true;
        };
      });
}
