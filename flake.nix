{
  description = "radish - a radicle client and node in Zig";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    zig-overlay = {
      url = "github:mitchellh/zig-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Source only, never built: build.zig compiles lib/compiler/Maker/Fetch/git.zig
    # as a standalone module, and this branch carries the pack-index CRC32 fix
    # (ziglang/zig#36328) that stock git.zig lacks. Drop once the PR lands.
    zig-src = {
      url = "git+https://codeberg.org/quint/zig-gpu?ref=git-index-crc32";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, zig-overlay, zig-src }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        zig = zig-overlay.packages.${system}.master;
        gitpackFlag = "-Dgitpack=${zig-src}/lib/compiler/Maker/Fetch/git.zig";
      in
      {
        devShells.default = pkgs.mkShell {
          # git: used by storage tests to build repos in radish's clone layout.
          # radicle-node provides `rad`/`radicle-node` for integration tests
          # against the real reference implementation.
          packages = [ zig pkgs.git pkgs.radicle-node ];
          # build.zig falls back to this when -Dgitpack is not passed, so a bare
          # `zig build` in the shell still gets the forked git.zig.
          RADISH_GITPACK = "${zig-src}/lib/compiler/Maker/Fetch/git.zig";
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
