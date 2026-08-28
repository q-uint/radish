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
    # Radicle 2.x, which replaces Noise/TCP with iroh over QUIC. The only peer
    # that speaks what src/quic/ is built for: iroh 1.0.3, raw public keys, and
    # the ALPNs radicle/gossip/1 and radicle/git/1. Kept out of the default
    # devShell so a normal `zig build` never waits on a Rust toolchain; build it
    # on demand with `nix build .#radicle-ng`.
    #
    # The ng branch lives in one remote's namespace rather than on master, hence
    # the ref path. Its nixpkgs is deliberately not followed: it pins its own
    # through crane and rust-overlay.
    radicle-ng = {
      url = "git+https://seed.radicle.dev/rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5?ref=refs/namespaces/z6MkkPvBfjP4bQmco5Dm7UGsX2ruDBieEHi8n9DVJWX5sTEz/refs/heads/ng";
    };
  };

  outputs = { self, nixpkgs, flake-utils, zig-overlay, zig-src, radicle-ng }:
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

        # A radicle 2.x node, to probe src/quic/ against something that actually
        # speaks iroh. Not reached by packages.default.
        packages.radicle-ng = radicle-ng.packages.${system}.default;
      });
}
