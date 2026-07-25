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
          # radicle-node provides `rad`, `radicle-node`, `git-remote-rad` for
          # integration tests against the real reference implementation.
          packages = [ zig pkgs.libgit2 pkgs.radicle-node ];
          # build.zig reads these to locate the system libgit2 (optional; without
          # Nix it falls back to default system include/library paths).
          LIBGIT2_INCLUDE = "${pkgs.libgit2.dev}/include";
          LIBGIT2_LIB = "${pkgs.libgit2.lib}/lib";
        };

        packages.default = pkgs.stdenv.mkDerivation {
          pname = "radish";
          version = "0.0.0";
          src = ./.;
          nativeBuildInputs = [ zig ];
          buildInputs = [ pkgs.libgit2 ];
          LIBGIT2_INCLUDE = "${pkgs.libgit2.dev}/include";
          LIBGIT2_LIB = "${pkgs.libgit2.lib}/lib";
          XDG_CACHE_HOME = "$TMPDIR/zig-cache";
          buildPhase = ''
            zig build -Doptimize=ReleaseSafe --prefix $out
          '';
          dontInstall = true;
        };
      });
}
