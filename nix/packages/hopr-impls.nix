# hopr-impls.nix - hopr-impls workspace package definitions
#
# Defines all variants of the hopr-impls workspace for different platforms.
# hopr-impls is a *virtual* Cargo workspace (the root manifest has no [package]
# stanza) of Rust crates implementing the hopr-lib API traits.
#
# Because there is no root package, nix-lib's `mkRustLibrary` (which builds a
# single `-p <pname> --lib`) cannot be used — it would resolve an empty pname
# and fail with "no packages selected". Instead we build every workspace member
# via `mkRustPackage` with `prependPackageName = false` and an explicit
# `--workspace` selector, mirroring the multi-crate sibling repos.

{
  lib,
  builders,
  sources,
  rev,
  nixLib,
}:

let
  cargoToml = ./../../Cargo.toml;

  # Build the whole workspace rather than a single package.
  mkWorkspaceBuildArgs =
    { src, depsSrc }:
    {
      inherit
        src
        depsSrc
        rev
        cargoToml
        ;
      prependPackageName = false;
      cargoExtraArgs = "--workspace";
    };

  localArgs = mkWorkspaceBuildArgs {
    src = sources.main;
    depsSrc = sources.deps;
  };

  mkHoprImplsPlatformPackages =
    platform:
    let
      name = "lib-hopr-impls-${platform}";
    in
    {
      "${name}" = builders.${platform}.callPackage nixLib.mkRustPackage localArgs;
    }
    // lib.optionalAttrs (lib.hasSuffix "-linux" platform) {
      "${name}-dev" = builders.${platform}.callPackage nixLib.mkRustPackage (
        localArgs // { CARGO_PROFILE = "dev"; }
      );
    };

  hoprImplsPlatformPackages = builtins.foldl' (a: b: a // b) { } (
    map mkHoprImplsPlatformPackages [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ]
  );
in
{
  lib-hopr-impls = builders.local.callPackage nixLib.mkRustPackage localArgs;

  clippy = builders.local.callPackage nixLib.mkRustPackage (
    localArgs
    // {
      runClippy = true;
      cargoExtraArgs = "--workspace --all-targets --all-features";
    }
  );
}
// hoprImplsPlatformPackages
