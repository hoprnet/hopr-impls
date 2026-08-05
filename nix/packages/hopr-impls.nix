# hopr-impls.nix - hopr-impls workspace package definitions
#
# Defines all variants of the hopr-impls workspace for different platforms.
# hopr-impls is a virtual Cargo workspace of Rust crates implementing the
# hopr-lib API traits.

{
  lib,
  builders,
  sources,
  hoprImplsCrateInfo,
  rev,
  nixLib,
}:

let
  # Common build arguments for hopr-impls variants
  mkHoprImplsBuildArgs =
    { src, depsSrc }:
    {
      inherit src depsSrc rev;
      inherit (hoprImplsCrateInfo) pname version;
      cargoToml = ./../../Cargo.toml;
    };

  localArgs = mkHoprImplsBuildArgs {
    src = sources.main;
    depsSrc = sources.deps;
  };

  mkHoprImplsPlatformPackages =
    platform:
    let
      name = "lib-hopr-impls-${platform}";
    in
    {
      "${name}" = builders.${platform}.callPackage nixLib.mkRustLibrary localArgs;
    }
    // lib.optionalAttrs (lib.hasSuffix "-linux" platform) {
      "${name}-dev" = builders.${platform}.callPackage nixLib.mkRustLibrary (
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
  lib-hopr-impls = builders.local.callPackage nixLib.mkRustLibrary localArgs;

  clippy = builders.local.callPackage nixLib.mkRustLibrary (
    localArgs
    // {
      runClippy = true;
    }
  );
}
// hoprImplsPlatformPackages
