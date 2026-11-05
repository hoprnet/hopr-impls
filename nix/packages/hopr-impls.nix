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
  builders,
  sources,
  rev,
  nixLib,
  craneLib,
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

  mkHoprImplsPlatformPackage = platform: {
    "lib-hopr-impls-${platform}" = builders.${platform}.callPackage nixLib.mkRustPackage localArgs;
  };

  # Run the doc and doctest checks over all features, like clippy does.
  allFeaturesArgs = localArgs // {
    cargoExtraArgs = "--workspace --all-features";
  };

  # mkRustPackage has no doc or deny mode (only mkRustLibrary does, and it needs a
  # root package), so run them as a test derivation with a replaced check phase.
  mkCheck =
    checkPhase:
    (builders.local.callPackage nixLib.mkRustPackage (allFeaturesArgs // { runTests = true; }))
    .overrideAttrs
      (_: {
        inherit checkPhase;
      });

  hoprImplsPlatformPackages = builtins.foldl' (a: b: a // b) { } (
    map mkHoprImplsPlatformPackage [
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

  # Rustdoc with warnings denied.
  doc = mkCheck ''
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
  '';

  # nextest does not run doctests.
  test-doc = mkCheck ''
    cargo test --doc --workspace --all-features
  '';

  # cargo deny compiles nothing, so it needs no dependency build. Advisories are
  # covered by `nix run .#audit`, which needs network access.
  deny = craneLib.cargoDeny {
    pname = "hopr-impls";
    version = "0.0.0";
    src = sources.main;
    cargoDenyChecks = "bans licenses sources";
  };
}
// hoprImplsPlatformPackages
