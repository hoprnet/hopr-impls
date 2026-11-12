## Implementations

The crates located in this directory implement the external `hopr-lib` API traits mandatory for proper construction and running of the
`Hopr` instance.

## Semver checks

Run `nix run .#semver-checks` to compare publishable workspace libraries with their crates.io releases. For unpublished libraries, the
checker uses the Git base (`origin/main` locally, the PR base SHA in CI). A library absent from both is reported as a first release: there
is no earlier API to compare. Once published, it automatically uses the registry baseline. Registry/network failures remain errors.

Use `nix run .#semver-checks -- --baseline-rev main` to select another Git base. The baseline-selection regression tests run as the
`hopr-impls-semver-policy` Nix check.
