# AGENTS.md

## Checks before a push

1. Run `nix develop -c true` once in each new worktree. It installs the pre-commit and pre-push hooks. Without it, commits skip
   `.pre-commit-config.yaml` and a format failure reaches CI.
2. Run `nix fmt`. CI runs treefmt with `--fail-on-change`, and it also formats `README.md`.
3. Run `cargo clippy --workspace --all-targets`, with and without `--no-default-features` for crates that have features.
4. Run `cargo shear` and `cargo machete`.
5. Bump the crate version in the PR that changes it, then `cargo update -p <crate>`. Never run a bare `cargo update`.

## Releases

`hopr-network-graph` and `hopr-ct-full-network` are pinned by edge-client and hoprd, which can be on a different `hopr-api` major than
`main`. Before pinning a downstream to a branch, follow the `hopr-release` skill and compare the `hopr-api` majors. A mismatch needs a
backport onto the matching release.
