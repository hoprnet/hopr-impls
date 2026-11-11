# checks.nix - CI/CD quality checks
#
# Defines automated checks that run in CI to ensure code quality.
# These checks can also be run locally for pre-push validation.

{
  packages,
}:

{
  # Rust linting checks
  hopr-impls-clippy = packages.clippy;

  # Rustdoc with warnings denied, doctests, and the cargo-deny policy
  hopr-impls-doc = packages.doc;
  hopr-impls-test-doc = packages.test-doc;
  hopr-impls-deny = packages.deny;

  # Repository hygiene checks
  pre-commit = packages.pre-commit-check;
}
