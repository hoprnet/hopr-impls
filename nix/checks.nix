# checks.nix - CI/CD quality checks
#
# Defines automated checks that run in CI to ensure code quality.
# These checks can also be run locally for pre-push validation.

{
  packages,
  pkgs,
}:

{
  # Rust linting checks
  hopr-impls-clippy = packages.clippy;

  # Rustdoc with warnings denied, doctests, and the cargo-deny policy
  hopr-impls-doc = packages.doc;
  hopr-impls-test-doc = packages.test-doc;
  hopr-impls-deny = packages.deny;

  hopr-impls-semver-policy =
    pkgs.runCommand "semver-policy-tests" { nativeBuildInputs = [ pkgs.python3 ]; }
      ''
        cp ${./semver-checks.py} semver-checks.py
        cp ${./test_semver_checks.py} test_semver_checks.py
        python -m unittest discover -p 'test_semver_checks.py' -v
        touch "$out"
      '';

  # Repository hygiene checks
  pre-commit = packages.pre-commit-check;
}
