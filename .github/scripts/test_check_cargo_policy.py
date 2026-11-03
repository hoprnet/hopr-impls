"""Tests for the Cargo dependency policy check."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_cargo_policy as policy


def violations_for(manifest: str) -> list[str]:
    """Return the messages reported for a manifest given as TOML text."""
    return [
        v.message for v in policy.find_violations("Cargo.toml", tomllib.loads(manifest))
    ]


def git_init(path: Path) -> None:
    subprocess.run(["git", "-C", str(path), "init", "-q"], check=True)


class PatchSectionTest(unittest.TestCase):
    def test_crates_io_patch_with_git_branch_is_rejected(self) -> None:
        messages = violations_for(
            """
[patch.crates-io]
blokli-client = { git = "https://github.com/hoprnet/blokli-client", branch = "feature/x" }
"""
        )
        self.assertEqual(len(messages), 1)
        self.assertIn("[patch.crates-io]", messages[0])
        self.assertIn("not allowed", messages[0])

    def test_patch_for_git_source_is_rejected(self) -> None:
        messages = violations_for(
            """
[patch."https://github.com/hoprnet/blokli-client"]
blokli-client = { path = "../blokli-client" }
"""
        )
        self.assertEqual(len(messages), 1)
        self.assertIn('[patch."https://github.com/hoprnet/blokli-client"]', messages[0])

    def test_patch_using_a_registry_version_is_still_rejected(self) -> None:
        messages = violations_for(
            """
[patch.crates-io]
serde = { version = "1.0.0" }
"""
        )
        self.assertEqual(len(messages), 1)
        self.assertIn("[patch.crates-io]", messages[0])


class GitDependencyTest(unittest.TestCase):
    def assert_rejected(
        self, manifest: str, section: str, name: str = "blokli-client"
    ) -> None:
        messages = violations_for(manifest)
        self.assertEqual(len(messages), 1, messages)
        self.assertIn(section, messages[0])
        self.assertIn(f"'{name}'", messages[0])
        self.assertIn("git source", messages[0])

    def test_dependency_pinned_to_revision_is_rejected(self) -> None:
        self.assert_rejected(
            """
[dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client", rev = "0123456" }
""",
            "[dependencies]",
        )

    def test_dependency_pinned_to_tag_is_rejected(self) -> None:
        self.assert_rejected(
            """
[dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client", tag = "v0.5.0" }
""",
            "[dependencies]",
        )

    def test_dependency_with_branch_is_rejected(self) -> None:
        self.assert_rejected(
            """
[dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client", branch = "main" }
""",
            "[dependencies]",
        )

    def test_dependency_sub_table_is_rejected(self) -> None:
        self.assert_rejected(
            """
[dependencies.blokli-client]
git = "https://github.com/hoprnet/blokli-client"
""",
            "[dependencies]",
        )

    def test_development_dependency_is_rejected(self) -> None:
        self.assert_rejected(
            """
[dev-dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client" }
""",
            "[dev-dependencies]",
        )

    def test_build_dependency_is_rejected(self) -> None:
        self.assert_rejected(
            """
[build-dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client" }
""",
            "[build-dependencies]",
        )

    def test_workspace_dependency_is_rejected(self) -> None:
        self.assert_rejected(
            """
[workspace.dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client" }
""",
            "[workspace.dependencies]",
        )

    def test_target_specific_dependency_is_rejected(self) -> None:
        self.assert_rejected(
            """
[target.'cfg(unix)'.dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client" }
""",
            '[target."cfg(unix)".dependencies]',
        )

    def test_target_triple_build_dependency_is_rejected(self) -> None:
        self.assert_rejected(
            """
[target.x86_64-unknown-linux-gnu.build-dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client" }
""",
            "[target.x86_64-unknown-linux-gnu.build-dependencies]",
        )

    def test_underscore_development_dependency_alias_is_rejected(self) -> None:
        self.assert_rejected(
            """
[dev_dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client" }
""",
            "[dev_dependencies]",
        )

    def test_underscore_build_dependency_alias_is_rejected(self) -> None:
        self.assert_rejected(
            """
[target.'cfg(unix)'.build_dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client" }
""",
            '[target."cfg(unix)".build_dependencies]',
        )

    def test_git_replace_override_is_rejected(self) -> None:
        messages = violations_for(
            """
[replace]
"blokli-client:0.35.0" = { git = "https://github.com/hoprnet/blokli-client" }
"""
        )
        self.assertEqual(len(messages), 1, messages)
        self.assertIn("[replace]", messages[0])
        self.assertIn("'blokli-client:0.35.0'", messages[0])

    def test_path_replace_override_passes(self) -> None:
        messages = violations_for(
            """
[replace]
"blokli-client:0.35.0" = { path = "../blokli-client" }
"""
        )
        self.assertEqual(messages, [])

    def test_every_violation_is_reported(self) -> None:
        messages = violations_for(
            """
[dependencies]
blokli-client = { git = "https://github.com/hoprnet/blokli-client" }

[dev-dependencies]
other-client = { git = "https://github.com/hoprnet/other-client" }

[patch.crates-io]
third-client = { version = "0.1.0" }
"""
        )
        self.assertEqual(len(messages), 3, messages)


class AllowedDependencyTest(unittest.TestCase):
    def test_registry_dependencies_pass(self) -> None:
        messages = violations_for(
            """
[package]
name = "hopr-impls"
version = "0.1.0"

[dependencies]
serde = "1.0.44"
tokio = { version = "1.53.1", features = ["macros"] }
thiserror = { version = "2.0.0", optional = true }

[dev-dependencies]
tokio-test = "0.4.4"

[build-dependencies]
cc = "1.0.0"
"""
        )
        self.assertEqual(messages, [])

    def test_path_dependencies_pass(self) -> None:
        messages = violations_for(
            """
[dependencies]
hopr-internal = { path = "../hopr-internal" }
hopr-versioned = { path = "../hopr-versioned", version = "0.1.0" }
"""
        )
        self.assertEqual(messages, [])

    def test_workspace_inheritance_passes(self) -> None:
        messages = violations_for(
            """
[workspace.dependencies]
serde = "1.0.44"

[dependencies]
serde = { workspace = true }
"""
        )
        self.assertEqual(messages, [])


class ManifestDiscoveryTest(unittest.TestCase):
    def test_only_tracked_manifests_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_init(root)
            (root / "Cargo.toml").write_text(
                '[package]\nname = "root"\n', encoding="utf-8"
            )
            crate = root / "crate"
            crate.mkdir()
            (crate / "Cargo.toml").write_text(
                '[package]\nname = "crate"\n', encoding="utf-8"
            )
            (crate / "ignored.toml").write_text("", encoding="utf-8")
            (root / "untracked").mkdir()
            (root / "untracked" / "Cargo.toml").write_text(
                '[patch.crates-io]\nserde = { version = "1.0.0" }\n', encoding="utf-8"
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "Cargo.toml", "crate"], check=True
            )

            manifests = sorted(
                path.relative_to(root).as_posix()
                for path in policy.tracked_manifests(root)
            )

            self.assertEqual(manifests, ["Cargo.toml", "crate/Cargo.toml"])

    def test_invalid_manifest_manifests_as_violation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_init(root)
            (root / "Cargo.toml").write_text("[patch.crates-io\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "Cargo.toml"], check=True)

            violations = policy.check_manifest(root / "Cargo.toml", root)

            self.assertEqual(len(violations), 1)
            self.assertIn("cannot be parsed", violations[0].message)


class MainTest(unittest.TestCase):
    def test_main_fails_and_reports_the_offending_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_init(root)
            (root / "Cargo.toml").write_text(
                '[package]\nname = "root"\n\n[patch.crates-io]\nserde = { version = "1.0.0" }\n',
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", str(root), "add", "Cargo.toml"], check=True)

            self.assertEqual(policy.main(root), 1)

    def test_main_checks_the_root_it_is_given(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_init(root)
            (root / "Cargo.toml").write_text(
                '[dependencies]\nserde = { git = "https://github.com/serde-rs/serde" }\n',
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", str(root), "add", "Cargo.toml"], check=True)

            script = Path(__file__).resolve().parent / "check_cargo_policy.py"
            result = subprocess.run(
                [sys.executable, str(script), str(root)], capture_output=True, text=True
            )

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn(
                "Cargo.toml: [dependencies] dependency 'serde' uses a git source",
                result.stdout,
            )

    def test_main_passes_without_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_init(root)

            self.assertEqual(policy.main(root), 0)


if __name__ == "__main__":
    unittest.main()
