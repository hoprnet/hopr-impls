"""Baseline-policy tests; no registry access or Rust compilation required."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

spec = importlib.util.spec_from_file_location(
    "semver_checks", Path(__file__).with_name("semver-checks.py")
)
semver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(semver)


class BaselinePolicyTests(unittest.TestCase):
    def test_baseline_archive_extracts_sources_without_store_symlinks(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as source:
            contents = b"[workspace]\nmembers = []\n"
            manifest = tarfile.TarInfo("Cargo.toml")
            manifest.size = len(contents)
            source.addfile(manifest, io.BytesIO(contents))
            link = tarfile.TarInfo(".pre-commit-config.yaml")
            link.type = tarfile.SYMTYPE
            link.linkname = "/nix/store/example-config"
            source.addfile(link)

        def read_packages(cargo, root):
            self.assertEqual((root / "Cargo.toml").read_bytes(), contents)
            self.assertFalse((root / ".pre-commit-config.yaml").is_symlink())
            return [{"name": "existing"}]

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(semver, "workspace_packages", side_effect=read_packages),
            patch.object(
                semver.subprocess,
                "run",
                side_effect=[
                    subprocess.CompletedProcess([], 0),
                    subprocess.CompletedProcess([], 0, archive.getvalue()),
                ],
            ),
        ):
            self.assertEqual(
                semver.baseline_packages("cargo", "git", "base", Path(directory)),
                {"existing"},
            )

    def test_released_new_and_unpublished_existing_crates_use_their_own_baselines(self):
        packages = [
            {"name": name} for name in ["released", "new", "unpublished-existing"]
        ]
        with (
            patch.object(semver, "workspace_packages", return_value=packages),
            patch.object(
                semver, "is_published", side_effect=lambda name: name == "released"
            ),
            patch.object(
                semver,
                "baseline_packages",
                return_value={"released", "unpublished-existing"},
            ),
            patch.object(semver.subprocess, "run") as run,
            patch("builtins.print") as output,
        ):
            semver.check_workspace("checker", "cargo", "git", "base-sha", Path.cwd())
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[0].args[0], ["checker", "--package", "released"]
        )
        git_check = run.call_args_list[1].args[0]
        self.assertEqual(git_check[:2], ["checker", "--baseline-root"])
        self.assertEqual(git_check[3:], ["--package", "unpublished-existing"])
        self.assertIn("First release: new;", output.call_args.args[0])

    def test_a_new_crate_is_checked_automatically_after_its_first_publication(self):
        with (
            patch.object(semver, "workspace_packages", return_value=[{"name": "new"}]),
            patch.object(semver, "is_published", return_value=True),
            patch.object(semver, "baseline_packages") as baseline,
            patch.object(semver.subprocess, "run") as run,
        ):
            semver.check_workspace("checker", "cargo", "git", "base-sha", Path.cwd())
        run.assert_called_once_with(["checker", "--package", "new"], check=True)
        baseline.assert_not_called()

    def test_only_registry_404_means_no_published_baseline(self):
        for status in [401, 403, 429, 500, 503]:
            with (
                self.subTest(status=status),
                patch.object(
                    semver.urllib.request,
                    "urlopen",
                    side_effect=urllib.error.HTTPError(
                        "url", status, "error", {}, None
                    ),
                ),
            ):
                with self.assertRaises(urllib.error.HTTPError):
                    semver.is_published("example")
        with patch.object(
            semver.urllib.request,
            "urlopen",
            side_effect=urllib.error.HTTPError("url", 404, "missing", {}, None),
        ):
            self.assertFalse(semver.is_published("example"))
        with patch.object(
            semver.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("offline"),
        ):
            with self.assertRaises(urllib.error.URLError):
                semver.is_published("example")

    def test_sparse_index_paths_match_crate_name_lengths(self):
        for name, suffix in [
            ("a", "1/a"),
            ("ab", "2/ab"),
            ("abc", "3/a/abc"),
            ("example", "ex/am/example"),
        ]:
            with (
                self.subTest(name=name),
                patch.object(
                    semver.urllib.request, "urlopen", return_value=MagicMock()
                ) as request,
            ):
                self.assertTrue(semver.is_published(name))
                self.assertEqual(
                    request.call_args.args[0].full_url,
                    f"https://index.crates.io/{suffix}",
                )

    def test_only_publishable_workspace_libraries_are_selected(self):
        def package(name, kind="lib", publish=None):
            return {
                "id": name,
                "name": name,
                "publish": publish,
                "targets": [{"kind": [kind]}],
            }

        metadata = {
            "workspace_members": ["lib", "private", "binary"],
            "packages": [
                package("lib"),
                package("private", publish=[]),
                package("binary", kind="bin"),
                package("dependency"),
            ],
        }
        with patch.object(
            semver.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps(metadata)),
        ):
            self.assertEqual(
                [p["name"] for p in semver.workspace_packages("cargo", Path.cwd())],
                ["lib"],
            )

    def test_semver_violations_are_not_swallowed(self):
        with (
            patch.object(
                semver, "workspace_packages", return_value=[{"name": "released"}]
            ),
            patch.object(semver, "is_published", return_value=True),
            patch.object(
                semver.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(100, "checker"),
            ),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                semver.check_workspace(
                    "checker", "cargo", "git", "base-sha", Path.cwd()
                )


if __name__ == "__main__":
    unittest.main()
