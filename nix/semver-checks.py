"""Check released APIs, with Git baselines for crates awaiting their first release."""

import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request


def workspace_packages(cargo, root):
    result = subprocess.run(
        [
            cargo,
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(root / "Cargo.toml"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    members = set(metadata["workspace_members"])
    library_kinds = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}
    return [
        package
        for package in metadata["packages"]
        if package["id"] in members
        and package.get("publish") != []
        and any(
            library_kinds.intersection(target["kind"]) for target in package["targets"]
        )
    ]


def is_published(name):
    # Follow the crates.io sparse-index layout. Only 404 means no published baseline;
    # registry outages, authentication errors and network failures must fail CI.
    name = name.lower()
    if len(name) <= 2:
        path = f"{len(name)}/{name}"
    elif len(name) == 3:
        path = f"3/{name[0]}/{name}"
    else:
        path = f"{name[:2]}/{name[2:4]}/{name}"
    request = urllib.request.Request(
        f"https://index.crates.io/{path}",
        headers={"User-Agent": "hopr-impls-semver-checks"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30):
            return True
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise


def baseline_packages(cargo, git, revision, root):
    if subprocess.run(
        [git, "cat-file", "-e", f"{revision}^{{commit}}"], capture_output=True
    ).returncode:
        subprocess.run(
            [git, "fetch", "--no-tags", "--depth=1", "origin", revision], check=True
        )
    archive = subprocess.run(
        [git, "archive", "--format=tar", revision], check=True, capture_output=True
    )
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as source:
        # Nix/pre-commit configuration can contain absolute store symlinks; those are
        # not source files and are unnecessary for reading the baseline manifests.
        source.extractall(
            root,
            members=[entry for entry in source if entry.isfile() or entry.isdir()],
            filter="data",
        )
    return {package["name"] for package in workspace_packages(cargo, root)}


def check_workspace(checker, cargo, git, baseline_rev, root):
    packages = workspace_packages(cargo, root)
    published = []
    unpublished = []
    for package in packages:
        (published if is_published(package["name"]) else unpublished).append(
            package["name"]
        )

    if published:
        subprocess.run(
            [checker, *[arg for name in published for arg in ("--package", name)]],
            check=True,
        )

    if unpublished:
        with tempfile.TemporaryDirectory(prefix="hopr-semver-baseline-") as directory:
            baseline_root = Path(directory)
            previous = baseline_packages(cargo, git, baseline_rev, baseline_root)
            existing = []
            for name in unpublished:
                if name in previous:
                    existing.append(name)
                else:
                    print(
                        f"First release: {name}; no earlier API exists in crates.io or {baseline_rev}",
                        flush=True,
                    )
            if existing:
                subprocess.run(
                    [
                        checker,
                        "--baseline-root",
                        str(baseline_root),
                        *[arg for name in existing for arg in ("--package", name)],
                    ],
                    check=True,
                )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checker", required=True)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--git", default="git")
    parser.add_argument(
        "--baseline-rev", default=os.environ.get("SEMVER_BASE_REV", "origin/main")
    )
    args = parser.parse_args()
    try:
        check_workspace(
            args.checker, args.cargo, args.git, args.baseline_rev, Path.cwd()
        )
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr, file=sys.stderr)
        return error.returncode if error.returncode > 0 else 1
    except (OSError, ValueError, urllib.error.URLError, tarfile.TarError) as error:
        print(f"Semver baseline discovery failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
