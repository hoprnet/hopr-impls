"""Reject Cargo ``[patch]`` sections and git dependencies in tracked manifests.

Protected branches must only resolve dependencies from a registry or from a
versioned in-repository path. Cargo ``[patch]`` overrides and git dependencies
pull unreleased or externally-controlled code into published crates, so they
are rejected here regardless of the registry, branch, tag or revision used.

See https://github.com/hoprnet/hopr-devops/issues/345.

Requires Python 3.11 or newer for the standard library ``tomllib``.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

MANIFEST_NAME = "Cargo.toml"

# Tables Cargo resolves dependencies from. The same names appear under
# `[workspace]` and under `[target.<cfg>]`.
DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")

GIT_KEY = "git"

BARE_KEY_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


@dataclass(frozen=True)
class Violation:
    """A single manifest declaration that violates the dependency policy."""

    manifest: str
    message: str

    def __str__(self) -> str:
        return f"{self.manifest}: {self.message}"


def tracked_manifests(root: Path) -> list[Path]:
    """Return every ``Cargo.toml`` tracked by git below *root*.

    Only tracked files matter: a policy for protected branches must not be
    influenced by build output or other ignored files in the working tree.
    """
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    names = listing.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    return [root / name for name in names if name and Path(name).name == MANIFEST_NAME]


def section_name(*keys: str) -> str:
    """Render a TOML table path, quoting keys that are not bare, e.g. ``[target."cfg(unix)".dependencies]``."""
    rendered = []
    for key in keys:
        if key and set(key) <= BARE_KEY_CHARACTERS:
            rendered.append(key)
        else:
            rendered.append(f'"{key}"')
    return "[" + ".".join(rendered) + "]"


def patch_sections(manifest: dict[str, Any]) -> Iterator[str]:
    """Yield every declared ``[patch]`` section, e.g. ``[patch.crates-io]``."""
    patch = manifest.get("patch")
    if not isinstance(patch, dict):
        if "patch" in manifest:
            yield "[patch]"
        return
    if not patch:
        yield "[patch]"
        return
    for source in patch:
        yield section_name("patch", source)


def dependency_tables(
    manifest: dict[str, Any],
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(section, dependencies)`` for every table declaring dependencies."""
    for section in DEPENDENCY_SECTIONS:
        table = manifest.get(section)
        if isinstance(table, dict):
            yield section_name(section), table

    workspace = manifest.get("workspace")
    if isinstance(workspace, dict):
        for section in DEPENDENCY_SECTIONS:
            table = workspace.get(section)
            if isinstance(table, dict):
                yield section_name("workspace", section), table

    targets = manifest.get("target")
    if isinstance(targets, dict):
        for target, config in targets.items():
            if not isinstance(config, dict):
                continue
            for section in DEPENDENCY_SECTIONS:
                table = config.get(section)
                if isinstance(table, dict):
                    yield section_name("target", target, section), table


def find_violations(manifest_name: str, manifest: dict[str, Any]) -> list[Violation]:
    """Return every policy violation in an already-parsed manifest."""
    violations = [
        Violation(manifest_name, f"{section} section is not allowed")
        for section in patch_sections(manifest)
    ]

    for section, dependencies in dependency_tables(manifest):
        for name, spec in dependencies.items():
            if isinstance(spec, dict) and GIT_KEY in spec:
                violations.append(
                    Violation(
                        manifest_name,
                        f"{section} dependency '{name}' uses a git source ({spec[GIT_KEY]})",
                    )
                )

    return violations


def check_manifest(path: Path, root: Path) -> list[Violation]:
    """Parse a manifest from disk and return its policy violations."""
    name = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    try:
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        return [Violation(name, f"cannot be parsed: {error}")]
    return find_violations(name, manifest)


def main(root: Path | None = None) -> int:
    """Check every tracked manifest below *root* and report violations."""
    root = root if root is not None else Path(__file__).resolve().parents[2]

    manifests = tracked_manifests(root)
    if not manifests:
        print("No tracked Cargo manifests found; nothing to check.")
        return 0

    violations = [
        violation for manifest in manifests for violation in check_manifest(manifest, root)
    ]
    if not violations:
        print(f"Checked {len(manifests)} Cargo manifest(s): no [patch] sections or git dependencies.")
        return 0

    for violation in violations:
        print(f"::error file={violation.manifest}::{violation.message}")

    print(f"\n{len(violations)} Cargo dependency policy violation(s):")
    for violation in violations:
        print(f"  {violation}")
    print(
        "\nCargo [patch] sections and git dependencies must not reach protected "
        "branches. Depend on a released registry version instead, or drop the "
        "patch once the release contains the change."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
