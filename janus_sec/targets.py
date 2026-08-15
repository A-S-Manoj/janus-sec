"""Default scan targets, grouped by credential area.

Each group has an `expected_root` - the directory these files are
supposed to live inside. This is used by the symlink-escape check to
detect a target that's secretly a symlink pointing outside where it
belongs.

`files` lists the specific filenames expected directly inside that root.
A missing file (e.g. no ~/.aws/credentials because you don't use AWS) is
simply skipped by the scanner - not an error.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class TargetGroup:
    name: str
    expected_root: Path
    files: tuple[str, ...]


def default_targets() -> list[TargetGroup]:
    home = Path.home()
    return [
        TargetGroup(
            name="ssh",
            expected_root=home / ".ssh",
            files=(
                "id_rsa",
                "id_ed25519",
                "id_ecdsa",
                "config",
                "authorized_keys",
                "known_hosts",
            ),
        ),
        TargetGroup(
            name="aws",
            expected_root=home / ".aws",
            files=("credentials", "config"),
        ),
        TargetGroup(
            name="kube",
            expected_root=home / ".kube",
            files=("config",),
        ),
        TargetGroup(
            name="npm",
            expected_root=home,
            files=(".npmrc",),
        ),
        TargetGroup(
            name="git",
            expected_root=home,
            files=(".git-credentials",),
        ),
        TargetGroup(
            name="docker",
            expected_root=home / ".docker",
            files=("config.json",),
        ),
        TargetGroup(
            name="gcloud",
            expected_root=home / ".config" / "gcloud",
            files=("credentials.db", "access_tokens.db"),
        ),
        TargetGroup(
            name="azure",
            expected_root=home / ".azure",
            files=("accessTokens.json", "msal_token_cache.json"),
        ),
        TargetGroup(
            name="gh",
            expected_root=home / ".config" / "gh",
            files=("hosts.yml",),
        ),
        TargetGroup(
            name="pypirc",
            expected_root=home,
            files=(".pypirc",),
        ),
        TargetGroup(
            name="netrc",
            expected_root=home,
            files=(".netrc",),
        ),
        TargetGroup(
            name="vault",
            expected_root=home,
            files=(".vault-token",),
        ),
    ]
