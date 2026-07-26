"""Group-readable detection, with an allowlist for known-benign groups.

A file readable by a group other than the user's own primary group means
other accounts in that group can read it. This is lower severity than
world-readable (it's a bounded set of accounts, not literally everyone),
so it's classified MEDIUM rather than HIGH - unless the group matches a
known-benign pattern (e.g. some platforms use unusual default groups that
aren't actually a meaningful exposure), in which case it's suppressed or
downgraded.
"""

from __future__ import annotations

import platform
import stat
from dataclasses import dataclass
from importlib import resources

from janus_sec.checks.context import FileContext
from janus_sec.checks.identity import (
    current_primary_gid,
    groupname_for_gid,
    username_for_uid,
)
from janus_sec.models import CheckType, Confidence, Finding, FilesystemType, RiskLevel

try:
    import tomllib  # Python 3.11+, standard library
except ModuleNotFoundError:
    import tomli as tomllib  # Python 3.10 fallback


@dataclass(frozen=True, slots=True)
class AllowlistPattern:
    group: str
    action: str  # "suppress" | "downgrade_to_low"
    os_name: str | None = None  # matches platform.system().lower(), e.g. "linux"


def load_allowlist() -> list[AllowlistPattern]:
    """Load the built-in allowlist bundled inside the package."""
    toml_file = resources.files("janus_sec.checks").joinpath("allowlist.toml")
    data = tomllib.loads(toml_file.read_text(encoding="utf-8"))
    return [
        AllowlistPattern(
            group=p["group"],
            action=p.get("action", "suppress"),
            os_name=p.get("os"),
        )
        for p in data.get("patterns", [])
    ]


def _matches_allowlist(
    group_name: str, patterns: list[AllowlistPattern]
) -> AllowlistPattern | None:
    current_os = platform.system().lower()
    for pattern in patterns:
        if pattern.group != group_name:
            continue
        if pattern.os_name is not None and pattern.os_name != current_os:
            continue
        return pattern
    return None


def check(
    ctx: FileContext,
    filesystem_type: FilesystemType,
    allowlist: list[AllowlistPattern] | None = None,
) -> Finding | None:
    if ctx.resolved_stat is None:
        return None

    mode = ctx.resolved_stat.st_mode
    if not (mode & stat.S_IRGRP):
        return None  # group can't even read it - nothing to flag

    file_gid = ctx.resolved_stat.st_gid
    my_gid = current_primary_gid()
    if file_gid == my_gid:
        return None  # it's your own primary group - not a concern

    group_name = groupname_for_gid(file_gid)
    matched = _matches_allowlist(group_name, allowlist or [])

    if matched is not None and matched.action == "suppress":
        return None

    risk_level = RiskLevel.MEDIUM
    confidence = Confidence.HIGH
    reason = (
        f"This file is readable by group '{group_name}', which is not your "
        "primary group. Other accounts in that group can read this file."
    )
    if matched is not None and matched.action == "downgrade_to_low":
        risk_level = RiskLevel.LOW
        confidence = Confidence.LOW
        reason += (
            f" (Downgraded: '{group_name}' matches a known pattern for this "
            "platform, but confidence isn't high enough to fully suppress.)"
        )

    owner_only = oct(stat.S_IMODE(mode) & stat.S_IRWXU)[2:].zfill(3)
    return Finding(
        path=str(ctx.path),
        current_mode_octal=oct(stat.S_IMODE(mode))[2:].zfill(3),
        current_mode_human=stat.filemode(mode),
        risk_level=risk_level,
        check_type=CheckType.GROUP_READABLE,
        reason=reason,
        owner=username_for_uid(ctx.resolved_stat.st_uid),
        expected_owner=username_for_uid(ctx.resolved_stat.st_uid),
        is_symlink=ctx.is_symlink,
        filesystem_type=filesystem_type,
        confidence=confidence,
        suggested_fix_octal=owner_only,
    )