"""Applies permission fixes safely.

Two layers: apply_fix() does the actual, careful chmod operation on a raw
path+mode. apply_fix_for_finding() is a thin wrapper for callers (TUI, CLI)
that are working with a Finding from a scan rather than a raw path.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from janus_sec.models import Finding


@dataclass(frozen=True, slots=True)
class FixResult:
    path: str
    success: bool
    before_mode_octal: str | None
    after_mode_octal: str | None
    error: str | None


def _mode_octal(mode: int) -> str:
    return oct(stat.S_IMODE(mode))[2:].zfill(3)


def apply_fix(path: Path, target_mode: int) -> FixResult:
    """Apply a chmod fix to one file, safely.

    Re-checks the file's current state immediately before fixing (not
    relying on stale data from an earlier scan), since the file may have
    changed in the time between when it was scanned and when the fix is
    actually applied.
    """
    try:
        current_stat = os.lstat(path)
    except FileNotFoundError:
        return FixResult(
            path=str(path), success=False,
            before_mode_octal=None, after_mode_octal=None,
            error="file no longer exists",
        )
    except PermissionError:
        return FixResult(
            path=str(path), success=False,
            before_mode_octal=None, after_mode_octal=None,
            error="permission denied reading current state",
        )

    before_octal = _mode_octal(current_stat.st_mode)

    try:
        # Last-instant re-check: os.chmod follows symlinks, so if the path
        # has been swapped for a symlink since the lstat above, the chmod
        # would silently change whatever the symlink points at instead.
        # This check must sit immediately before the chmod call - doing it
        # any earlier just moves the race window rather than closing it.
        if stat.S_ISLNK(os.lstat(path).st_mode):
            return FixResult(
                path=str(path), success=False,
                before_mode_octal=before_octal, after_mode_octal=None,
                error="path became a symlink - refusing to modify its target",
            )
        os.chmod(path, target_mode)
    except PermissionError:
        return FixResult(
            path=str(path), success=False,
            before_mode_octal=before_octal, after_mode_octal=None,
            error="permission denied - you may not own this file",
        )
    except OSError as e:
        return FixResult(
            path=str(path), success=False,
            before_mode_octal=before_octal, after_mode_octal=None,
            error=str(e),
        )

    after_stat = os.lstat(path)
    after_octal = _mode_octal(after_stat.st_mode)

    return FixResult(
        path=str(path), success=True,
        before_mode_octal=before_octal, after_mode_octal=after_octal,
        error=None,
    )


def apply_fix_for_finding(finding: Finding) -> FixResult:
    """Apply the suggested fix for a Finding produced by a scan."""
    if finding.suggested_fix_octal is None:
        return FixResult(
            path=finding.path, success=False,
            before_mode_octal=None, after_mode_octal=None,
            error=(
                f"no automatic fix available for {finding.check_type.value} "
                "- this requires manual action"
            ),
        )

    target_mode = int(finding.suggested_fix_octal, 8)
    return apply_fix(Path(finding.path), target_mode)