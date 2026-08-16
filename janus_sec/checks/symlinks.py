"""Symlink-escape detection.

Some credential files are supposed to be real files living inside a
specific directory (e.g. ~/.ssh/config living inside ~/.ssh). If one turns
out to actually be a symlink pointing OUTSIDE that expected directory, the
"file" you think you're managing is actually controlled by whatever put
that symlink there - could be a bad tarball extraction, a misconfigured
tool, or something deliberately planted.

This check only fires for symlinks that successfully resolve. A symlink
pointing at a target that doesn't exist at all is a separate, simpler
problem (a broken symlink), not an escape - the scanner handles that case
on its own once it exists.
"""

from __future__ import annotations

from pathlib import Path

from janus_sec.checks._shared import build_finding
from janus_sec.checks.context import FileContext
from janus_sec.models import CheckType, Finding, FilesystemType, RiskLevel


def check(
    ctx: FileContext,
    filesystem_type: FilesystemType,
    expected_root: Path,
) -> Finding | None:
    """expected_root is the directory this file is supposed to live under,
    e.g. ~/.ssh for ~/.ssh/config. Passed in by the scanner, which owns the
    knowledge of which target files belong under which directory.
    """
    if not ctx.is_symlink or ctx.resolved_stat is None:
        return None  # not a symlink, or a broken symlink - nothing to check here

    resolved_path = ctx.path.resolve()
    expected_root_resolved = expected_root.resolve()

    try:
        resolved_path.relative_to(expected_root_resolved)
        escapes = False
    except ValueError:
        escapes = True

    if not escapes:
        return None

    return build_finding(
        ctx,
        filesystem_type,
        check_type=CheckType.SYMLINK_ESCAPE,
        risk_level=RiskLevel.MEDIUM,
        reason=(
            f"This is a symlink pointing to '{resolved_path}', outside the "
            f"expected directory ('{expected_root_resolved}'). This can "
            "redirect reads and writes to an unexpected location."
        ),
        suggested_fix_octal=None,
    )