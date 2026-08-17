"""Ownership mismatch detection.

A credential file not owned by the current user means someone else (or
some other process/account) controls it - permissions on it don't mean
what you'd expect, and janus-sec can't safely offer an automatic fix here
since reassigning ownership normally requires root, which this tool never
attempts.
"""

from __future__ import annotations

from janus_sec.checks._shared import build_finding
from janus_sec.checks.context import FileContext
from janus_sec.checks.identity import current_uid, username_for_uid
from janus_sec.models import CheckType, Finding, FilesystemType, RiskLevel


def check(ctx: FileContext, filesystem_type: FilesystemType) -> Finding | None:
    if ctx.resolved_stat is None:
        return None  # uninspectable - scanner reports this case separately

    file_uid = ctx.resolved_stat.st_uid
    my_uid = current_uid()
    if file_uid == my_uid:
        return None

    return build_finding(
        ctx,
        filesystem_type,
        check_type=CheckType.OWNERSHIP_MISMATCH,
        risk_level=RiskLevel.HIGH,
        reason=(
            f"This file is owned by '{username_for_uid(file_uid)}', not you "
            f"('{username_for_uid(my_uid)}'). A credential file you rely on "
            "being under your own control is actually controlled by "
            "another account."
        ),
        owner=username_for_uid(file_uid),
        expected_owner=username_for_uid(my_uid),
        suggested_fix_octal=None,  # no auto-fix - would require chown/sudo
    )