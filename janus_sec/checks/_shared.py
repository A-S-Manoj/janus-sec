"""Shared utilities and protocol definitions for check modules."""

from __future__ import annotations

import stat
from typing import Any, Protocol

from janus_sec.checks.context import FileContext
from janus_sec.checks.identity import username_for_uid
from janus_sec.models import (
    CheckType,
    Confidence,
    Finding,
    FilesystemType,
    RiskLevel,
)


class CheckFn(Protocol):
    """Protocol describing the signature of a check function."""

    def __call__(
        self,
        ctx: FileContext,
        filesystem_type: FilesystemType,
        **kwargs: Any,
    ) -> Finding | None:
        ...


def build_finding(
    ctx: FileContext,
    filesystem_type: FilesystemType,
    check_type: CheckType,
    risk_level: RiskLevel,
    reason: str,
    *,
    owner: str | None = None,
    expected_owner: str | None = None,
    confidence: Confidence = Confidence.HIGH,
    suggested_fix_octal: str | None = None,
) -> Finding:
    """Construct a Finding instance with common fields derived from FileContext."""
    if ctx.resolved_stat is not None:
        mode = ctx.resolved_stat.st_mode
        current_octal = oct(stat.S_IMODE(mode))[2:].zfill(3)
        current_human = stat.filemode(mode)
        default_owner = username_for_uid(ctx.resolved_stat.st_uid)
    else:
        current_octal = "???"
        current_human = "?"
        default_owner = "unknown"

    actual_owner = owner if owner is not None else default_owner
    actual_expected_owner = (
        expected_owner if expected_owner is not None else actual_owner
    )

    return Finding(
        path=str(ctx.path),
        current_mode_octal=current_octal,
        current_mode_human=current_human,
        risk_level=risk_level,
        check_type=check_type,
        reason=reason,
        owner=actual_owner,
        expected_owner=actual_expected_owner,
        is_symlink=ctx.is_symlink,
        filesystem_type=filesystem_type,
        confidence=confidence,
        suggested_fix_octal=suggested_fix_octal,
    )
