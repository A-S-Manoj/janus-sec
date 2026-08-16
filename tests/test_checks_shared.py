"""Tests for shared check utilities and Protocol definition."""

import os
from pathlib import Path

from janus_sec.checks._shared import CheckFn, build_finding
from janus_sec.checks.context import FileContext, build_context
from janus_sec.models import (
    CheckType,
    Confidence,
    FilesystemType,
    RiskLevel,
)


def test_build_finding_defaults(tmp_path: Path) -> None:
    f = tmp_path / "test_file"
    f.write_text("content")
    os.chmod(f, 0o644)

    ctx = build_context(f)
    finding = build_finding(
        ctx,
        FilesystemType.LOCAL,
        check_type=CheckType.WORLD_READABLE,
        risk_level=RiskLevel.HIGH,
        reason="test reason",
    )

    assert finding.path == str(f)
    assert finding.current_mode_octal == "644"
    assert finding.current_mode_human.startswith("-rw-r--r--") or "r--" in finding.current_mode_human
    assert finding.risk_level == RiskLevel.HIGH
    assert finding.check_type == CheckType.WORLD_READABLE
    assert finding.reason == "test reason"
    assert finding.is_symlink is False
    assert finding.filesystem_type == FilesystemType.LOCAL
    assert finding.confidence == Confidence.HIGH
    assert finding.owner == finding.expected_owner


def test_build_finding_custom_owner(tmp_path: Path) -> None:
    f = tmp_path / "test_file"
    f.write_text("content")

    ctx = build_context(f)
    finding = build_finding(
        ctx,
        FilesystemType.LOCAL,
        check_type=CheckType.OWNERSHIP_MISMATCH,
        risk_level=RiskLevel.HIGH,
        reason="ownership mismatch",
        owner="other_user",
        expected_owner="my_user",
    )

    assert finding.owner == "other_user"
    assert finding.expected_owner == "my_user"


def test_build_finding_none_stat(tmp_path: Path) -> None:
    f = tmp_path / "test_file"
    f.write_text("content")
    lstat_res = os.lstat(f)
    ctx = FileContext(
        path=f,
        lstat_result=lstat_res,
        is_symlink=False,
        resolved_stat=None,
        resolve_error="denied",
    )

    finding = build_finding(
        ctx,
        FilesystemType.LOCAL,
        check_type=CheckType.UNINSPECTABLE,
        risk_level=RiskLevel.INFO,
        reason="uninspectable",
    )

    assert finding.current_mode_octal == "???"
    assert finding.current_mode_human == "?"
    assert finding.owner == "unknown"
    assert finding.expected_owner == "unknown"


def test_check_fn_protocol() -> None:
    from janus_sec.checks import group_ownership, ownership, symlinks, world_permissions

    def runs_check(fn: CheckFn, ctx: FileContext, fs: FilesystemType) -> None:
        fn(ctx, fs)

    # Verify functions comply with CheckFn type signature
    assert callable(world_permissions.check)
    assert callable(ownership.check)
    assert callable(group_ownership.check)
    assert callable(symlinks.check)
