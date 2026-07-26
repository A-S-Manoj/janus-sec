"""Tests for world-readable / world-writable detection."""

import os
from pathlib import Path

from janus_sec.checks.context import build_context
from janus_sec.checks import world_permissions
from janus_sec.models import CheckType, RiskLevel, FilesystemType


def test_world_readable_flagged(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f.write_text("fake key")
    os.chmod(f, 0o644)

    ctx = build_context(f)
    finding = world_permissions.check(ctx, FilesystemType.LOCAL)

    assert finding is not None
    assert finding.check_type == CheckType.WORLD_READABLE
    assert finding.risk_level == RiskLevel.HIGH
    assert finding.current_mode_octal == "644"
    assert finding.suggested_fix_octal == "600"


def test_world_writable_flagged(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f.write_text("fake key")
    os.chmod(f, 0o666)

    ctx = build_context(f)
    finding = world_permissions.check(ctx, FilesystemType.LOCAL)

    assert finding is not None
    assert finding.check_type == CheckType.WORLD_WRITABLE
    assert finding.risk_level == RiskLevel.HIGH
    assert finding.suggested_fix_octal == "600"


def test_world_writable_wins_over_readable(tmp_path: Path) -> None:
    # mode 666 is both world-readable AND world-writable - should report
    # only ONE finding (world_writable), not two, since it's strictly worse
    # and the fix is identical either way.
    f = tmp_path / "id_rsa"
    f.write_text("fake key")
    os.chmod(f, 0o666)

    ctx = build_context(f)
    finding = world_permissions.check(ctx, FilesystemType.LOCAL)

    assert finding.check_type == CheckType.WORLD_WRITABLE


def test_safe_file_not_flagged(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f.write_text("fake key")
    os.chmod(f, 0o600)

    ctx = build_context(f)
    finding = world_permissions.check(ctx, FilesystemType.LOCAL)

    assert finding is None


def test_group_readable_only_not_flagged(tmp_path: Path) -> None:
    # 640 = owner rw, group r, world nothing. This module only checks the
    # WORLD bits - group-readable is a separate, lower-severity check
    f = tmp_path / "id_rsa"
    f.write_text("fake key")
    os.chmod(f, 0o640)

    ctx = build_context(f)
    finding = world_permissions.check(ctx, FilesystemType.LOCAL)

    assert finding is None