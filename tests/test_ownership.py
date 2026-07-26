"""Tests for ownership mismatch detection."""

from pathlib import Path
from unittest.mock import patch

from janus_sec.checks.context import build_context
from janus_sec.checks import ownership
from janus_sec.models import CheckType, RiskLevel, FilesystemType


def test_own_file_not_flagged(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f.write_text("fake key")

    ctx = build_context(f)
    finding = ownership.check(ctx, FilesystemType.LOCAL)

    assert finding is None


def test_mismatched_owner_flagged(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f.write_text("fake key")

    ctx = build_context(f)

    # We can't actually chown to a different real user without root, so
    # instead we simulate "someone else owns this" by pretending our own
    # uid is different from the file's real uid when the check asks.
    fake_other_uid = ctx.resolved_stat.st_uid + 1
    with patch("janus_sec.checks.ownership.current_uid", return_value=fake_other_uid):
        finding = ownership.check(ctx, FilesystemType.LOCAL)

    assert finding is not None
    assert finding.check_type == CheckType.OWNERSHIP_MISMATCH
    assert finding.risk_level == RiskLevel.HIGH
    assert finding.suggested_fix_octal is None