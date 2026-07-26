"""Tests for symlink-escape detection."""

from pathlib import Path

from janus_sec.checks.context import build_context
from janus_sec.checks import symlinks
from janus_sec.models import CheckType, RiskLevel, FilesystemType


def test_symlink_within_root_not_flagged(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    real_file = ssh_dir / "real_config"
    real_file.write_text("x")
    link = ssh_dir / "config"
    link.symlink_to(real_file)

    ctx = build_context(link)
    finding = symlinks.check(ctx, FilesystemType.LOCAL, expected_root=ssh_dir)

    assert finding is None


def test_symlink_escaping_root_flagged(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    real_file = outside_dir / "real_config"
    real_file.write_text("x")
    link = ssh_dir / "config"
    link.symlink_to(real_file)

    ctx = build_context(link)
    finding = symlinks.check(ctx, FilesystemType.LOCAL, expected_root=ssh_dir)

    assert finding is not None
    assert finding.check_type == CheckType.SYMLINK_ESCAPE
    assert finding.risk_level == RiskLevel.MEDIUM
    assert finding.suggested_fix_octal is None


def test_regular_file_not_flagged(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    f = ssh_dir / "config"
    f.write_text("x")

    ctx = build_context(f)
    finding = symlinks.check(ctx, FilesystemType.LOCAL, expected_root=ssh_dir)

    assert finding is None


def test_broken_symlink_not_flagged_here(tmp_path: Path) -> None:
    # A broken symlink is a different problem, handled elsewhere by the
    # scanner - this check should just step aside for it, not error out.
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    link = ssh_dir / "config"
    link.symlink_to(ssh_dir / "does_not_exist")

    ctx = build_context(link)
    finding = symlinks.check(ctx, FilesystemType.LOCAL, expected_root=ssh_dir)

    assert finding is None