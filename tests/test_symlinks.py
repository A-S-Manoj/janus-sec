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

def test_finding_describes_the_target_seen_at_scan_time(tmp_path: Path) -> None:
    # The check must report the target the context captured, not re-read the
    # link when it runs. Anything able to plant the symlink can repoint it in
    # between, and re-reading would produce a finding whose path came from one
    # moment and whose mode bits came from another.
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    scanned_dir = tmp_path / "scanned_target"
    scanned_dir.mkdir()
    swapped_dir = tmp_path / "swapped_target"
    swapped_dir.mkdir()
    scanned_file = scanned_dir / "real_config"
    scanned_file.write_text("x")
    swapped_file = swapped_dir / "real_config"
    swapped_file.write_text("x")

    link = ssh_dir / "config"
    link.symlink_to(scanned_file)
    ctx = build_context(link)

    # The link is repointed after the scan read it, before the check runs.
    link.unlink()
    link.symlink_to(swapped_file)

    finding = symlinks.check(ctx, FilesystemType.LOCAL, expected_root=ssh_dir)

    assert finding is not None
    assert str(scanned_file) in finding.reason
    assert str(swapped_file) not in finding.reason


def test_reason_does_not_present_the_target_as_current(tmp_path: Path) -> None:
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
    assert "When scanned" in finding.reason


def test_no_finding_when_the_target_did_not_resolve(tmp_path: Path) -> None:
    # resolved_stat present but resolved_path missing should stay quiet rather
    # than guess at a target to compare against the expected root.
    import dataclasses

    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    real_file = outside_dir / "real_config"
    real_file.write_text("x")
    link = ssh_dir / "config"
    link.symlink_to(real_file)

    ctx = dataclasses.replace(build_context(link), resolved_path=None)
    finding = symlinks.check(ctx, FilesystemType.LOCAL, expected_root=ssh_dir)

    assert finding is None
