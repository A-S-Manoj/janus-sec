"""Tests for the fix engine - the code that actually mutates files."""

import os
import stat
from pathlib import Path
from unittest.mock import patch

from janus_sec.fix import apply_fix, apply_fix_for_finding
from janus_sec.models import CheckType, Confidence, Finding, FilesystemType, RiskLevel


def _finding_for(path: Path, fix_octal: str | None) -> Finding:
    return Finding(
        path=str(path),
        current_mode_octal="644",
        current_mode_human="-rw-r--r--",
        risk_level=RiskLevel.HIGH,
        check_type=CheckType.WORLD_READABLE,
        reason="test",
        owner="ezio",
        expected_owner="ezio",
        is_symlink=False,
        filesystem_type=FilesystemType.LOCAL,
        confidence=Confidence.HIGH,
        suggested_fix_octal=fix_octal,
    )


def test_apply_fix_changes_mode(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f.write_text("x")
    os.chmod(f, 0o644)

    result = apply_fix(f, 0o600)

    assert result.success is True
    assert result.before_mode_octal == "644"
    assert result.after_mode_octal == "600"
    assert result.error is None

    actual_mode = stat.S_IMODE(os.lstat(f).st_mode)
    assert oct(actual_mode)[2:].zfill(3) == "600"


def test_apply_fix_missing_file(tmp_path: Path) -> None:
    f = tmp_path / "does_not_exist"

    result = apply_fix(f, 0o600)

    assert result.success is False
    assert result.error == "file no longer exists"
    assert result.before_mode_octal is None


def test_apply_fix_refuses_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target_secret"
    target.write_text("target")
    os.chmod(target, 0o644)

    link = tmp_path / "symlink_secret"
    os.symlink(target, link)

    result = apply_fix(link, 0o600)

    assert result.success is False
    assert "file is a symlink" in result.error

    # Ensure target file mode was NOT modified
    actual_mode = stat.S_IMODE(os.lstat(target).st_mode)
    assert oct(actual_mode)[2:].zfill(3) == "644"


def test_apply_fix_toctou_symlink_race(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f.write_text("x")
    os.chmod(f, 0o644)

    # Simulate path becoming a symlink immediately after pre-stat
    with patch("os.path.islink", return_value=True):
        result = apply_fix(f, 0o600)

    assert result.success is False
    assert "file is a symlink" in result.error


def test_apply_fix_on_locked_directory_file(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        return  # root bypasses permission checks

    restricted_dir = tmp_path / "restricted"
    restricted_dir.mkdir()
    f = restricted_dir / "secret"
    f.write_text("x")

    try:
        os.chmod(restricted_dir, 0o000)
        result = apply_fix(f, 0o600)
    finally:
        os.chmod(restricted_dir, 0o755)

    assert result.success is False
    assert result.error is not None


def test_apply_fix_for_finding_with_fix(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f.write_text("x")
    os.chmod(f, 0o644)
    finding = _finding_for(f, "600")

    result = apply_fix_for_finding(finding)

    assert result.success is True
    assert result.after_mode_octal == "600"


def test_apply_fix_for_finding_without_fix_available(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f.write_text("x")
    finding = _finding_for(f, None)  # e.g. ownership_mismatch or symlink_escape

    result = apply_fix_for_finding(finding)

    assert result.success is False
    assert "no automatic fix available" in result.error


def test_apply_fix_result_is_never_an_exception(tmp_path: Path) -> None:
    # The whole point of FixResult is that callers never need a try/except
    # around apply_fix - every failure mode comes back as a normal value.
    f = tmp_path / "does_not_exist"
    try:
        result = apply_fix(f, 0o600)
    except Exception as e:
        assert False, f"apply_fix raised instead of returning a FixResult: {e}"

    assert result.success is False