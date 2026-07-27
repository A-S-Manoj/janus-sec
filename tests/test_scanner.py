"""Tests for the scanner - the full pipeline glued together."""

import os
from pathlib import Path

from janus_sec.scanner import scan
from janus_sec.targets import TargetGroup
from janus_sec.models import CheckType, RiskLevel


def test_missing_files_skipped_not_errored(tmp_path: Path) -> None:
    targets = [
        TargetGroup(name="fake", expected_root=tmp_path, files=("nonexistent",))
    ]

    result = scan(targets)

    assert result.files_scanned == 0
    assert result.files_missing == 1
    assert result.findings == []


def test_safe_file_produces_no_findings(tmp_path: Path) -> None:
    f = tmp_path / "safe_key"
    f.write_text("x")
    os.chmod(f, 0o600)
    targets = [TargetGroup(name="fake", expected_root=tmp_path, files=("safe_key",))]

    result = scan(targets)

    assert result.files_scanned == 1
    assert result.files_missing == 0
    assert result.findings == []


def test_world_readable_file_detected(tmp_path: Path) -> None:
    f = tmp_path / "id_rsa"
    f.write_text("fake key")
    os.chmod(f, 0o644)
    targets = [TargetGroup(name="fake", expected_root=tmp_path, files=("id_rsa",))]

    result = scan(targets)

    assert result.files_scanned == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.check_type == CheckType.WORLD_READABLE
    assert finding.risk_level == RiskLevel.HIGH
    assert finding.suggested_fix_octal == "600"


def test_locked_directory_produces_uninspectable_finding(tmp_path: Path) -> None:
    # Skip as root - root bypasses permission checks entirely
    if os.geteuid() == 0:
        return

    restricted_dir = tmp_path / "restricted"
    restricted_dir.mkdir()
    f = restricted_dir / "secret"
    f.write_text("x")

    targets = [
        TargetGroup(name="fake", expected_root=restricted_dir, files=("secret",))
    ]

    try:
        os.chmod(restricted_dir, 0o000)
        result = scan(targets)
    finally:
        os.chmod(restricted_dir, 0o755)  # restore so tmp_path cleanup can delete it

    assert result.files_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].check_type == CheckType.UNINSPECTABLE
    assert result.findings[0].risk_level == RiskLevel.INFO


def test_broken_symlink_produces_uninspectable_finding(tmp_path: Path) -> None:
    link = tmp_path / "config"
    link.symlink_to(tmp_path / "does_not_exist")
    targets = [TargetGroup(name="fake", expected_root=tmp_path, files=("config",))]

    result = scan(targets)

    assert result.files_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].check_type == CheckType.UNINSPECTABLE


def test_multiple_findings_on_one_file(tmp_path: Path) -> None:
    # A symlink that's ALSO world-writable at the target: should get both a
    # world_writable finding AND a symlink_escape finding, since these are
    # genuinely two distinct problems on the same path.
    outside = tmp_path / "outside"
    outside.mkdir()
    real_target = outside / "real_config"
    real_target.write_text("x")
    os.chmod(real_target, 0o666)

    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    link = ssh_dir / "config"
    link.symlink_to(real_target)

    targets = [TargetGroup(name="ssh", expected_root=ssh_dir, files=("config",))]

    result = scan(targets)

    check_types = {f.check_type for f in result.findings}
    assert CheckType.WORLD_WRITABLE in check_types
    assert CheckType.SYMLINK_ESCAPE in check_types


def test_real_default_targets_do_not_crash() -> None:
    # Smoke test against your actual home directory - most files won't
    # exist, that's fine, we're just confirming scan() doesn't throw on a
    # real machine with real (mostly absent) targets.
    result = scan()
    assert result.files_scanned + result.files_missing > 0