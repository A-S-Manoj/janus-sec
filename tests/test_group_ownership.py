"""Tests for group-readable detection and allowlist behavior."""

from dataclasses import replace
import os
from pathlib import Path
from unittest.mock import patch

from janus_sec.checks.context import build_context
from janus_sec.checks import group_ownership
from janus_sec.checks.group_ownership import AllowlistPattern
from janus_sec.models import CheckType, RiskLevel, Confidence, FilesystemType


def test_own_primary_group_not_flagged(tmp_path: Path) -> None:
    f = tmp_path / "config"
    f.write_text("x")
    os.chmod(f, 0o640)  # group-readable, but it's YOUR own primary group

    ctx = build_context(f)
    finding = group_ownership.check(ctx, FilesystemType.LOCAL, allowlist=[])

    assert finding is None


def test_not_group_readable_not_flagged(tmp_path: Path) -> None:
    f = tmp_path / "config"
    f.write_text("x")
    os.chmod(f, 0o600)  # no group bits at all

    ctx = build_context(f)
    finding = group_ownership.check(ctx, FilesystemType.LOCAL, allowlist=[])

    assert finding is None


def test_different_group_flagged_medium(tmp_path: Path) -> None:
    f = tmp_path / "config"
    f.write_text("x")
    os.chmod(f, 0o640)

    ctx = build_context(f)
    my_gid = ctx.resolved_stat.st_gid

    # Simulate the file's group being different from any of our groups
    with patch(
        "janus_sec.checks.group_ownership.current_group_ids",
        return_value={my_gid + 1},
    ):
        finding = group_ownership.check(ctx, FilesystemType.LOCAL, allowlist=[])

    assert finding is not None
    assert finding.check_type == CheckType.GROUP_READABLE
    assert finding.risk_level == RiskLevel.MEDIUM


def test_supplementary_group_not_flagged(tmp_path: Path) -> None:
    f = tmp_path / "config"
    f.write_text("x")
    os.chmod(f, 0o640)

    ctx = build_context(f)
    my_gid = ctx.resolved_stat.st_gid
    supp_gid = my_gid + 10

    fake_stat = type(
        "Stat", (), {"st_mode": 0o100640, "st_gid": supp_gid, "st_uid": ctx.resolved_stat.st_uid}
    )()
    supp_ctx = replace(ctx, resolved_stat=fake_stat)

    # Simulate that file's group matches one of our supplementary groups
    with patch(
        "janus_sec.checks.group_ownership.current_group_ids",
        return_value={my_gid, supp_gid},
    ):
        finding = group_ownership.check(supp_ctx, FilesystemType.LOCAL, allowlist=[])

    assert finding is None


def test_allowlist_suppress(tmp_path: Path) -> None:
    f = tmp_path / "config"
    f.write_text("x")
    os.chmod(f, 0o640)

    ctx = build_context(f)
    my_gid = ctx.resolved_stat.st_gid
    group_name = group_ownership.groupname_for_gid(my_gid)

    allowlist = [AllowlistPattern(group=group_name, action="suppress")]

    with patch(
        "janus_sec.checks.group_ownership.current_group_ids",
        return_value={my_gid + 1},
    ):
        finding = group_ownership.check(ctx, FilesystemType.LOCAL, allowlist=allowlist)

    assert finding is None


def test_allowlist_downgrade(tmp_path: Path) -> None:
    f = tmp_path / "config"
    f.write_text("x")
    os.chmod(f, 0o640)

    ctx = build_context(f)
    my_gid = ctx.resolved_stat.st_gid
    group_name = group_ownership.groupname_for_gid(my_gid)

    allowlist = [AllowlistPattern(group=group_name, action="downgrade_to_low")]

    with patch(
        "janus_sec.checks.group_ownership.current_group_ids",
        return_value={my_gid + 1},
    ):
        finding = group_ownership.check(ctx, FilesystemType.LOCAL, allowlist=allowlist)

    assert finding is not None
    assert finding.risk_level == RiskLevel.LOW
    assert finding.confidence == Confidence.LOW


def test_bundled_allowlist_loads_empty() -> None:
    # Sanity check that the real, bundled allowlist.toml still loads and is
    # empty - if this ever fails, either the file is malformed TOML, or
    # someone added entries without updating this test intentionally.
    patterns = group_ownership.load_allowlist()
    assert patterns == []