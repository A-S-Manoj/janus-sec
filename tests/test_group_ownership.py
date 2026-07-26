"""Tests for group-readable detection and allowlist behavior."""

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

    # Simulate the file's group being different from our own primary group
    # by faking what current_primary_gid() returns, same trick as the
    # ownership test - we can't easily chgrp to a real different group
    # without being in one.
    with patch(
        "janus_sec.checks.group_ownership.current_primary_gid",
        return_value=my_gid + 1,
    ):
        finding = group_ownership.check(ctx, FilesystemType.LOCAL, allowlist=[])

    assert finding is not None
    assert finding.check_type == CheckType.GROUP_READABLE
    assert finding.risk_level == RiskLevel.MEDIUM


def test_allowlist_suppress(tmp_path: Path) -> None:
    f = tmp_path / "config"
    f.write_text("x")
    os.chmod(f, 0o640)

    ctx = build_context(f)
    my_gid = ctx.resolved_stat.st_gid
    group_name = group_ownership.groupname_for_gid(my_gid)

    allowlist = [AllowlistPattern(group=group_name, action="suppress")]

    with patch(
        "janus_sec.checks.group_ownership.current_primary_gid",
        return_value=my_gid + 1,
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
        "janus_sec.checks.group_ownership.current_primary_gid",
        return_value=my_gid + 1,
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