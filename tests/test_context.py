"""Tests for FileContext / build_context."""

import os
from pathlib import Path

from janus_sec.checks.context import build_context


def test_normal_file(tmp_path: Path) -> None:
    f = tmp_path / "normal.txt"
    f.write_text("hi")

    ctx = build_context(f)

    assert ctx.is_symlink is False
    assert ctx.resolve_error is None
    assert ctx.resolved_stat is not None


def test_broken_symlink(tmp_path: Path) -> None:
    link = tmp_path / "broken_link"
    link.symlink_to(tmp_path / "does_not_exist")

    ctx = build_context(link)

    assert ctx.is_symlink is True
    assert ctx.resolve_error == "broken_symlink"
    assert ctx.resolved_stat is None


def test_working_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.txt"
    target.write_text("hi")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    ctx = build_context(link)

    assert ctx.is_symlink is True
    assert ctx.resolve_error is None
    assert ctx.resolved_stat is not None


def test_permission_denied(tmp_path: Path) -> None:
    # Skip this test if running as root - root bypasses permission checks
    if os.geteuid() == 0:
        return

    f = tmp_path / "secret.txt"
    f.write_text("hi")

    try:
        os.chmod(f, 0o000)
        # Even with 0o000, lstat still succeeds - file *metadata* (owner,
        # mode, size) is readable via the containing directory regardless
        # of the file's own permission bits. Only *content* reads are
        # blocked. So build_context should succeed normally here - this
        # test documents that fact rather than expecting a failure.
        ctx = build_context(f)
        assert ctx.resolve_error is None
        assert ctx.resolved_stat is not None
        assert ctx.resolved_stat.st_mode & 0o777 == 0
    finally:
        os.chmod(f, 0o644)  # restore so tmp_path cleanup can delete it