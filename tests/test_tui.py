"""Tests for the TUI, using Textual's Pilot test harness."""

import pytest
from textual.widgets import DataTable, Static

from janus_sec.tui import JanusSecApp
from janus_sec.models import CheckType, Confidence, Finding, FilesystemType, RiskLevel


def _finding(path: str, risk: RiskLevel = RiskLevel.HIGH) -> Finding:
    return Finding(
        path=path,
        current_mode_octal="644",
        current_mode_human="-rw-r--r--",
        risk_level=risk,
        check_type=CheckType.WORLD_READABLE,
        reason="test reason",
        owner="ezio",
        expected_owner="ezio",
        is_symlink=False,
        filesystem_type=FilesystemType.LOCAL,
        confidence=Confidence.HIGH,
        suggested_fix_octal="600",
    )


@pytest.mark.asyncio
async def test_table_populated_with_findings() -> None:
    findings = [_finding("/x/id_rsa"), _finding("/x/credentials")]
    app = JanusSecApp(findings)

    async with app.run_test() as pilot:
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == 2


@pytest.mark.asyncio
async def test_detail_panel_shows_first_finding_on_mount() -> None:
    findings = [_finding("/x/id_rsa")]
    app = JanusSecApp(findings)

    async with app.run_test() as pilot:
        panel = app.query_one("#detail-panel", Static)
        assert "/x/id_rsa" in str(panel.render())


@pytest.mark.asyncio
async def test_j_key_moves_cursor_down() -> None:
    findings = [_finding("/x/id_rsa"), _finding("/x/credentials")]
    app = JanusSecApp(findings)

    async with app.run_test() as pilot:
        table = app.query_one("#findings-table", DataTable)
        assert table.cursor_row == 0

        await pilot.press("j")
        assert table.cursor_row == 1


@pytest.mark.asyncio
async def test_k_key_moves_cursor_up() -> None:
    findings = [_finding("/x/id_rsa"), _finding("/x/credentials")]
    app = JanusSecApp(findings)

    async with app.run_test() as pilot:
        table = app.query_one("#findings-table", DataTable)
        await pilot.press("j")  # go to row 1 first
        assert table.cursor_row == 1

        await pilot.press("k")
        assert table.cursor_row == 0


@pytest.mark.asyncio
async def test_detail_panel_updates_on_row_change() -> None:
    findings = [_finding("/x/id_rsa"), _finding("/x/credentials")]
    app = JanusSecApp(findings)

    async with app.run_test() as pilot:
        await pilot.press("j")
        panel = app.query_one("#detail-panel", Static)
        assert "/x/credentials" in str(panel.render())


@pytest.mark.asyncio
async def test_empty_findings_does_not_crash() -> None:
    app = JanusSecApp([])

    async with app.run_test() as pilot:
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == 0