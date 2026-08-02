"""Interactive TUI for janus-sec, built with Textual.

Main screen: a scrollable list of findings (color-coded by risk) with a
detail panel showing the full explanation for whichever finding is
currently selected.
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Static

from janus_sec.models import RiskLevel


_RISK_STYLE = {
    RiskLevel.HIGH: "bold red",
    RiskLevel.MEDIUM: "bold yellow",
    RiskLevel.LOW: "bold cyan",
    RiskLevel.INFO: "dim",
}


class JanusSecApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    #body {
        height: 1fr;
    }
    #findings-table {
        width: 2fr;
        border: solid $panel;
    }
    #detail-panel {
        width: 1fr;
        border: solid $panel;
        padding: 1 2;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("j", "cursor_down", "Down"),
        ("k", "cursor_up", "Up"),
    ]

    def __init__(self, findings: list) -> None:
        super().__init__()
        self.findings = findings

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="body"):
            yield DataTable(id="findings-table")
            yield Static(id="detail-panel")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Risk", "Path", "Issue")
        table.cursor_type = "row"

        for f in self.findings:
            style = _RISK_STYLE.get(f.risk_level, "")
            table.add_row(
                f"[{style}]{f.risk_level.value}[/{style}]",
                f.path,
                f.check_type.value,
                key=f.id,
            )

        if self.findings:
            self._show_detail(self.findings[0])

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        finding = next((f for f in self.findings if f.id == event.row_key.value), None)
        if finding is not None:
            self._show_detail(finding)

    def action_cursor_down(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.action_cursor_down()

    def action_cursor_up(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.action_cursor_up()
        
    def _show_detail(self, finding) -> None:
        panel = self.query_one("#detail-panel", Static)
        fix_line = (
            f"Suggested fix: chmod {finding.suggested_fix_octal}"
            if finding.suggested_fix_octal
            else "No automatic fix available."
        )
        panel.update(
            f"[bold]{finding.path}[/bold]\n\n"
            f"Risk: {finding.risk_level.value}\n"
            f"Current mode: {finding.current_mode_octal}\n\n"
            f"{finding.reason}\n\n"
            f"{fix_line}"
        )


def run_app(findings: list) -> None:
    app = JanusSecApp(findings)
    app.run()