"""Interactive TUI for janus-sec, built with Textual.

Main screen: a scrollable list of findings (color-coded by risk) with a
detail panel showing the full explanation for whichever finding is
currently selected.
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Static, Button, Label

from janus_sec.models import RiskLevel


_RISK_STYLE = {
    RiskLevel.HIGH: "bold red",
    RiskLevel.MEDIUM: "bold yellow",
    RiskLevel.LOW: "bold cyan",
    RiskLevel.INFO: "dim",
}

class ConfirmFixScreen(ModalScreen[bool]):
    """A yes/no confirmation dialog for applying a fix."""

    CSS = """
    ConfirmFixScreen {
        align: center middle;
    }
    #dialog {
        width: 60;
        height: auto;
        border: thick $accent;
        padding: 1 2;
        background: $panel;
    }
    #buttons {
        height: 3;
        align: center middle;
    }
    """

    def __init__(self, finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(f"Fix {self.finding.path}?")
            yield Label(
                f"chmod {self.finding.current_mode_octal} -> "
                f"{self.finding.suggested_fix_octal}"
            )
            with Horizontal(id="buttons"):
                yield Button("Yes", id="yes", variant="error")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

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
        ("f", "fix_selected", "Fix"),
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

    def action_fix_selected(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        if table.row_count == 0:
            return

        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        finding = next((f for f in self.findings if f.id == row_key.value), None)
        if finding is None or finding.suggested_fix_octal is None:
            self.notify("No automatic fix available for this finding.", severity="warning")
            return

        def handle_result(confirmed: bool | None) -> None:
            if confirmed:
                self._apply_fix(finding)

        self.push_screen(ConfirmFixScreen(finding), handle_result)

    def _apply_fix(self, finding) -> None:
        from janus_sec.fix import apply_fix_for_finding
        from janus_sec.audit import append_entry

        result = apply_fix_for_finding(finding)
        if result.success:
            append_entry(
                path=result.path,
                before_mode_octal=result.before_mode_octal,
                after_mode_octal=result.after_mode_octal,
                applied_via="tui",
            )
            self.notify(f"Fixed {result.path}")
            self.findings = [f for f in self.findings if f.id != finding.id]
            self._rebuild_table()
        else:
            self.notify(f"Failed: {result.error}", severity="error")

    def _rebuild_table(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()
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
        else:
            self.query_one("#detail-panel", Static).update("No findings remaining.")

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


def run_app() -> None:
    from janus_sec.scanner import scan
    result = scan()
    app = JanusSecApp(result.findings)
    app.run()