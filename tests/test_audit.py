"""Tests for the audit log."""

from pathlib import Path

from janus_sec.audit import append_entry, read_entries


def test_append_creates_file_and_directory(tmp_path: Path) -> None:
    log_path = tmp_path / "nested" / "audit.log"
    assert not log_path.exists()

    append_entry(
        path="/home/ezio/.ssh/id_rsa",
        before_mode_octal="644",
        after_mode_octal="600",
        applied_via="cli",
        log_path=log_path,
    )

    assert log_path.exists()


def test_append_is_additive_not_overwriting(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"

    append_entry("path1", "644", "600", "cli", log_path=log_path)
    append_entry("path2", "666", "600", "tui", log_path=log_path)

    entries = read_entries(log_path)

    assert len(entries) == 2
    assert "path1" in entries[0]
    assert "path2" in entries[1]


def test_entry_line_contains_expected_fields(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"

    entry = append_entry(
        path="/home/ezio/.ssh/id_rsa",
        before_mode_octal="644",
        after_mode_octal="600",
        applied_via="cli",
        log_path=log_path,
    )

    line = entry.to_line()
    assert "/home/ezio/.ssh/id_rsa" in line
    assert "644 -> 600" in line
    assert "via cli" in line
    assert entry.timestamp in line


def test_read_entries_on_nonexistent_log_returns_empty(tmp_path: Path) -> None:
    log_path = tmp_path / "never_created.log"

    entries = read_entries(log_path)

    assert entries == []


def test_default_log_path_uses_xdg_state_home(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))

    from janus_sec.audit import default_log_path
    path = default_log_path()

    assert path == tmp_path / "janus-sec" / "audit.log"