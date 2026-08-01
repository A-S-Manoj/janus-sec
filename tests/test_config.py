"""Tests for the config system: config.toml loading, ignore-list, allowlist merging."""

from pathlib import Path

from janus_sec.config import (
    Config,
    IgnoreEntry,
    default_config_path,
    filter_ignored,
    is_ignored,
    load_config,
)
from janus_sec.checks.group_ownership import AllowlistPattern
from janus_sec.models import CheckType, Confidence, Finding, FilesystemType, RiskLevel


def _finding(path: str, check_type: CheckType) -> Finding:
    return Finding(
        path=path,
        current_mode_octal="644",
        current_mode_human="-rw-r--r--",
        risk_level=RiskLevel.HIGH,
        check_type=check_type,
        reason="test",
        owner="ezio",
        expected_owner="ezio",
        is_symlink=False,
        filesystem_type=FilesystemType.LOCAL,
        confidence=Confidence.HIGH,
        suggested_fix_octal="600",
    )


def test_missing_config_file_returns_empty_config(tmp_path: Path) -> None:
    config_path = tmp_path / "does_not_exist.toml"

    config = load_config(config_path)

    assert config.ignore == []
    assert config.allowlist == []


def test_load_config_parses_ignore_entries(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[[ignore]]
path = "/home/ezio/.ssh/known_hosts"
check_type = "group_readable"
note = "shared dev box"
"""
    )

    config = load_config(config_path)

    assert len(config.ignore) == 1
    entry = config.ignore[0]
    assert entry.path == "/home/ezio/.ssh/known_hosts"
    assert entry.check_type == "group_readable"
    assert entry.note == "shared dev box"


def test_load_config_parses_allowlist_entries(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[[allowlist]]
group = "wheel"
action = "suppress"
os = "linux"
"""
    )

    config = load_config(config_path)

    assert len(config.allowlist) == 1
    pattern = config.allowlist[0]
    assert pattern.group == "wheel"
    assert pattern.action == "suppress"
    assert pattern.os_name == "linux"


def test_load_config_allowlist_action_defaults_to_suppress(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[[allowlist]]
group = "staff"
"""
    )

    config = load_config(config_path)

    assert config.allowlist[0].action == "suppress"


def test_is_ignored_matches_path_and_check_type() -> None:
    config = Config(
        ignore=[IgnoreEntry(path="/x/known_hosts", check_type="group_readable")],
        allowlist=[],
    )

    assert is_ignored("/x/known_hosts", "group_readable", config) is True


def test_is_ignored_does_not_match_different_check_type_same_path() -> None:
    # This is the whole point of path+check_type granularity: ignoring one
    # issue on a file must NOT silently ignore a different issue on that
    # same file.
    config = Config(
        ignore=[IgnoreEntry(path="/x/known_hosts", check_type="group_readable")],
        allowlist=[],
    )

    assert is_ignored("/x/known_hosts", "world_writable", config) is False


def test_is_ignored_does_not_match_different_path() -> None:
    config = Config(
        ignore=[IgnoreEntry(path="/x/known_hosts", check_type="group_readable")],
        allowlist=[],
    )

    assert is_ignored("/x/other_file", "group_readable", config) is False


def test_filter_ignored_removes_matching_findings() -> None:
    findings = [
        _finding("/x/known_hosts", CheckType.GROUP_READABLE),
        _finding("/x/id_rsa", CheckType.WORLD_READABLE),
    ]
    config = Config(
        ignore=[IgnoreEntry(path="/x/known_hosts", check_type="group_readable")],
        allowlist=[],
    )

    result = filter_ignored(findings, config)

    assert len(result) == 1
    assert result[0].path == "/x/id_rsa"


def test_filter_ignored_keeps_everything_with_empty_ignore_list() -> None:
    findings = [
        _finding("/x/known_hosts", CheckType.GROUP_READABLE),
        _finding("/x/id_rsa", CheckType.WORLD_READABLE),
    ]
    config = Config(ignore=[], allowlist=[])

    result = filter_ignored(findings, config)

    assert len(result) == 2


def test_default_config_path_uses_xdg_config_home(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    path = default_config_path()

    assert path == tmp_path / "janus-sec" / "config.toml"