"""Tests for the CLI - argument parsing and output formatting."""

import json

from janus_sec.cli import build_parser, main
from janus_sec.models import (
    CheckType,
    Confidence,
    Finding,
    FilesystemType,
    RiskLevel,
)
from janus_sec.scanner import ScanResult
from janus_sec.fix import FixResult


def _fake_finding(risk: RiskLevel = RiskLevel.HIGH) -> Finding:
    return Finding(
        path="/home/ezio/.ssh/id_rsa",
        current_mode_octal="644",
        current_mode_human="-rw-r--r--",
        risk_level=risk,
        check_type=CheckType.WORLD_READABLE,
        reason="Readable by any local user.",
        owner="ezio",
        expected_owner="ezio",
        is_symlink=False,
        filesystem_type=FilesystemType.LOCAL,
        confidence=Confidence.HIGH,
        suggested_fix_octal="600",
    )


def test_scan_subcommand_parses() -> None:
    parser = build_parser()
    args = parser.parse_args(["scan"])

    assert args.command == "scan"
    assert args.format == "human"
    assert args.ci is False


def test_scan_with_json_and_ci_flags_parse() -> None:
    parser = build_parser()
    args = parser.parse_args(["scan", "--format", "json", "--ci"])

    assert args.format == "json"
    assert args.ci is True


def test_human_output_no_findings(monkeypatch, capsys) -> None:
    fake_result = ScanResult(findings=[], files_scanned=3, files_missing=9)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)

    import sys
    monkeypatch.setattr(sys, "argv", ["janus-sec", "scan"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "No issues found." in captured.out
    assert "Scanned 3 file(s), 9 not present." in captured.out


def test_human_output_with_findings(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=[_fake_finding()], files_scanned=1, files_missing=11)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "scan"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "[HIGH]" in captured.out
    assert "/home/ezio/.ssh/id_rsa" in captured.out
    assert "chmod 600" in captured.out


def test_json_output_is_valid_json(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=[_fake_finding()], files_scanned=1, files_missing=11)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "scan", "--format", "json"])

    exit_code = main()
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    assert payload["files_scanned"] == 1
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["risk_level"] == "HIGH"


def test_ci_flag_exits_nonzero_on_high_risk(monkeypatch) -> None:
    import sys
    fake_result = ScanResult(findings=[_fake_finding(RiskLevel.HIGH)], files_scanned=1, files_missing=0)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "scan", "--ci"])

    exit_code = main()

    assert exit_code == 1


def test_ci_flag_exits_zero_when_no_high_risk(monkeypatch) -> None:
    import sys
    fake_result = ScanResult(
        findings=[_fake_finding(RiskLevel.LOW)], files_scanned=1, files_missing=0
    )
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "scan", "--ci"])

    exit_code = main()

    assert exit_code == 0


def test_ci_flag_exits_zero_with_no_findings_at_all(monkeypatch) -> None:
    import sys
    fake_result = ScanResult(findings=[], files_scanned=0, files_missing=12)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "scan", "--ci"])

    exit_code = main()

    assert exit_code == 0


def _fake_findings_for_fix() -> list:
    return [_fake_finding()]


def test_fix_dry_run_makes_no_changes(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=_fake_findings_for_fix(), files_scanned=1, files_missing=0)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)

    apply_calls = []
    monkeypatch.setattr(
        "janus_sec.cli.apply_fix_for_finding",
        lambda f: apply_calls.append(f) or FixResult(f.path, True, "644", "600", None),
    )
    monkeypatch.setattr(sys, "argv", ["janus-sec", "fix", "--dry-run"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Dry run" in captured.out
    assert apply_calls == []  # apply_fix_for_finding must NOT have been called


def test_fix_aborts_when_user_declines(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=_fake_findings_for_fix(), files_scanned=1, files_missing=0)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")

    apply_calls = []
    monkeypatch.setattr(
        "janus_sec.cli.apply_fix_for_finding",
        lambda f: apply_calls.append(f) or FixResult(f.path, True, "644", "600", None),
    )
    monkeypatch.setattr(sys, "argv", ["janus-sec", "fix"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Aborted" in captured.out
    assert apply_calls == []


def test_fix_applies_when_user_confirms(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=_fake_findings_for_fix(), files_scanned=1, files_missing=0)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    monkeypatch.setattr(
        "janus_sec.cli.apply_fix_for_finding",
        lambda f: FixResult(f.path, True, "644", "600", None),
    )
    monkeypatch.setattr("janus_sec.cli.append_entry", lambda **kwargs: None)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "fix"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "1 fixed, 0 failed" in captured.out


def test_fix_yes_flag_skips_prompt(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=_fake_findings_for_fix(), files_scanned=1, files_missing=0)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(
        "janus_sec.cli.apply_fix_for_finding",
        lambda f: FixResult(f.path, True, "644", "600", None),
    )
    monkeypatch.setattr("janus_sec.cli.append_entry", lambda **kwargs: None)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "fix", "--yes"])
    # deliberately NOT patching input() - if the code tries to call it,
    # this test will hang/error, proving --yes actually skips the prompt

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "1 fixed, 0 failed" in captured.out


def test_fix_short_flag_aliases_parse() -> None:
    parser = build_parser()
    args = parser.parse_args(["fix", "-d", "-y"])

    assert args.dry_run is True
    assert args.yes is True


def test_fix_short_dry_run_flag_makes_no_changes(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=_fake_findings_for_fix(), files_scanned=1, files_missing=0)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)

    apply_calls = []
    monkeypatch.setattr(
        "janus_sec.cli.apply_fix_for_finding",
        lambda f: apply_calls.append(f) or FixResult(f.path, True, "644", "600", None),
    )
    monkeypatch.setattr(sys, "argv", ["janus-sec", "fix", "-d"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Dry run" in captured.out
    assert apply_calls == []  # apply_fix_for_finding must NOT have been called


def test_fix_short_yes_flag_skips_prompt(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=_fake_findings_for_fix(), files_scanned=1, files_missing=0)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(
        "janus_sec.cli.apply_fix_for_finding",
        lambda f: FixResult(f.path, True, "644", "600", None),
    )
    monkeypatch.setattr("janus_sec.cli.append_entry", lambda **kwargs: None)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "fix", "-y"])
    # deliberately NOT patching input() - if the code tries to call it,
    # this test will hang/error, proving -y actually skips the prompt

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "1 fixed, 0 failed" in captured.out


def test_fix_reports_failure_correctly(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=_fake_findings_for_fix(), files_scanned=1, files_missing=0)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(
        "janus_sec.cli.apply_fix_for_finding",
        lambda f: FixResult(f.path, False, "644", None, "permission denied"),
    )
    monkeypatch.setattr(sys, "argv", ["janus-sec", "fix", "--yes"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 1  # nonzero because a fix failed
    assert "0 fixed, 1 failed" in captured.out
    assert "permission denied" in captured.out


def test_fix_no_fixable_findings(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=[], files_scanned=1, files_missing=0)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "fix"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "No fixable findings." in captured.out


def test_fix_specific_path_not_found(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=_fake_findings_for_fix(), files_scanned=1, files_missing=0)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "fix", "/some/other/path"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "No fixable finding for /some/other/path" in captured.out

def test_bare_command_defaults_to_scan(monkeypatch, capsys) -> None:
    import sys
    fake_result = ScanResult(findings=[], files_scanned=0, files_missing=12)
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(sys, "argv", ["janus-sec"])  # no subcommand at all

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Scanned 0 file(s)" in captured.out


def test_verbose_flag_human_output(monkeypatch, capsys) -> None:
    import sys
    from janus_sec.scanner import TargetStatus
    fake_result = ScanResult(
        findings=[],
        files_scanned=1,
        files_missing=1,
        targets_status=[
            TargetStatus(group_name="ssh", path="/home/ezio/.ssh/config", exists=True, mode_octal="600", status="ok"),
            TargetStatus(group_name="ssh", path="/home/ezio/.ssh/id_rsa", exists=False, status="missing"),
        ],
    )
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "scan", "-v"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Target Statuses:" in captured.out
    assert "[ssh]" in captured.out
    assert "[OK]" in captured.out
    assert "[MISSING]" in captured.out


def test_verbose_flag_json_output(monkeypatch, capsys) -> None:
    import sys
    from janus_sec.scanner import TargetStatus
    fake_result = ScanResult(
        findings=[],
        files_scanned=1,
        files_missing=1,
        targets_status=[
            TargetStatus(group_name="ssh", path="/home/ezio/.ssh/config", exists=True, mode_octal="600", status="ok"),
        ],
    )
    monkeypatch.setattr("janus_sec.cli.scan", lambda: fake_result)
    monkeypatch.setattr(sys, "argv", ["janus-sec", "scan", "--format", "json", "--verbose"])

    exit_code = main()
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    assert "targets_status" in payload
    assert payload["targets_status"][0]["group"] == "ssh"
    assert payload["targets_status"][0]["status"] == "ok"
