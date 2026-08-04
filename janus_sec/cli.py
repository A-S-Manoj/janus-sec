"""Command-line entry point for janus-sec.

Currently supports one subcommand: `scan`. More subcommands (fix, ignore,
log) get added here as those pieces of the tool are built.
"""

from __future__ import annotations

import argparse
import json
import sys

from janus_sec.models import RiskLevel
from janus_sec.scanner import ScanResult, scan
from janus_sec.audit import append_entry
from janus_sec.fix import apply_fix_for_finding

_RISK_ORDER = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2, RiskLevel.INFO: 3}


def _print_human(result: ScanResult) -> None:
    print(f"Scanned {result.files_scanned} file(s), {result.files_missing} not present.\n")

    if not result.findings:
        print("No issues found.")
        return

    sorted_findings = sorted(result.findings, key=lambda f: _RISK_ORDER[f.risk_level])

    for f in sorted_findings:
        print(f"[{f.risk_level.value}] {f.path}")
        print(f"    Issue:  {f.check_type.value} (mode {f.current_mode_octal})")
        print(f"    Why:    {f.reason}")
        if f.suggested_fix_octal is not None:
            print(f"    Fix:    chmod {f.suggested_fix_octal} {f.path}")
        print()

    high_count = sum(1 for f in result.findings if f.risk_level == RiskLevel.HIGH)
    print(f"{len(result.findings)} finding(s) total, {high_count} HIGH risk.")


def _print_json(result: ScanResult) -> None:
    payload = {
        "files_scanned": result.files_scanned,
        "files_missing": result.files_missing,
        "findings": [f.to_json_dict() for f in result.findings],
    }
    print(json.dumps(payload, indent=2))


def _cmd_scan(args: argparse.Namespace) -> int:
    result = scan()

    if args.format == "json":
        _print_json(result)
    else:
        _print_human(result)

    if args.ci:
        high_count = sum(1 for f in result.findings if f.risk_level == RiskLevel.HIGH)
        return 1 if high_count > 0 else 0

    return 0

def _cmd_tui(args: argparse.Namespace) -> int:
    from janus_sec.tui import run_app
    run_app()
    return 0

def _print_planned_fixes(findings: list) -> None:
    print("The following fixes would be applied:\n")
    for f in findings:
        print(f"  {f.path}")
        print(f"    {f.current_mode_octal} -> {f.suggested_fix_octal}  ({f.check_type.value})")
    print()


def _cmd_fix(args: argparse.Namespace) -> int:
    result = scan()

    fixable = [f for f in result.findings if f.suggested_fix_octal is not None]

    if args.path is not None:
        fixable = [f for f in fixable if f.path == args.path]
        if not fixable:
            print(f"No fixable finding for {args.path}.")
            print("(Either it's clean, wasn't scanned, or its issue has no automatic fix.)")
            return 1

    if not fixable:
        print("No fixable findings.")
        return 0

    _print_planned_fixes(fixable)

    if args.dry_run:
        print(f"Dry run - no changes made. {len(fixable)} fix(es) would be applied.")
        return 0

    if not args.yes:
        answer = input(f"Apply {len(fixable)} fix(es)? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted - no changes made.")
            return 1

    succeeded = 0
    failed = 0
    for finding in fixable:
        fix_result = apply_fix_for_finding(finding)
        if fix_result.success:
            succeeded += 1
            append_entry(
                path=fix_result.path,
                before_mode_octal=fix_result.before_mode_octal,
                after_mode_octal=fix_result.after_mode_octal,
                applied_via="cli",
            )
            print(f"  Fixed: {fix_result.path} ({fix_result.before_mode_octal} -> {fix_result.after_mode_octal})")
        else:
            failed += 1
            print(f"  Failed: {fix_result.path} - {fix_result.error}")

    print(f"\n{succeeded} fixed, {failed} failed.")
    return 1 if failed > 0 else 0
    
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="janus-sec",
        description="Scan credential files for unsafe permissions and ownership.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan default credential file locations.")
    scan_parser.add_argument(
        "--format",
        choices=["human", "json"],
        default="human",
        help="Output format (default: human).",
    )
    scan_parser.add_argument(
        "--ci",
        action="store_true",
        help="Exit with status 1 if any HIGH-risk finding exists (for use in CI pipelines).",
    )
    scan_parser.set_defaults(func=_cmd_scan)
    fix_parser = subparsers.add_parser("fix", help="Fix findings from a scan.")
    fix_parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Fix only this specific path. If omitted, fixes all fixable findings.",
    )
    fix_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be fixed without making any changes.",
    )
    fix_parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt (for scripted use).",
    )
    fix_parser.set_defaults(func=_cmd_fix)
    tui_parser = subparsers.add_parser("tui", help="Launch the interactive TUI.")
    tui_parser.set_defaults(func=_cmd_tui)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())