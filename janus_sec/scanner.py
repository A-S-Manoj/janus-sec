"""Walks the target list, inspects each file, and runs all checks.

This is the piece that ties the target list, FileContext, and the four
individual checks together into one final list of findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from janus_sec.checks.context import build_context
from janus_sec.checks import world_permissions, ownership, group_ownership, symlinks
from janus_sec.checks.group_ownership import AllowlistPattern, load_allowlist
from janus_sec.checks.identity import username_for_uid
from janus_sec.models import CheckType, Confidence, Finding, FilesystemType, RiskLevel
from janus_sec.targets import TargetGroup, default_targets
from janus_sec.config import Config, filter_ignored, load_config


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: list[Finding]
    files_scanned: int
    files_missing: int


def _detect_filesystem_type(path: Path) -> FilesystemType:
    # Placeholder for now - real network/DrvFs detection comes later as its
    # own module. Everything is treated as local until then.
    return FilesystemType.LOCAL


def _uninspectable_finding(
    path: Path, reason_detail: str, filesystem_type: FilesystemType
) -> Finding:
    return Finding(
        path=str(path),
        current_mode_octal="???",
        current_mode_human="?",
        risk_level=RiskLevel.INFO,
        check_type=CheckType.UNINSPECTABLE,
        reason=(
            f"janus-sec could not inspect this file ({reason_detail}). "
            "It may still be a security concern - worth checking manually."
        ),
        owner="unknown",
        expected_owner="unknown",
        is_symlink=False,
        filesystem_type=filesystem_type,
        confidence=Confidence.LOW,
        suggested_fix_octal=None,
    )


def _scan_one_file(
    path: Path,
    expected_root: Path,
    allowlist: list[AllowlistPattern],
) -> list[Finding]:
    filesystem_type = _detect_filesystem_type(path)

    try:
        ctx = build_context(path)
    except PermissionError:
        return [_uninspectable_finding(path, "permission denied", filesystem_type)]
    except FileNotFoundError:
        return [_uninspectable_finding(path, "vanished during scan", filesystem_type)]

    if ctx.resolve_error is not None:
        return [_uninspectable_finding(path, ctx.resolve_error, filesystem_type)]

    findings: list[Finding] = []

    wp_finding = world_permissions.check(ctx, filesystem_type)
    if wp_finding is not None:
        findings.append(wp_finding)

    own_finding = ownership.check(ctx, filesystem_type)
    if own_finding is not None:
        findings.append(own_finding)

    grp_finding = group_ownership.check(ctx, filesystem_type, allowlist=allowlist)
    if grp_finding is not None:
        findings.append(grp_finding)

    sym_finding = symlinks.check(ctx, filesystem_type, expected_root=expected_root)
    if sym_finding is not None:
        findings.append(sym_finding)

    return findings


def scan(targets: list[TargetGroup] | None = None) -> ScanResult:
    if targets is None:
        targets = default_targets()

    config = load_config()
    allowlist = load_allowlist() + config.allowlist
    all_findings: list[Finding] = []
    files_scanned = 0
    files_missing = 0

    for group in targets:
        for filename in group.files:
            path = group.expected_root / filename

            # lstat, not exists(), because exists() follows symlinks and
            # would report False for a broken symlink - which is a real
            # finding we want to surface, not silently skip.
            try:
                path.lstat()
            except FileNotFoundError:
                files_missing += 1
                continue
            except PermissionError:
                files_scanned += 1
                filesystem_type = _detect_filesystem_type(path)
                all_findings.append(
                    _uninspectable_finding(path, "permission denied", filesystem_type)
                )
                continue

            files_scanned += 1
            all_findings.extend(
                _scan_one_file(path, group.expected_root, allowlist)
            )
    all_findings = filter_ignored(all_findings, config)
    return ScanResult(
        findings=all_findings,
        files_scanned=files_scanned,
        files_missing=files_missing,
    )