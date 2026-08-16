"""World-readable / world-writable permission bit detection.

Anyone on this machine, regardless of user or group, can read (or write)
a file with these bits set. For credential files this is close to the
worst case short of the file being actively leaked - any local process
or account can grab it.
"""

from __future__ import annotations

import stat

from janus_sec.checks._shared import build_finding
from janus_sec.checks.context import FileContext
from janus_sec.models import CheckType, Finding, FilesystemType, RiskLevel

_WORLD_READ = stat.S_IROTH
_WORLD_WRITE = stat.S_IWOTH


def check(ctx: FileContext, filesystem_type: FilesystemType) -> Finding | None:
    if ctx.resolved_stat is None:
        return None  # uninspectable - the scanner reports this case separately

    mode = ctx.resolved_stat.st_mode

    # Credential files have no legitimate reason to be group- or
    # world-accessible, so the suggested fix always goes straight to
    # owner-only rather than just clearing the one bit that triggered
    # the finding.
    owner_only = oct(stat.S_IMODE(mode) & stat.S_IRWXU)[2:].zfill(3)

    if mode & _WORLD_WRITE:
        return build_finding(
            ctx,
            filesystem_type,
            check_type=CheckType.WORLD_WRITABLE,
            risk_level=RiskLevel.HIGH,
            reason=(
                "This file is writable by any local user on this machine, "
                "meaning another account (or a compromised process running "
                "as another user) could modify or corrupt it."
            ),
            suggested_fix_octal=owner_only,
        )

    if mode & _WORLD_READ:
        return build_finding(
            ctx,
            filesystem_type,
            check_type=CheckType.WORLD_READABLE,
            risk_level=RiskLevel.HIGH,
            reason=(
                "This file is readable by any local user on this machine. "
                "Credential files should only be readable by their owner."
            ),
            suggested_fix_octal=owner_only,
        )

    return None