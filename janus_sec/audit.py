"""Append-only audit log of every fix applied.

Deliberately plain text, one line per entry - meant to be human-readable
(tail -f it, grep it) rather than a structured format, since machine-
readable output already exists separately via --format json on scan.

Never logs file CONTENTS, only the operation metadata: what path, what
mode changed to what, when, and how (cli vs tui).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AuditLogEntry:
    timestamp: str  # ISO 8601 UTC
    path: str
    before_mode_octal: str
    after_mode_octal: str
    applied_via: str  # "cli" | "tui"

    def to_line(self) -> str:
        return (
            f"{self.timestamp}  chmod  {self.path}  "
            f"{self.before_mode_octal} -> {self.after_mode_octal}  "
            f"(via {self.applied_via})"
        )


def default_log_path() -> Path:
    # XDG state directory - the conventional home for append-only logs
    # and other "history of what happened" data, distinct from config
    # (XDG_CONFIG_HOME) and cache (XDG_CACHE_HOME).
    xdg_state = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg_state) if xdg_state else Path.home() / ".local" / "state"
    return base / "janus-sec" / "audit.log"


def append_entry(
    path: str,
    before_mode_octal: str,
    after_mode_octal: str,
    applied_via: str,
    log_path: Path | None = None,
) -> AuditLogEntry:
    """Append one entry to the audit log, creating the log file/directory
    if this is the first entry ever written.
    """
    if log_path is None:
        log_path = default_log_path()

    entry = AuditLogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        path=path,
        before_mode_octal=before_mode_octal,
        after_mode_octal=after_mode_octal,
        applied_via=applied_via,
    )

    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(entry.to_line() + "\n")

    return entry


def read_entries(log_path: Path | None = None) -> list[str]:
    """Read raw log lines, most recent last (natural file order).
    Returns an empty list if the log doesn't exist yet - no entries
    logged is not an error.
    """
    if log_path is None:
        log_path = default_log_path()

    if not log_path.exists():
        return []

    with open(log_path, encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip()]