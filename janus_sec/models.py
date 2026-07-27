"""Core data model for janus-sec.

`Finding` is the single unit of data that flows between the scanner, the
TUI, JSON output, and the audit log. Every other module builds on this
shape, so it's treated as a stable contract - once findings start getting
written to JSON output that other tools/scripts consume, changing field
names or types here is a breaking change.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum


class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "high"
    LOW = "low"


class FilesystemType(str, Enum):
    LOCAL = "local"
    NETWORK = "network"
    DRVFS = "drvfs"      # WSL2 Windows-mounted drive
    UNKNOWN = "unknown"


class CheckType(str, Enum):
    WORLD_READABLE = "world_readable"
    WORLD_WRITABLE = "world_writable"
    GROUP_READABLE = "group_readable"
    OWNERSHIP_MISMATCH = "ownership_mismatch"
    SYMLINK_ESCAPE = "symlink_escape"
    UNINSPECTABLE = "uninspectable"
    

@dataclass(frozen=True, slots=True)
class Finding:
    """One detected issue on one file: one path, one risk."""

    path: str
    current_mode_octal: str
    current_mode_human: str
    risk_level: RiskLevel
    check_type: CheckType
    reason: str
    owner: str
    expected_owner: str
    is_symlink: bool
    filesystem_type: FilesystemType
    confidence: Confidence
    suggested_fix_octal: str | None = None
    id: str = field(default="")

    def __post_init__(self) -> None:
        if not self.id:
            # Hash path + check_type, not just path, since a single file
            # can have multiple distinct findings (e.g. world-readable AND
            # wrong owner on the same key) that each need their own stable id.
            digest = hashlib.sha256(
                f"{self.path}:{self.check_type.value}".encode("utf-8")
            ).hexdigest()
            object.__setattr__(self, "id", digest)

    def to_json_dict(self) -> dict:
        d = asdict(self)
        d["risk_level"] = self.risk_level.value
        d["check_type"] = self.check_type.value
        d["filesystem_type"] = self.filesystem_type.value
        d["confidence"] = self.confidence.value
        return d