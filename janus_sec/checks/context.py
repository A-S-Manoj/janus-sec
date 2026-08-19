"""Shared per-file inspection, done once per file.

Multiple checks (world-readable, ownership, symlink escape, etc.) all need
to know things like "what are this file's permission bits" and "is this a
symlink". Rather than have every check call os.stat() itself - which means
redundant syscalls and a risk of the file changing between two of those
calls - we gather everything once into FileContext and pass that into
each check function.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class FileContext:
    path: Path
    lstat_result: os.stat_result   # info about the path itself, never follows symlinks
    is_symlink: bool
    # None if the file doesn't exist, is a broken symlink, or we don't have
    # permission to read its metadata. Checks must treat None as "this file
    # can't be inspected" rather than assuming any particular state.
    resolved_stat: os.stat_result | None
    # The symlink target, resolved in the same pass as resolved_stat above, so
    # a check reporting both a target's path and its mode describes a single
    # observation. None when the file could not be inspected, or when the path
    # could not be resolved at all (a symlink loop, say).
    resolved_path: Path | None
    resolve_error: str | None   # "denied" | "broken_symlink" | None


def build_context(path: Path) -> FileContext:
    """Gather everything a check function needs about one file, in one pass."""
    lstat_result = os.lstat(path)
    is_symlink = stat.S_ISLNK(lstat_result.st_mode)

    resolved_stat: os.stat_result | None = None
    resolve_error: str | None = None
    try:
        resolved_stat = os.stat(path)
    except PermissionError:
        resolve_error = "denied"
    except FileNotFoundError:
        # A regular file can't hit FileNotFoundError here (lstat already
        # succeeded, so something exists at `path`). This case only really
        # happens when `path` is a symlink pointing at a target that's gone.
        resolve_error = "broken_symlink" if is_symlink else "denied"

    # Resolved here rather than in the checks, for the reason this module
    # exists: a check that resolves the path itself is reading the filesystem
    # at a different moment from the stat above, and can end up describing the
    # mode of one target and the path of another.
    resolved_path: Path | None = None
    if resolved_stat is not None:
        try:
            resolved_path = path.resolve()
        except OSError:
            # A symlink loop, or anything else the kernel refuses to resolve.
            # Uninspectable rather than fatal - one pathological file should
            # not end the scan.
            resolved_path = None

    return FileContext(
        path=path,
        lstat_result=lstat_result,
        is_symlink=is_symlink,
        resolved_stat=resolved_stat,
        resolved_path=resolved_path,
        resolve_error=resolve_error,
    )