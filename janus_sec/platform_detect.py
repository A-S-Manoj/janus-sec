"""Filesystem type detection - local vs network vs WSL DrvFs.

Permission bits mean different things depending on what's actually
enforcing them. A local ext4/xfs/btrfs filesystem genuinely enforces Unix
permissions. NFS/CIFS mounts can have different real enforcement than what
stat() reports. WSL's DrvFs (Windows drives bridged into WSL) famously
reports permission bits that don't correspond to any real enforcement at
all, since NTFS has no native Unix permission model.

This matters because a HIGH-confidence "world_readable" finding on a
filesystem where permissions aren't really enforced is actively
misleading - the file might be far more or less exposed than the mode
bits suggest.
"""

from __future__ import annotations

from pathlib import Path

from janus_sec.models import FilesystemType

_NETWORK_FS_TYPES = {"nfs", "nfs4", "cifs", "smb", "smbfs", "sshfs", "fuse.sshfs"}
_DRVFS_TYPES = {"drvfs", "9p"}  # 9p also used by some WSL configurations


def _read_mounts() -> list[tuple[str, str]]:
    """Returns (mount_point, fs_type) pairs from /proc/mounts.

    Returns an empty list on any failure (e.g. non-Linux, /proc not
    present) - callers should treat that as "couldn't determine, assume
    local" rather than erroring.
    """
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            lines = f.readlines()
    except (FileNotFoundError, PermissionError, OSError):
        return []

    mounts = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            mount_point, fs_type = parts[1], parts[2]
            mounts.append((mount_point, fs_type))
    return mounts


def detect_filesystem_type(path: Path) -> FilesystemType:
    """Determine what kind of filesystem `path` actually lives on, by
    finding the longest matching mount point (the most specific mount
    that contains this path) and checking its reported type.
    """
    mounts = _read_mounts()
    if not mounts:
        return FilesystemType.UNKNOWN

    resolved = path.resolve()
    best_match: tuple[str, str] | None = None

    for mount_point, fs_type in mounts:
        mount_path = Path(mount_point)
        try:
            resolved.relative_to(mount_path)
        except ValueError:
            continue
        # Prefer the most specific (longest) mount point match - e.g.
        # /mnt/c should win over / for a file under /mnt/c/something.
        if best_match is None or len(mount_point) > len(best_match[0]):
            best_match = (mount_point, fs_type)

    if best_match is None:
        return FilesystemType.UNKNOWN

    fs_type = best_match[1].lower()
    if fs_type in _DRVFS_TYPES:
        return FilesystemType.DRVFS
    if fs_type in _NETWORK_FS_TYPES:
        return FilesystemType.NETWORK
    return FilesystemType.LOCAL