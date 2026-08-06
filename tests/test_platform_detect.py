"""Tests for filesystem type detection via /proc/mounts."""

from pathlib import Path
from unittest.mock import mock_open, patch

from janus_sec.platform_detect import detect_filesystem_type
from janus_sec.models import FilesystemType


_FAKE_MOUNTS = """\
/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid 0 0
C:\\ /mnt/c drvfs rw,relatime 0 0
fileserver:/export /mnt/nfs nfs4 rw,relatime 0 0
"""


def test_local_path_detected(tmp_path: Path) -> None:
    with patch("builtins.open", mock_open(read_data=_FAKE_MOUNTS)):
        result = detect_filesystem_type(Path("/some/local/path"))

    assert result == FilesystemType.LOCAL


def test_drvfs_path_detected() -> None:
    with patch("builtins.open", mock_open(read_data=_FAKE_MOUNTS)):
        result = detect_filesystem_type(Path("/mnt/c/Users/ezio/.ssh/id_rsa"))

    assert result == FilesystemType.DRVFS


def test_network_path_detected() -> None:
    with patch("builtins.open", mock_open(read_data=_FAKE_MOUNTS)):
        result = detect_filesystem_type(Path("/mnt/nfs/shared/config"))

    assert result == FilesystemType.NETWORK


def test_most_specific_mount_wins() -> None:
    # /mnt/c/Users/... is technically also "under" / , but the more
    # specific /mnt/c mount (drvfs) should win, not the root ext4 mount.
    with patch("builtins.open", mock_open(read_data=_FAKE_MOUNTS)):
        result = detect_filesystem_type(Path("/mnt/c/something"))

    assert result == FilesystemType.DRVFS


def test_unreadable_proc_mounts_returns_unknown() -> None:
    with patch("builtins.open", side_effect=FileNotFoundError):
        result = detect_filesystem_type(Path("/anything"))

    assert result == FilesystemType.UNKNOWN


def test_real_system_does_not_crash() -> None:
    # Smoke test against the ACTUAL machine's real /proc/mounts - just
    # confirming it runs without error and returns a valid enum member,
    # not asserting a specific value since that depends on the machine.
    result = detect_filesystem_type(Path.home())
    assert isinstance(result, FilesystemType)