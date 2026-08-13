"""uid/gid -> name resolution, shared across checks.

Centralized here so every check reports human-readable owner/group names
consistently, and lookup failures (e.g. a uid with no matching /etc/passwd
entry, which can happen in some containers) are handled in one place.
"""

from __future__ import annotations

import grp
import os
import pwd


def username_for_uid(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def groupname_for_gid(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def current_uid() -> int:
    return os.geteuid()


def current_username() -> str:
    return username_for_uid(current_uid())


def current_primary_gid() -> int:
    return os.getgid()


def current_group_ids() -> set[int]:
    groups = {current_primary_gid()}
    if hasattr(os, "getgroups"):
        try:
            groups.update(os.getgroups())
        except OSError:
            pass
    return groups