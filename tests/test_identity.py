"""Tests for identity resolution helpers."""

import os
from unittest.mock import patch

from janus_sec.checks import identity


def test_current_group_ids_includes_primary_gid() -> None:
    primary = identity.current_primary_gid()
    group_ids = identity.current_group_ids()
    assert primary in group_ids


def test_current_group_ids_includes_supplementary_groups() -> None:
    if hasattr(os, "getgroups"):
        try:
            supp = os.getgroups()
            group_ids = identity.current_group_ids()
            for g in supp:
                assert g in group_ids
        except OSError:
            pass


def test_current_group_ids_handles_oserror() -> None:
    if hasattr(os, "getgroups"):
        with patch("os.getgroups", side_effect=OSError("Not permitted")):
            group_ids = identity.current_group_ids()
            assert identity.current_primary_gid() in group_ids
