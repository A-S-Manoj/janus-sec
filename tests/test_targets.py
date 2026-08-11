"""Tests for the default target list."""

from pathlib import Path

from janus_sec.targets import default_targets, TargetGroup


def test_default_targets_returns_groups() -> None:
    targets = default_targets()

    assert len(targets) > 0
    assert all(isinstance(t, TargetGroup) for t in targets)


def test_group_names_are_unique() -> None:
    targets = default_targets()
    names = [t.name for t in targets]

    assert len(names) == len(set(names))


def test_every_group_has_at_least_one_file() -> None:
    targets = default_targets()

    for group in targets:
        assert len(group.files) > 0, f"{group.name} has no files"


def test_ssh_group_root_is_dot_ssh() -> None:
    targets = default_targets()
    ssh_group = next(t for t in targets if t.name == "ssh")

    assert ssh_group.expected_root == Path.home() / ".ssh"
    assert "id_rsa" in ssh_group.files


def test_npm_and_git_root_directly_at_home() -> None:
    # These are standalone dotfiles, not their own subdirectory - the
    # expected_root should be the home directory itself, not home/.npm or
    # similar. Worth locking down since it's an easy thing to fat-finger.
    targets = default_targets()
    npm_group = next(t for t in targets if t.name == "npm")
    git_group = next(t for t in targets if t.name == "git")

    assert npm_group.expected_root == Path.home()
    assert git_group.expected_root == Path.home()


def test_resolved_paths_are_absolute() -> None:
    # Every actual file path the scanner will check should be absolute -
    # a relative path here would cause bugs depending on the working
    # directory the tool happens to be run from.
    targets = default_targets()

    for group in targets:
        for filename in group.files:
            full_path = group.expected_root / filename
            assert full_path.is_absolute()

def test_gcloud_group_exists() -> None:
    targets = default_targets()
    gcloud_group = next(t for t in targets if t.name == "gcloud")

    assert gcloud_group.expected_root == Path.home() / ".config" / "gcloud"
    assert len(gcloud_group.files) > 0


def test_azure_group_exists() -> None:
    targets = default_targets()
    azure_group = next(t for t in targets if t.name == "azure")

    assert azure_group.expected_root == Path.home() / ".azure"
    assert len(azure_group.files) > 0


def test_gh_group_exists() -> None:
    targets = default_targets()
    gh_group = next(t for t in targets if t.name == "gh")

    assert gh_group.expected_root == Path.home() / ".config" / "gh"
    assert "hosts.yml" in gh_group.files
