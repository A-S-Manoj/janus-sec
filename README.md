# janus-sec

![Tests](https://github.com/A-S-Manoj/janus-sec/actions/workflows/tests.yml/badge.svg)

**A terminal-first credential exposure auditor.**

Your SSH keys, AWS credentials, and kube config are only as safe as their file
permissions. A `chmod 644` typo, a bad tarball extraction, or a cloud sync
tool can quietly leave a private key readable by every user on your machine
— and there's usually no warning until something goes wrong.

`janus-sec` scans the credential files you already have, tells you exactly
what's wrong and why it matters, and fixes it with one confirmed keystroke.
Nothing leaves your machine — no network calls, no file content is ever
read, no `sudo`.

```
$ janus-sec
Scanned 4 file(s), 8 not present.

[HIGH] /home/user/.ssh/id_rsa
    Issue:  world_readable (mode 644)
    Why:    This file is readable by any local user on this machine.
            Credential files should only be readable by their owner.
    Fix:    chmod 600 /home/user/.ssh/id_rsa

[MEDIUM] /home/user/.aws/credentials
    Issue:  group_readable (mode 640)
    Why:    This file is readable by group 'docker', which is not your
            primary group. Other accounts in that group can read this file.
    Fix:    chmod 600 /home/user/.aws/credentials

2 finding(s) total, 1 HIGH risk.
```

## Why this exists

The underlying check here is genuinely simple — `find ~/.ssh -perm /077`
does most of the mechanical work in one line. That's not the point.
The gap `janus-sec` closes isn't "how do I check this," it's "I never
thought to check this, and if I did, I wouldn't trust a one-off command
to tell me what to do about it or keep a record that I did it."

Concretely, what a one-liner doesn't give you:
- **An explanation.** `-rw-r--r--` means nothing to most people at a
  glance. "This private key is readable by any local user on this
  machine" changes behavior.
- **The right fix for each file type.** SSH keys, `known_hosts`, AWS
  credentials, and kube configs don't all want the same target mode.
- **A safe way to apply it.** Confirmation by default, `--dry-run` to
  preview, and a re-check immediately before writing (the file you
  looked at when scanning might not be the file you're about to change).
- **A record.** An append-only audit log of every fix, so "what did I
  change and when" has a real answer.
- **A CI gate.** `--ci` exits non-zero on any HIGH-risk finding, so this
  can fail a pipeline, not just print a warning nobody reads.

## What it checks

| Check | Risk | Auto-fix? |
|---|---|---|
| World-readable / world-writable | HIGH | Yes |
| Owned by a different user | HIGH | No — would require `sudo`, out of scope |
| Group-readable (non-primary group) | MEDIUM | Yes |
| Symlink pointing outside its expected directory | MEDIUM | No — target choice is a judgment call |

Scans by default: `~/.ssh/*`, `~/.aws/*`, `~/.kube/config`, `~/.npmrc`,
`~/.git-credentials`, `~/.docker/config.json`. Missing files are silently
skipped, not errors — most people won't have all of these.

## Safety properties

- **No network access, ever.**
- **Never reads file contents** — only metadata (permissions, ownership).
  It can't tell you if a secret has leaked; it tells you if the file is
  more exposed than it should be.
- **Never elevates privileges.** No `sudo`, no `chown`. If a fix would
  require that, `janus-sec` reports the problem and stops — it doesn't
  attempt it.
- **Every fix requires confirmation** (or an explicit `--yes` for
  scripted use), and `--dry-run` previews changes with zero side effects.
- **Append-only audit log** of every fix applied, at
  `~/.local/state/janus-sec/audit.log`.

Found a security issue? See [SECURITY.md](SECURITY.md) for how to report it.

## Install

```bash
pip install janus-sec
```

Or from source, for development:

```bash
git clone https://github.com/A-S-Manoj/janus-sec.git
cd janus-sec
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# Scan (also the default with no arguments - read-only, safe to run any time)
janus-sec
janus-sec scan

# Interactive TUI
janus-sec tui

# Machine-readable output
janus-sec scan --format json

# CI mode: exit 1 if any HIGH-risk finding exists
janus-sec scan --ci

# Fix everything fixable, with confirmation
janus-sec fix

# Fix one specific file
janus-sec fix ~/.ssh/id_rsa

# Preview fixes without changing anything
janus-sec fix --dry-run

# Skip the confirmation prompt (for scripts)
janus-sec fix --yes
```

## Configuration

`~/.config/janus-sec/config.toml` (optional — everything works with no
config file at all):

```toml
# Suppress a specific check on a specific file - not the whole file,
# just that one issue, so other real problems on it still get caught.
[[ignore]]
path = "/home/user/.ssh/known_hosts"
check_type = "group_readable"
note = "shared dev box, group access is intentional"

# Treat a group as known-safe, machine-wide.
[[allowlist]]
group = "wheel"
action = "suppress"   # or "downgrade_to_low"
note = "trusted admin group on my machines"
```

## Development

Same setup as above, plus test dependencies:

```bash
pip install pytest pytest-asyncio
pytest -v
```

## License

MIT