# Contributing to janus-sec

Thanks for considering a contribution. This is a small, focused security
tool, and contributions of any size — bug reports, documentation fixes,
new checks, additional default targets — are welcome.

## Setup

```bash
git clone https://github.com/A-S-Manoj/janus-sec.git
cd janus-sec
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pip install pytest pytest-asyncio
pytest -v
```

The full test suite should pass cleanly before you start making changes.
If it doesn't, please open an issue rather than assuming it's expected.

## Making changes

- **Every behavior change requires a test.** The test suite covers
  checks, the scanner, the CLI, the TUI, and config independently. A pull
  request that changes behavior without a corresponding test will not be
  merged as-is.
- **Checks are pure functions.** Each check in `janus_sec/checks/` takes
  a `FileContext` and returns a `Finding` (or `None`), with no I/O beyond
  what's passed in. This keeps them trivial to test with fake data — new
  checks should follow the same pattern.
- **The safety properties are non-negotiable.** No network access, no
  reading of file contents, no privilege escalation (`sudo`/`chown`), and
  no fix applied without confirmation or an explicit `--dry-run`/`--yes`.
  These are core design constraints, not stylistic preferences — pull
  requests that cross these lines will be declined regardless of the
  feature's usefulness.
- **Test against multiple Python versions if possible.** CI runs the
  suite on Python 3.10, 3.11, and 3.12 — a change that only works on
  your local Python version can still break CI. `pyenv` or similar is
  useful for testing locally against an older version if you're not
  sure.
- **Run the full suite before opening a pull request:**

```bash
pytest -v
```

## Reporting bugs

Please include your OS, Python version, the exact command run, and the
expected versus actual behavior. For detection issues (false positives or
false negatives), include the file's permissions (`ls -la`).

## Reporting security issues

If you find an issue that could let janus-sec be tricked into an unsafe
action — bypassing a confirmation, applying an incorrect fix, or anything
touching the safety properties above — please open an issue describing
the concern rather than submitting a pull request with the fix attached.