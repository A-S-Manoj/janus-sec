# Security Policy

## Reporting a vulnerability

If you find a security issue in janus-sec — something that could let it
be tricked into an unsafe action (bypassing a confirmation, applying an
incorrect fix, escaping its no-network/no-sudo/no-content-reading
guarantees, or anything else that undermines the safety properties
described in the README) — please report it privately rather than
opening a public issue.

Use GitHub's private vulnerability reporting: go to the **Security** tab
of this repository and select **"Report a vulnerability."**

Please include:
- A clear description of the issue and its potential impact
- Steps to reproduce it
- The version of janus-sec and your OS/Python version

## Response

Reports will be acknowledged promptly, and reporters will be credited
(unless otherwise requested) once a fix is released.

## Scope

janus-sec deliberately does not: make network requests, read file
contents, or elevate privileges (no `sudo`/`chown`). If a report
describes behavior outside this scope (e.g. "it doesn't detect a leaked
secret in file contents"), that's expected behavior, not a
vulnerability — see the README's "Why this exists" section for what the
tool is and isn't designed to do.