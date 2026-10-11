# ADR-0005: The hardening script runs on bash 3.2

- Status: accepted
- Date: 2026-10-11

## Context

The hardening checks run on Linux hosts. The project's tests and development run on macOS, whose default `/bin/bash` is version 3.2. A script that needs bash 4 features would fail on the development machine, so the tests could not run where the code is written.

## Decision

`hardening/harden.sh` avoids bash 4 features: no associative arrays, no `mapfile`, and no `sed -i`. Edits are written to a temporary file in the same directory and then moved into place. A changed file is backed up once, as `<file>.sentinel.bak`. The `SENTINEL_ROOT` variable prefixes every path, so the tests run against a fixture tree in `tests/fixtures/hardening/`.

## Consequences

- The same script and tests run on macOS and Linux.
- `--apply` never edits a live system during tests, because the tests always set `SENTINEL_ROOT`.
- The script reads config files only. It does not query live sshd or the kernel, so the checklist lists a manual verify command for each check.
- The `--reload` flag, which runs `sysctl -p` and reloads sshd, acts only when `SENTINEL_ROOT` is empty. When `SENTINEL_ROOT` is set, the script prints a note and ignores the flag.
