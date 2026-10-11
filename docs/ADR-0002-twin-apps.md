# ADR-0002: Two Flask apps with the same API, one vulnerable and one fixed

- Status: accepted
- Date: 2026-10-11

## Context

The project has to show what the scanners find before a fix and after it. Scanning one app at two points in time gives a weak comparison, because the scanners' rules and the app's code change together. A deliberately vulnerable app also needs a fixed twin to compare against.

## Decision

Keep two apps with identical routes and response shapes: `apps/vulnerable` (planted flaws, documented in its own `VULNERABILITIES.md`) and `apps/fixed` (the same API with each flaw closed, documented in `apps/fixed/FIXES.md`). The same scanners run on both. The CI job for the fixed app is the gate. The job for the vulnerable app is informational.

## Consequences

- The before/after report compares the same routes under the same scanners.
- `apps/fixed` is the only app that is deployed, scanned by ZAP for the gate, and shipped to the log stack.
- The vulnerable app must never be deployed. The compose file does not include it.
- The "before" job is `continue-on-error`, so a scanner failure on the vulnerable app never turns CI red.
- GitHub dependency alerts will flag `apps/vulnerable/requirements.txt`. That is expected; dismiss them as intentional.
