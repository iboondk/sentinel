# Sentinel write-up

## Problem

Small web services often ship with well-known flaws: SQL injection, XSS, shell injection, path traversal, unsafe deserialisation and plaintext passwords. Scanners find them, but each tool uses its own severity names, a fix's effect is hard to show, and attack traces in the logs are not searchable. Sentinel answers three questions: what the scanners find, whether a fix changes the result, and whether the attack shows up in the logs.

## Architecture

A Flask demo app exists in two variants with the same routes: `apps/fixed` (hardened) and `apps/vulnerable` (planted flaws, never deployed). A GitHub Actions workflow runs Semgrep, gitleaks, Trivy and ZAP against each. A stdlib-only gate maps every finding onto one severity scale and fails the job at `high` or worse, and a renderer builds the before/after report from the summaries. Docker compose runs Elasticsearch, Kibana and Filebeat, which ingest the fixed app's JSON request logs. A `harden.sh` script checks Linux SSH, sysctl and file-permission settings.

## Key decisions

The gate uses only the Python standard library, so it needs no install step (ADR-0001). Both apps share one API, so the scanners compare like with like (ADR-0002). All severities map onto one scale with one threshold (ADR-0003). The Elastic stack runs single-node with security off, bound to `127.0.0.1`, as a local demo (ADR-0004). The hardening script avoids bash 4 features so its tests run on macOS (ADR-0005).

## Results

Verified locally:

- The pytest suite passes: 129 tests. They cover the fixed app's routes and headers, the gate's parsers and threshold, the report renderer, the hardening script on good and bad fixture trees, and the structure of the workflow and compose files. The exploit tests for the vulnerable app run under the dev dependencies (Flask 3.1.3), not the Flask 2.2.2 pins used in CI and Docker.
- The workflow and compose YAML parse with PyYAML.

CI:

- The `sentinel-security` workflow failed on GitHub in runs 38172856747 and 38136899692. The scan jobs could not resolve `trivy-action@0.28.0`, so the gate and report jobs never ran. The fix is the tag `v0.28.0` (commit `915b19bb`), plus a test that requires exact tags or SHAs. A green run is not confirmed yet.

Not verified:

- No scanner has run here. Semgrep, Trivy, gitleaks, ZAP, Docker and actionlint are not installed. The scanner files under `tests/fixtures/` are synthetic and labelled as fixtures.
- `docker compose up` has not run, so the stack has not been seen to start.
- No before or after scanner numbers exist yet. No CI run has completed the gate, so `reports/before-after.md` has no real counts. Once a green run exists, the counts will be taken from its `before-after.md` artifact and cited by run ID here.

## What I would do next

Run a full CI pass for real before/after counts. Run `docker compose up` on a machine with Docker and confirm documents reach Kibana. Add the planned Trivy image scan. Enable Elasticsearch security before any shared use. Add live `sshd -T` and `sysctl` checks on a test host, since the script reads only config files today.
