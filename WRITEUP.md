# Sentinel write-up

## Problem

Small web services often ship with well-known flaws: SQL injection, XSS, shell injection, path traversal, unsafe deserialisation and plaintext passwords. Scanners find them, but each uses its own severity names, a fix's effect is hard to show, and attack traces in logs are not searchable. Sentinel answers three questions: what the scanners find, whether a fix changes the result, and whether the attack shows up in the logs.

## Architecture

A Flask demo app exists in two variants with the same routes: `apps/fixed` (hardened) and `apps/vulnerable` (planted flaws, never deployed). A GitHub Actions workflow runs Semgrep, gitleaks, Trivy and ZAP against each. A stdlib-only gate maps every finding onto one severity scale and fails the job at `high` or worse, and a renderer builds the before/after report. Docker compose runs Elasticsearch, Kibana and Filebeat, which ingest the fixed app's JSON request logs. A `harden.sh` script checks Linux SSH, sysctl and file-permission settings.

## Key decisions

The gate uses only the Python standard library, so it needs no install step (ADR-0001). Both apps share one API, so the scanners compare like with like (ADR-0002). All severities map onto one scale with one threshold (ADR-0003). The Elastic stack runs single-node with security off, bound to `127.0.0.1`, as a local demo (ADR-0004). The hardening script avoids bash 4 features so its tests run on macOS (ADR-0005).

## Results

- 129 pytest tests pass locally. The exploit tests run against Flask 3.1.3, not the Flask 2.2.2 pins used in CI and Docker.
- The `tests` workflow passes on GitHub. The security workflow has not passed yet. Runs 38172856747 and 38136899692 failed because `trivy-action@0.28.0` is not a tag. The fix pins `v0.28.0` (commit `b0715b6`), which is not yet pushed to GitHub.
- No scanner or Docker run has happened, so there are no before/after counts yet. Semgrep, Trivy, gitleaks, ZAP, Docker and actionlint are not installed here.

Full detail is in the README's [Status and known gaps](README.md#status-and-known-gaps).

## What I would do next

Run a full CI pass for real before/after counts. Run `docker compose up` on a machine with Docker and confirm documents reach Kibana. Add the planned Trivy image scan. Enable Elasticsearch security before any shared use. Add live `sshd -T` and `sysctl` checks on a test host, since the script reads only config files today.
