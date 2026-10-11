# ADR-0003: One severity scale, and the gate fails on high

- Status: accepted
- Date: 2026-10-11

## Context

Semgrep, Trivy, gitleaks and ZAP each use their own severity names: Semgrep uses `ERROR`, `WARNING` and `INFO`, Trivy uses `CRITICAL` to `UNKNOWN`, ZAP uses a numeric `riskcode`, and gitleaks has no severity at all. A gate that compares raw values would need one rule per tool, and the report could not compare tools fairly.

## Decision

Normalise every finding onto `critical, high, medium, low, info`:

- Semgrep: `ERROR` to high, `WARNING` to medium, `INFO` to low.
- Trivy: its own level, lower-cased. Any unknown level becomes info.
- gitleaks: every finding is high, because a committed secret is high risk by default.
- ZAP: riskcode 3 to high, 2 to medium, 1 to low, 0 to info.

The gate exits 1 when any finding is at or above `--fail-on`, which defaults to `high`. The before job uses `--fail-on none`, so it only reports.

## Consequences

- One rule decides pass or fail for all four tools.
- The mapping is a judgement and is written down here. A reviewer can change a row in `pipeline/gate.py` and the tests will show what moves.
- gitleaks findings are never read beyond the rule and location, so the gate never copies a secret value into `summary.json`.
- A missing or empty scanner report counts as zero findings, so the gate can pass when a scanner did not write its file. The workflow uploads every scanner output, so a reviewer can check that each file exists.
