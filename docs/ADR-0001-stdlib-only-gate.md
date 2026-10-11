# ADR-0001: The gate and report renderer use the Python standard library only

- Status: accepted
- Date: 2026-10-11

## Context

The gate (`pipeline/gate.py`) and the report renderer (`pipeline/render_report.py`) run in GitHub Actions on every pull request, and locally on a developer machine. They must parse scanner JSON and write Markdown. The pipeline already installs Semgrep, Trivy, gitleaks and ZAP, so each extra dependency is one more thing to pin, audit and keep current.

## Decision

Both scripts use only the Python 3 standard library: `json`, `argparse`, `pathlib`, `datetime`, and for the renderer `string.Template`. There is no templating library and no third-party parser.

## Consequences

- The gate runs on any runner with Python 3 and needs no install step.
- The gate can be tested with plain pytest fixtures and no mocks of third-party code.
- Markdown is filled through `string.Template` with values read from `summary.json`. The report is therefore traceable to scanner output.
- Scanner JSON formats change over time. The parsers read only the keys they need, and a missing key falls back to an empty value. Malformed JSON still raises an error, so a broken report fails the job.
- We give up Jinja-style templating. The templates are simple enough that this costs nothing.
