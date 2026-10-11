"""Tests for pipeline/render_report.py.

The summaries below are small synthetic inputs written inline for these
unit tests. They are not scanner output and are not benchmark results.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline import render_report  # noqa: E402

RENDER_CLI = ROOT / "pipeline" / "render_report.py"
TEMPLATE = ROOT / "reports" / "templates" / "before-after.md.tmpl"
SCAN_TEMPLATE = ROOT / "reports" / "templates" / "scan-summary.md.tmpl"


def _summary(target, totals, counts, failed, threshold="high"):
    return {
        "target": target,
        "generated_at": "2026-01-01T00:00:00Z",
        "threshold": threshold,
        "counts": counts,
        "totals": totals,
        "failed": failed,
        "findings": [],
    }


BEFORE = _summary(
    "vulnerable",
    totals={"critical": 0, "high": 3, "medium": 2, "low": 1, "info": 0},
    counts={
        "semgrep": {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 0},
        "gitleaks": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        "trivy": {"critical": 0, "high": 0, "medium": 1, "low": 1, "info": 0},
    },
    failed=False,
    threshold="none",
)

AFTER = _summary(
    "fixed",
    totals={"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 2},
    counts={
        "semgrep": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 2},
        "trivy": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
    },
    failed=False,
)


def _rows(report):
    return [line for line in report.splitlines() if line.startswith("| ")]


def test_before_after_table_has_one_row_per_severity_with_delta():
    report = render_report.render(BEFORE, AFTER, TEMPLATE)
    assert "| critical | 0 | 0 | 0 |" in report
    assert "| high | 3 | 0 | -3 |" in report
    assert "| medium | 2 | 1 | -1 |" in report
    assert "| low | 1 | 0 | -1 |" in report
    assert "| info | 0 | 2 | +2 |" in report
    severity_rows = [r for r in _rows(report) if r.split("|")[1].strip() in render_report.SEVERITIES]
    assert len(severity_rows) == len(render_report.SEVERITIES)


def test_per_tool_totals_cover_both_runs():
    report = render_report.render(BEFORE, AFTER, TEMPLATE)
    assert "| gitleaks | 1 | not run |" not in report
    assert "| gitleaks | 1 | 0 |" in report
    assert "| semgrep | 3 | 2 |" in report
    assert "| trivy | 2 | 1 |" in report


def test_result_line_reflects_after_gate_and_header_says_generated():
    failing_after = dict(AFTER, failed=True, threshold="high")
    report = render_report.render(BEFORE, failing_after, TEMPLATE)
    assert "**Result: FAIL**" in report
    assert "generated from scanner output" in report.lower()
    passing = render_report.render(BEFORE, AFTER, TEMPLATE)
    assert "**Result: PASS**" in passing


def test_missing_before_shows_not_run():
    report = render_report.render(None, AFTER, TEMPLATE)
    assert "not run" in report
    assert "| high | not run | 0 | not run |" in report
    assert "| semgrep | not run | 2 |" in report
    assert "**Result: PASS**" in report


def test_numbers_come_only_from_input():
    odd = _summary(
        "t",
        totals={"critical": 0, "high": 41, "medium": 0, "low": 0, "info": 0},
        counts={"zap": {"critical": 0, "high": 41, "medium": 0, "low": 0, "info": 0}},
        failed=True,
    )
    report = render_report.render(None, odd, TEMPLATE)
    assert "| high | not run | 41 | not run |" in report
    assert "| zap | not run | 41 |" in report


def test_pipe_in_tool_name_is_escaped():
    weird = _summary("t", totals={s: 0 for s in render_report.SEVERITIES},
                     counts={"a|b": {"high": 1}}, failed=False)
    assert "| a\\|b | not run | 1 |" in render_report.render(None, weird, TEMPLATE)


def test_scan_summary_template_renders():
    text = render_report.render_scan_summary(AFTER, SCAN_TEMPLATE)
    assert "# Sentinel scan summary: fixed" in text
    assert "| high | 0 |" in text
    assert "**Result: PASS**" in text
    assert "generated from scanner output" in text.lower()


def test_templates_are_placeholder_templates_with_header():
    for path in (TEMPLATE, SCAN_TEMPLATE):
        body = path.read_text(encoding="utf-8")
        assert "$" in body
        assert "generated from scanner output" in body.lower()


def test_render_requires_after():
    with pytest.raises(ValueError):
        render_report.render(BEFORE, None, TEMPLATE)


def test_cli_with_only_after_prints_not_run(tmp_path):
    after_path = tmp_path / "after.json"
    after_path.write_text(json.dumps(AFTER), encoding="utf-8")
    out = tmp_path / "before-after.md"
    result = subprocess.run(
        [sys.executable, str(RENDER_CLI), "--after", str(after_path),
         "--template", str(TEMPLATE), "--out", str(out)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    text = out.read_text(encoding="utf-8")
    assert "| high | not run | 0 | not run |" in text
    assert "not run" in text


def test_cli_missing_before_file_is_treated_as_not_run(tmp_path):
    after_path = tmp_path / "after.json"
    after_path.write_text(json.dumps(AFTER), encoding="utf-8")
    out = tmp_path / "report.md"
    result = subprocess.run(
        [sys.executable, str(RENDER_CLI), "--before", str(tmp_path / "absent.json"),
         "--after", str(after_path), "--template", str(TEMPLATE), "--out", str(out)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "| high | not run | 0 | not run |" in out.read_text(encoding="utf-8")


def test_cli_with_both_files(tmp_path):
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(BEFORE), encoding="utf-8")
    after_path.write_text(json.dumps(AFTER), encoding="utf-8")
    out = tmp_path / "report.md"
    result = subprocess.run(
        [sys.executable, str(RENDER_CLI), "--before", str(before_path),
         "--after", str(after_path), "--template", str(TEMPLATE), "--out", str(out)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "| high | 3 | 0 | -3 |" in out.read_text(encoding="utf-8")
