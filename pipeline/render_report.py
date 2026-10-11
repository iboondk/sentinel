#!/usr/bin/env python3
"""Render the before/after Markdown report from gate summary JSON files.

Python 3 standard library only. Every number in the output comes from the
input summary JSON (the files written by pipeline/gate.py). Nothing is typed
in by hand.

Usage:
    python pipeline/render_report.py --after F [--before F]
        [--template reports/templates/before-after.md.tmpl] --out F

When --before is omitted, or the file it names does not exist, the before
column shows "not run".
"""

import argparse
import json
import sys
from pathlib import Path
from string import Template

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TEMPLATE = ROOT / "reports" / "templates" / "before-after.md.tmpl"
SCAN_SUMMARY_TEMPLATE = ROOT / "reports" / "templates" / "scan-summary.md.tmpl"

SEVERITIES = ("critical", "high", "medium", "low", "info")
NOT_RUN = "not run"


def _cell(value):
    """Make a value safe to place inside a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def _total(summary, severity):
    totals = (summary or {}).get("totals") or {}
    return int(totals.get(severity, 0))


def _tool_totals(summary):
    counts = (summary or {}).get("counts") or {}
    return {
        tool: sum(int(value) for value in by_severity.values())
        for tool, by_severity in counts.items()
    }


def _gate_word(summary):
    return "FAIL" if summary.get("failed") else "PASS"


def _gate_line(summary):
    if summary is None:
        return NOT_RUN
    return f"{_gate_word(summary)} (threshold: {summary.get('threshold', 'high')})"


def _severity_rows(before, after):
    rows = []
    for severity in SEVERITIES:
        after_count = _total(after, severity)
        if before is None:
            before_cell, delta_cell = NOT_RUN, NOT_RUN
        else:
            before_count = _total(before, severity)
            delta = after_count - before_count
            before_cell = str(before_count)
            delta_cell = f"{delta:+d}" if delta else "0"
        rows.append(f"| {severity} | {before_cell} | {after_count} | {delta_cell} |")
    return "\n".join(rows)


def _tool_rows(before, after):
    after_tools = _tool_totals(after)
    before_tools = _tool_totals(before) if before is not None else {}
    names = sorted(set(after_tools) | set(before_tools))
    if not names:
        return "| (no tools reported) | | |"
    rows = []
    for name in names:
        before_cell = NOT_RUN if before is None else str(before_tools.get(name, 0))
        rows.append(f"| {_cell(name)} | {before_cell} | {after_tools.get(name, 0)} |")
    return "\n".join(rows)


def render(before_summary, after_summary, template_path):
    """Return the filled before/after report as Markdown text.

    before_summary may be None, in which case the before column reads
    "not run". after_summary is required. The result line reflects the
    after gate, because the before run uses --fail-on none.
    """
    if after_summary is None:
        raise ValueError("after_summary is required")

    template = Template(Path(template_path).read_text(encoding="utf-8"))
    after_gate = _gate_word(after_summary)
    return template.substitute(
        generated_at=_cell(after_summary.get("generated_at", "unknown")),
        before_target=_cell(before_summary.get("target", "unknown")) if before_summary else NOT_RUN,
        after_target=_cell(after_summary.get("target", "unknown")),
        severity_rows=_severity_rows(before_summary, after_summary),
        tool_rows=_tool_rows(before_summary, after_summary),
        before_gate=_gate_line(before_summary),
        after_gate=_gate_line(after_summary),
        result=after_gate,
    ) + "\n"


def render_scan_summary(summary, template_path=SCAN_SUMMARY_TEMPLATE):
    """Return a single-scan Markdown summary (scan-summary.md.tmpl)."""
    if summary is None:
        raise ValueError("summary is required")
    template = Template(Path(template_path).read_text(encoding="utf-8"))
    severity_rows = "\n".join(
        f"| {severity} | {_total(summary, severity)} |" for severity in SEVERITIES
    )
    tool_rows = "\n".join(
        f"| {_cell(name)} | {total} |" for name, total in sorted(_tool_totals(summary).items())
    ) or "| (no tools reported) | |"
    return template.substitute(
        target=_cell(summary.get("target", "unknown")),
        generated_at=_cell(summary.get("generated_at", "unknown")),
        threshold=_cell(summary.get("threshold", "high")),
        severity_rows=severity_rows,
        tool_rows=tool_rows,
        result=_gate_word(summary),
    ) + "\n"


def _load_summary(path, required):
    """Return parsed summary JSON, or None when an optional file is absent."""
    if path is None:
        if required:
            raise SystemExit("error: --after is required")
        return None
    file_path = Path(path)
    if not file_path.is_file():
        if required:
            raise SystemExit(f"error: summary not found: {path}")
        print(f"note: {path} not found, before column shows '{NOT_RUN}'", file=sys.stderr)
        return None
    return json.loads(file_path.read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Render the before/after scan report.")
    parser.add_argument("--before", help="gate summary JSON from the before run (optional)")
    parser.add_argument("--after", required=True, help="gate summary JSON from the after run")
    parser.add_argument("--template", default=str(DEFAULT_TEMPLATE), help="Markdown template")
    parser.add_argument("--out", required=True, help="where to write the Markdown report")
    args = parser.parse_args(argv)

    before = _load_summary(args.before, required=False)
    after = _load_summary(args.after, required=True)
    report = render(before, after, args.template)
    Path(args.out).write_text(report, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
