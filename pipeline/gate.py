#!/usr/bin/env python3
"""Normalise scanner output onto one severity scale and gate on a threshold.

Python 3 standard library only.

Usage:
    python pipeline/gate.py --target NAME [--semgrep F] [--trivy F]
        [--gitleaks F] [--zap F] [--fail-on high] [--summary-out F]

Exit status: 1 if any finding is at or above --fail-on, else 0.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low", "info")
THRESHOLDS = SEVERITIES + ("none",)
RANK = {sev: len(SEVERITIES) - index for index, sev in enumerate(SEVERITIES)}

SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
ZAP_RISKCODE = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def _load_json(path):
    """Return parsed JSON, or None when the file is missing, empty or null."""
    if path is None:
        return None
    file_path = Path(path)
    if not file_path.is_file():
        return None
    text = file_path.read_text(encoding="utf-8").strip()
    if not text:
        return None
    return json.loads(text)


def _finding(tool, rule_id, severity, location, message):
    return {
        "tool": tool,
        "rule_id": str(rule_id),
        "severity": severity,
        "location": str(location),
        "message": str(message),
    }


def _trivy_severity(raw):
    level = str(raw or "UNKNOWN").strip().lower()
    return level if level in RANK else "info"


def parse_semgrep(path):
    data = _load_json(path)
    if not isinstance(data, dict):
        return []
    findings = []
    for result in data.get("results") or []:
        extra = result.get("extra") or {}
        start = result.get("start") or {}
        raw = str(extra.get("severity", "")).upper()
        findings.append(
            _finding(
                "semgrep",
                result.get("check_id", ""),
                SEMGREP_SEVERITY.get(raw, "info"),
                f"{result.get('path', '')}:{start.get('line', '')}",
                extra.get("message", ""),
            )
        )
    return findings


def parse_trivy(path):
    data = _load_json(path)
    if not isinstance(data, dict):
        return []
    findings = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                _finding(
                    "trivy",
                    vuln.get("VulnerabilityID", ""),
                    _trivy_severity(vuln.get("Severity")),
                    target,
                    vuln.get("Title") or vuln.get("PkgName") or "",
                )
            )
        for misconf in result.get("Misconfigurations") or []:
            findings.append(
                _finding(
                    "trivy",
                    misconf.get("ID", ""),
                    _trivy_severity(misconf.get("Severity")),
                    target,
                    misconf.get("Title") or "",
                )
            )
    return findings


def parse_gitleaks(path):
    # Secret and Match are deliberately never read: only the rule and the
    # location leave this function.
    data = _load_json(path)
    if not isinstance(data, list):
        return []
    findings = []
    for item in data:
        rule = item.get("RuleID", "")
        location = f"{item.get('File', '')}:{item.get('StartLine', '')}"
        findings.append(_finding("gitleaks", rule, "high", location, rule))
    return findings


def parse_zap(path):
    data = _load_json(path)
    if not isinstance(data, dict):
        return []
    findings = []
    for site in data.get("site") or []:
        for alert in site.get("alerts") or []:
            risk = str(alert.get("riskcode", "0")).strip()
            location = alert.get("uri") or site.get("@name", "")
            findings.append(
                _finding(
                    "zap",
                    alert.get("pluginid", ""),
                    ZAP_RISKCODE.get(risk, "info"),
                    location,
                    alert.get("alert") or alert.get("name") or "",
                )
            )
    return findings


def summarize(findings, target, threshold):
    if threshold not in THRESHOLDS:
        raise ValueError(f"threshold must be one of {', '.join(THRESHOLDS)}")

    totals = {sev: 0 for sev in SEVERITIES}
    counts = {}
    for finding in findings:
        severity = finding["severity"]
        totals[severity] += 1
        tool_counts = counts.setdefault(finding["tool"], {sev: 0 for sev in SEVERITIES})
        tool_counts[severity] += 1

    failed = threshold != "none" and any(
        RANK[finding["severity"]] >= RANK[threshold] for finding in findings
    )
    ordered = sorted(findings, key=lambda finding: -RANK[finding["severity"]])

    return {
        "target": target,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "threshold": threshold,
        "counts": counts,
        "totals": totals,
        "failed": failed,
        "findings": ordered,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Normalise scanner output and gate on severity.")
    parser.add_argument("--target", required=True, help="name of the scanned target")
    parser.add_argument("--semgrep", help="semgrep JSON report")
    parser.add_argument("--trivy", help="trivy JSON report")
    parser.add_argument("--gitleaks", help="gitleaks JSON report")
    parser.add_argument("--zap", help="OWASP ZAP JSON report")
    parser.add_argument("--fail-on", default="high", choices=THRESHOLDS)
    parser.add_argument("--summary-out", default="summary.json", help="where to write summary JSON")
    args = parser.parse_args(argv)

    findings = []
    findings += parse_semgrep(args.semgrep)
    findings += parse_trivy(args.trivy)
    findings += parse_gitleaks(args.gitleaks)
    findings += parse_zap(args.zap)

    summary = summarize(findings, args.target, args.fail_on)
    Path(args.summary_out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    for sev in SEVERITIES:
        print(f"{sev:<10}{summary['totals'][sev]:>6}")
    result = "FAIL" if summary["failed"] else "PASS"
    print(f"target={args.target} threshold={args.fail_on} result={result}")
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
