import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline import gate  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "scanners"
GATE_CLI = ROOT / "pipeline" / "gate.py"


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _run_cli(args, cwd):
    return subprocess.run(
        [sys.executable, str(GATE_CLI), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def _fixture_args():
    return [
        "--target", "fixture",
        "--semgrep", str(FIXTURES / "semgrep.json"),
        "--trivy", str(FIXTURES / "trivy.json"),
        "--gitleaks", str(FIXTURES / "gitleaks.json"),
        "--zap", str(FIXTURES / "zap.json"),
    ]


# --- parser mappings -------------------------------------------------------

def test_semgrep_maps_severity_and_location():
    findings = gate.parse_semgrep(FIXTURES / "semgrep.json")
    by_rule = {f["rule_id"]: f for f in findings}
    assert by_rule["sentinel.fixture-error-rule"]["severity"] == "high"
    assert by_rule["sentinel.fixture-warning-rule"]["severity"] == "medium"
    assert by_rule["sentinel.fixture-info-rule"]["severity"] == "low"
    assert by_rule["sentinel.fixture-error-rule"]["location"] == (
        "apps/vulnerable/sentinel_vuln/__init__.py:42"
    )
    assert all(f["tool"] == "semgrep" for f in findings)
    assert set(findings[0]) == {"tool", "rule_id", "severity", "location", "message"}


def test_trivy_maps_vulns_lowercased_with_unknown_as_info(tmp_path):
    findings = gate.parse_trivy(FIXTURES / "trivy.json")
    vulns = {f["rule_id"]: f for f in findings if f["rule_id"].startswith("CVE-")}
    assert vulns["CVE-0000-0001"]["severity"] == "high"
    assert vulns["CVE-0000-0002"]["severity"] == "info"
    assert vulns["CVE-0000-0001"]["location"] == "apps/vulnerable/requirements.txt"
    assert all(f["tool"] == "trivy" for f in findings)


def test_trivy_includes_misconfigurations_the_same_way():
    findings = gate.parse_trivy(FIXTURES / "trivy.json")
    misconf = [f for f in findings if f["rule_id"] == "FIX-DS-0001"]
    assert len(misconf) == 1
    assert misconf[0]["severity"] == "medium"
    assert misconf[0]["location"] == "Dockerfile"


def test_gitleaks_every_item_is_high_and_message_is_rule_only():
    findings = gate.parse_gitleaks(FIXTURES / "gitleaks.json")
    assert len(findings) == 2
    for finding in findings:
        assert finding["severity"] == "high"
        assert finding["message"] == finding["rule_id"]
        assert finding["tool"] == "gitleaks"
    assert findings[0]["location"] == "apps/vulnerable/sentinel_vuln/__init__.py:12"


def test_gitleaks_never_copies_secret_or_match(tmp_path):
    secret_file = _write(
        tmp_path,
        "gitleaks.json",
        json.dumps([{
            "RuleID": "fixture-rule",
            "File": "a.py",
            "StartLine": 1,
            "Secret": "SHOULD-NOT-LEAK",
            "Match": "SHOULD-NOT-LEAK",
        }]),
    )
    findings = gate.parse_gitleaks(secret_file)
    assert "SHOULD-NOT-LEAK" not in json.dumps(findings)


def test_zap_maps_riskcode_and_uses_pluginid():
    findings = gate.parse_zap(FIXTURES / "zap.json")
    by_plugin = {f["rule_id"]: f for f in findings}
    assert by_plugin["90000"]["severity"] == "high"
    assert by_plugin["90001"]["severity"] == "medium"
    assert by_plugin["90002"]["severity"] == "low"
    assert by_plugin["90003"]["severity"] == "info"
    assert by_plugin["90000"]["location"] == "http://127.0.0.1:5002/search"
    assert all(f["tool"] == "zap" for f in findings)


# --- missing and empty inputs ----------------------------------------------

@pytest.mark.parametrize(
    "parser",
    [gate.parse_semgrep, gate.parse_trivy, gate.parse_gitleaks, gate.parse_zap],
)
def test_missing_file_yields_empty_list(parser, tmp_path):
    assert parser(tmp_path / "does-not-exist.json") == []


@pytest.mark.parametrize(
    "parser",
    [gate.parse_semgrep, gate.parse_trivy, gate.parse_gitleaks, gate.parse_zap],
)
@pytest.mark.parametrize("content", ["", "   \n", "null"])
def test_empty_or_null_input_yields_empty_list(parser, content, tmp_path):
    path = _write(tmp_path, "scan.json", content)
    assert parser(path) == []


def test_missing_results_key_yields_empty_list(tmp_path):
    path = _write(tmp_path, "semgrep.json", json.dumps({"errors": []}))
    assert gate.parse_semgrep(path) == []


# --- summarize -------------------------------------------------------------

def _finding(tool, severity):
    return {"tool": tool, "rule_id": "r", "severity": severity, "location": "x", "message": "m"}


def test_summarize_totals_and_counts():
    findings = [
        _finding("semgrep", "high"),
        _finding("semgrep", "medium"),
        _finding("trivy", "high"),
        _finding("zap", "info"),
    ]
    summary = gate.summarize(findings, "demo", "high")
    assert summary["target"] == "demo"
    assert summary["threshold"] == "high"
    assert summary["totals"] == {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 1}
    assert summary["counts"]["semgrep"] == {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0}
    assert summary["counts"]["trivy"]["high"] == 1
    assert summary["failed"] is True
    assert summary["generated_at"].endswith("Z")
    ranks = [gate.RANK[f["severity"]] for f in summary["findings"]]
    assert ranks == sorted(ranks, reverse=True)


def test_summarize_failed_false_when_only_below_threshold():
    findings = [_finding("semgrep", "medium"), _finding("zap", "low")]
    assert gate.summarize(findings, "demo", "high")["failed"] is False


def test_summarize_threshold_none_never_fails():
    findings = [_finding("gitleaks", "high")]
    assert gate.summarize(findings, "demo", "none")["failed"] is False


def test_summarize_rejects_unknown_threshold():
    with pytest.raises(ValueError):
        gate.summarize([], "demo", "severe")


# --- CLI -------------------------------------------------------------------

def test_cli_exit_1_on_fixtures_with_fail_on_high(tmp_path):
    result = _run_cli([*_fixture_args(), "--fail-on", "high", "--summary-out", "s.json"], tmp_path)
    assert result.returncode == 1
    summary = json.loads((tmp_path / "s.json").read_text(encoding="utf-8"))
    assert summary["failed"] is True
    assert summary["totals"]["high"] >= 1


def test_cli_exit_0_with_fail_on_none(tmp_path):
    result = _run_cli([*_fixture_args(), "--fail-on", "none", "--summary-out", "s.json"], tmp_path)
    assert result.returncode == 0
    summary = json.loads((tmp_path / "s.json").read_text(encoding="utf-8"))
    assert summary["failed"] is False


def test_cli_exit_0_when_only_medium_and_threshold_high(tmp_path):
    semgrep = _write(
        tmp_path,
        "semgrep.json",
        json.dumps({"results": [{
            "check_id": "medium-only",
            "path": "a.py",
            "start": {"line": 3},
            "extra": {"severity": "WARNING", "message": "medium"},
        }]}),
    )
    result = _run_cli(
        ["--target", "medium-only", "--semgrep", str(semgrep), "--fail-on", "high",
         "--summary-out", "s.json"],
        tmp_path,
    )
    assert result.returncode == 0
    summary = json.loads((tmp_path / "s.json").read_text(encoding="utf-8"))
    assert summary["totals"]["medium"] == 1
    assert summary["failed"] is False


def test_cli_prints_one_line_per_severity(tmp_path):
    result = _run_cli([*_fixture_args(), "--fail-on", "none", "--summary-out", "s.json"], tmp_path)
    lines = result.stdout.strip().splitlines()
    severity_lines = [line.split()[0] for line in lines[:5]]
    assert severity_lines == ["critical", "high", "medium", "low", "info"]


def test_cli_summary_contains_no_redacted_fixture_string(tmp_path):
    result = _run_cli([*_fixture_args(), "--fail-on", "high", "--summary-out", "s.json"], tmp_path)
    summary_text = (tmp_path / "s.json").read_text(encoding="utf-8")
    assert "REDACTED-FIXTURE" not in summary_text
    assert "REDACTED-FIXTURE" not in result.stdout
    assert "REDACTED-FIXTURE" not in result.stderr


def test_cli_with_no_inputs_passes(tmp_path):
    result = _run_cli(["--target", "empty", "--summary-out", "s.json"], tmp_path)
    assert result.returncode == 0
    summary = json.loads((tmp_path / "s.json").read_text(encoding="utf-8"))
    assert summary["findings"] == []
    assert summary["failed"] is False
