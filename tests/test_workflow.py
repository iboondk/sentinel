"""Structure tests for the Sentinel security workflow and scanner configs.

These check YAML structure only. The workflow and scanners are not executed
here; real scanner runs happen in GitHub Actions.
"""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "sentinel-security.yml"
SEMGREP_RULES = ROOT / "pipeline" / "semgrep" / "sentinel.yml"
GITLEAKS = ROOT / ".gitleaks.toml"
ZAP_RULES = ROOT / "pipeline" / "zap" / "rules.tsv"


def _load_workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _triggers(doc):
    # PyYAML parses the bare key `on` as the boolean True (YAML 1.1).
    return doc.get("on", doc.get(True))


def _all_steps(job):
    return job.get("steps", [])


def _run_text(job):
    return "\n".join(step.get("run", "") for step in _all_steps(job) if "run" in step)


def test_workflow_triggers_on_pull_request_and_push_to_main():
    doc = _load_workflow()
    triggers = _triggers(doc)
    assert triggers is not None, "workflow has no 'on' trigger"
    assert "pull_request" in triggers
    assert triggers["push"]["branches"] == ["main"]


def test_workflow_permissions_are_read_only():
    assert _load_workflow()["permissions"] == {"contents": "read"}


def test_jobs_before_after_report_exist():
    jobs = _load_workflow()["jobs"]
    assert {"before", "after", "report"} <= set(jobs)


def test_after_job_runs_gate_with_fail_on_high():
    after = _load_workflow()["jobs"]["after"]
    gate_steps = [s for s in _all_steps(after) if "pipeline/gate.py" in s.get("run", "")]
    assert len(gate_steps) == 1
    gate_run = gate_steps[0]["run"]
    assert "--fail-on high" in gate_run
    assert "reports/after/summary.json" in gate_run


def test_before_job_is_informational():
    before = _load_workflow()["jobs"]["before"]
    assert before.get("continue-on-error") is True
    assert "--fail-on none" in _run_text(before)
    assert "reports/before/summary.json" in _run_text(before)
    assert "apps/vulnerable" in _run_text(before)


def test_report_job_needs_both_and_renders():
    report = _load_workflow()["jobs"]["report"]
    needs = report["needs"]
    assert set(needs) == {"before", "after"}
    assert "pipeline/render_report.py" in _run_text(report)


def test_scanners_are_wired():
    after = _load_workflow()["jobs"]["after"]
    text = _run_text(after) + "\n" + "\n".join(
        str(s.get("with", "")) for s in _all_steps(after)
    )
    assert "semgrep scan" in text
    assert "p/owasp-top-ten" in text
    assert "pipeline/semgrep/sentinel.yml" in text
    assert "ghcr.io/gitleaks/gitleaks" in text
    assert "--report-format json" in text
    assert "ghcr.io/zaproxy/zaproxy:stable" in text
    assert "-J zap.json" in text
    assert "-c rules.tsv" in text
    assert "5002" in text
    assert "apps/fixed" in text


def test_every_uses_is_pinned_to_a_tag():
    for job_name, job in _load_workflow()["jobs"].items():
        for step in _all_steps(job):
            if "uses" in step:
                assert "@" in step["uses"], f"{job_name}: unpinned {step['uses']}"
                ref = step["uses"].split("@", 1)[1]
                assert ref, f"{job_name}: empty ref in {step['uses']}"


PINNED_REF = re.compile(r"^(v\d+\.\d+\.\d+|[0-9a-f]{40})$")


def test_third_party_actions_use_exact_tag_or_sha():
    # A ref like "0.28.0" (no "v") does not resolve on GitHub and fails the job.
    for job_name, job in _load_workflow()["jobs"].items():
        for step in _all_steps(job):
            uses = step.get("uses")
            if not uses:
                continue
            ref = uses.split("@", 1)[1]
            assert PINNED_REF.match(ref), (
                f"{job_name}: {uses} must pin an exact tag like v0.28.0 or a 40-char SHA"
            )


def test_only_github_token_secret_is_used():
    text = WORKFLOW.read_text(encoding="utf-8")
    secrets_used = set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text))
    assert secrets_used <= {"GITHUB_TOKEN"}


def test_semgrep_rules_parse_with_ids_and_cwe():
    doc = yaml.safe_load(SEMGREP_RULES.read_text(encoding="utf-8"))
    rules = doc["rules"]
    assert len(rules) >= 4
    for rule in rules:
        assert rule.get("id"), "rule without id"
        assert rule["severity"] == "ERROR"
        assert "CWE-" in rule["metadata"]["cwe"]
        assert rule.get("message")


def test_gitleaks_config_extends_default_and_allowlists_paths():
    text = GITLEAKS.read_text(encoding="utf-8")
    assert "[extend]" in text
    assert "useDefault = true" in text
    assert "tests/fixtures/" in text
    assert "apps/vulnerable/" in text


def test_zap_rules_are_tab_separated_with_some_fail():
    lines = [
        line for line in ZAP_RULES.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    parsed = [line.split("\t") for line in lines]
    assert all(len(cols) == 3 for cols in parsed)
    assert all(cols[1] in {"IGNORE", "WARN", "FAIL"} for cols in parsed)
    assert any(cols[1] == "FAIL" for cols in parsed)
