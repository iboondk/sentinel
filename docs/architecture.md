# Sentinel architecture

Sentinel is a security and observability hardening kit. It holds:

1. A deliberately vulnerable Flask app and a fixed copy with the same API, so the same scanners can be run on both and compared.
2. A scan gate that reads the output of Semgrep, Trivy, gitleaks and OWASP ZAP, maps every finding onto one severity scale, and exits non-zero when anything is at or above `high`. A GitHub Actions workflow uses it to fail PRs.
3. A before/after report renderer and Markdown templates. They are filled only from real scanner output; no numbers are written by hand.
4. A STRIDE threat model of the demo app and its pipeline.
5. An Elastic (Elasticsearch, Kibana, Filebeat) docker compose stack that ingests the apps' JSON logs, with an optional Wazuh manager profile that has custom detection rules.
6. A Linux hardening checklist and an idempotent check/apply script.

Outputs: `reports/before/`, `reports/after/`, `reports/before-after.md` (made by CI or by a local run that has the scanners) and `docs/threat-model.md`.

## Constraints

- Local only. No cloud deploys, no paid services, no real credentials. Every secret-shaped value is fake and documented in `.env.example`.
- The virtualenv lives at `.venv` (git-ignored).
- Docker, semgrep, trivy, gitleaks, shellcheck and actionlint are optional locally:
  - pytest unit tests cover each component.
  - Compose and workflow files are checked locally for YAML structure (pytest + PyYAML), not by running them.
  - Real scanner runs happen in GitHub Actions. Scanner output is never fabricated; test fixtures are labelled as fixtures.

## Architecture

```
                 +------------------- GitHub Actions: sentinel-security.yml -------------------+
 PR / push ----> | semgrep (p/owasp-top-ten + pipeline/semgrep/sentinel.yml) -> semgrep.json    |
                 | gitleaks (config .gitleaks.toml)                         -> gitleaks.json     |
                 | trivy fs (fixed app)                                     -> trivy.json        |
                 | ZAP baseline against fixed app on :5002                 -> zap.json          |
                 |        \__________________ pipeline/gate.py ______________/                  |
                 |          normalise -> summary.json -> exit 1 if any >= high (fails PR)       |
                 | "before" job: same scanners on apps/vulnerable (continue-on-error)           |
                 | pipeline/render_report.py before/summary.json + after/summary.json           |
                 |          -> reports/before-after.md (uploaded artifact)                      |
                 +------------------------------------------------------------------------------+

 apps/vulnerable (:5001)  CI scans only; never deployed, not in docker-compose.yml
 apps/fixed      (:5002)  --JSON logs-->  logs volume  --> Filebeat --> Elasticsearch --> Kibana
                                                      \--> (profile wazuh) wazuh-manager + local_rules.xml

 hardening/harden.sh --check|--apply   (SENTINEL_ROOT prefix lets tests run on a fixture tree)
```

### Tech choices

| Concern | Choice | Why |
|---|---|---|
| Demo app | Python 3.10+ / Flask, sqlite3 in memory | Small; Semgrep, Trivy and ZAP all have good coverage for it; testable with pytest |
| Vulnerable deps | `Flask==2.2.2`, `Werkzeug==2.2.2`, `Jinja2==3.1.2` in `apps/vulnerable/requirements.txt` | Publicly known CVEs give Trivy real findings |
| Fixed deps | Current stable Flask/Werkzeug/Jinja2 | |
| Gate | Python 3 stdlib only (`json`, `argparse`) | Runs on any runner with no installs |
| Reports | Python stdlib + `string.Template` Markdown | No templating dependency |
| Logs | Elasticsearch/Kibana/Filebeat 8.15.x, security disabled, bound to 127.0.0.1 | Single-node local demo |
| SIEM option | `wazuh/wazuh-manager:4.9.x` under compose profile `wazuh` | Shows rule-based detection without the full Wazuh stack |
| Hardening | POSIX-leaning bash that also runs on macOS bash 3.2 (no associative arrays, no `sed -i`) | Tests run on macOS as well as Linux |
| Tests | pytest + PyYAML in `requirements-dev.txt` | |

## Directory layout

```
sentinel/
  .env.example                     # fake values only
  .gitleaks.toml                   # allowlists apps/vulnerable/ + tests/fixtures/ for the PR gate
  requirements-dev.txt             # flask (current), pytest, pyyaml
  pytest.ini                       # testpaths = tests
  apps/
    vulnerable/
      requirements.txt  Dockerfile (runs as root, unpinned base: intentional)
      sentinel_vuln/__init__.py    # create_app()
      sentinel_vuln/files/readme.txt
      VULNERABILITIES.md           # list of each planted flaw -> CWE -> endpoint
    fixed/
      requirements.txt  Dockerfile (non-root, slim pinned base, HEALTHCHECK)
      sentinel_fixed/__init__.py   # create_app()
      sentinel_fixed/files/readme.txt
      FIXES.md                     # flaw -> fix mapping
  pipeline/
    gate.py                        # normalise + gate
    render_report.py               # before/after markdown
    semgrep/sentinel.yml           # custom rules
    zap/rules.tsv                  # ZAP baseline rule config
  .github/workflows/sentinel-security.yml
  reports/
    templates/before-after.md.tmpl
    templates/scan-summary.md.tmpl
    before/.gitkeep  after/.gitkeep
  docs/architecture.md  docs/threat-model.md  docs/ADR-*.md
  observability/
    docker-compose.yml
    filebeat/filebeat.yml
    wazuh/local_rules.xml  wazuh/ossec-localfile.conf
    kibana/README-queries.md       # saved KQL queries
  hardening/
    harden.sh  CHECKLIST.md
  tests/
    conftest.py  test_*.py
    fixtures/scanners/{semgrep,trivy,gitleaks,zap}.json   # synthetic, labelled "fixture"
    fixtures/hardening/{bad,good}/etc/...
```

## Shared contracts

**App API** (identical routes on both apps; `variant` is `"vulnerable"` or `"fixed"`):

| Route | Vulnerable behaviour | Fixed behaviour |
|---|---|---|
| `GET /health` | `{"status":"ok","variant":...}` | same |
| `GET /search?q=` | SQL built with an f-string (SQLi, CWE-89); `q` reflected unescaped in HTML (XSS, CWE-79) | Parameterised query; Jinja autoescape |
| `POST /login` JSON `{username,password}` | SQLi in the WHERE clause; plaintext passwords | Parameterised query; passwords checked with `hashlib.pbkdf2_hmac` + `hmac.compare_digest` |
| `GET /ping?host=` | `subprocess.run(f"echo pinging {host}", shell=True)` (CWE-78) | Host checked against `^[A-Za-z0-9.-]{1,253}$`, else 400; no shell |
| `GET /files?name=` | `open(os.path.join(FILES_DIR, name))` (path traversal, CWE-22) | Resolved path must stay inside FILES_DIR, else 404 |
| `POST /import` body `{"data": "<base64>"}` | `pickle.loads` (CWE-502) | `json.loads` of the decoded payload; 400 if invalid |

Seeded users: `alice/wonderland`, `bob/builder`. These are fake demo creds. The vulnerable app has `SECRET_KEY = "sentinel-demo-hardcoded-key-not-real"` and `DEBUG=True`. The fixed app reads `SENTINEL_SECRET_KEY` from the environment (random per process if unset), runs with `DEBUG=False`, and sets the security headers `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` and `Referrer-Policy`.

**Log line** (one JSON object per request, appended to `$SENTINEL_LOG_DIR/<variant>.log`, default `./logs`):
`{"ts": ISO8601Z, "variant", "method", "path", "query", "status", "remote_addr", "event"}` where `event` ∈ `request` | `blocked_input` (fixed app rejected input) | `error`.

**Normalised finding** (gate): `{"tool","rule_id","severity","location","message"}`. `severity` ∈ `critical, high, medium, low, info`.
Mapping: Semgrep `ERROR→high, WARNING→medium, INFO→low`. Trivy native (`UNKNOWN→info`). Every gitleaks finding → `high`. ZAP `riskcode 3→high, 2→medium, 1→low, 0→info`.

**summary.json**: `{"target": str, "generated_at": ISO8601Z, "threshold": "high", "counts": {tool: {sev: n}}, "totals": {sev: n}, "failed": bool, "findings": [...]}`.

## Components

1. **Vulnerable app**: planted flaws, structured logging, tests that show each flaw can be exploited.
2. **Fixed app**: same API, tests that show each exploit is blocked and logged.
3. **Gate**: parsers, severity mapping, threshold exit code, synthetic fixtures, tests.
4. **Pipeline and reports**: the security workflow, custom Semgrep rules, gitleaks/ZAP configs, the report renderer and its templates.
5. **Threat model and observability**: STRIDE doc, Elastic/Filebeat compose, Wazuh profile and rules, structure tests.
6. **Linux hardening**: checklist, `harden.sh --check/--apply`, fixture-tree tests.

## Verification

Unit tests run with `.venv/bin/pytest -q`. Docker-, scanner- and actionlint-dependent checks run in CI. Real before/after numbers come only from an actual CI run or a local run with the scanners installed.
