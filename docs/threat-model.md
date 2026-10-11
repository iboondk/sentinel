# Sentinel threat model (STRIDE)

This document is a design-level threat model. It names threats and controls
and points to the check that verifies each control. It does not describe how
to exploit any threat.

## 1. Scope

In scope:

- **Demo app.** Two Flask variants with the same API: `apps/vulnerable` (planted
  flaws, for comparison) and `apps/fixed` (controls applied). The fixed variant
  is the one deployed to the observability stack and to the ZAP scan.
- **CI pipeline.** `.github/workflows/sentinel-security.yml`, the scanner
  configs under `pipeline/` and `.gitleaks.toml`, and the gate in
  `pipeline/gate.py`.
- **Log stack.** `observability/`: Filebeat, Elasticsearch, Kibana, and the
  optional Wazuh manager with `observability/wazuh/local_rules.xml`.

Out of scope are the items in section 6.

## 2. Data flow and trust boundaries

```
 Browser / HTTP client
        |  TB1: untrusted network -> app (HTTP on 127.0.0.1 in local use)
        v
 apps/fixed (Flask)  ---- TB2: app -> sqlite (in-memory, per process)
        |
        |  writes one JSON line per request
        v
 sentinel-logs volume (/var/log/sentinel/*.log)
        |  TB3: log volume -> Filebeat (read-only mount)
        v
 Filebeat --- TB4: Filebeat -> Elasticsearch (HTTP, no auth, 127.0.0.1 only)
        v
 Elasticsearch -> Kibana (operator browser, 127.0.0.1)
        |
        +-- sentinel-logs volume -> Wazuh manager (profile `wazuh`, read-only)

 GitHub PR / push
        |  TB5: untrusted PR content -> CI runner
        v
 CI runner --- TB6: runner -> scanners (semgrep, gitleaks, trivy, ZAP)
        |  scanner JSON -> gate.py -> summary.json -> render_report.py
        v
 reports/ artifacts (uploaded by the workflow)
```

Trust boundaries:

| ID | Boundary | Why it matters |
|---|---|---|
| TB1 | Client -> app | All request input (query, JSON body, base64 import) is untrusted. |
| TB2 | App -> sqlite | Queries are built from request input in the vulnerable variant only. |
| TB3 | Logs volume -> Filebeat | Log lines can contain attacker-chosen strings (path, query, user input). |
| TB4 | Filebeat -> Elasticsearch | No transport auth in the local demo. Anyone who can reach the port can read or write indices. |
| TB5 | PR content -> CI runner | A PR can change scanner configs, rules and the workflow. |
| TB6 | Runner -> scanners and reports | Scanner output is parsed by `gate.py`; a malformed file must not pass the gate. |

## 3. STRIDE threats

Likelihood and impact are rated `low`, `medium` or `high` for this demo.
Verifying controls name a scanner rule, a test in `tests/`, or a log event.

### 3.1 Spoofing

| ID | Component | Threat | Likelihood | Impact | Mitigation | Verifying control |
|---|---|---|---|---|---|---|
| S-1 | Fixed app, `POST /login` | A client impersonates a seeded user by guessing or replaying login details. | medium | high | Login secrets stored as salted PBKDF2 hashes; constant-time comparison (`hmac.compare_digest`). | `tests/test_apps.py::test_login_rejects_wrong_password`; Semgrep `sentinel-sqlite-execute-string-built` covers the query path. |
| S-2 | Log stack, Elasticsearch (TB4) | A process on the host writes forged log documents to `sentinel-logs-*` as if they came from the app. | low | medium | Ports bound to 127.0.0.1; only Filebeat is configured to ship into Elasticsearch; xpack security is disabled for the local demo only and is called out as a limitation (A-4). | Compose test asserts every published port starts with `127.0.0.1:` (`tests/test_observability.py`). |
| S-3 | CI, PR author (TB5) | A PR impersonates the maintainer to change the gate or scanner config. | low | high | Workflow permissions are `contents: read`; the gate runs from the PR's own checkout, so a PR can change its own gate. Protected branches and required reviews are an operator control (A-3). | `tests/test_workflow.py::test_workflow_permissions_are_read_only`. |

### 3.2 Tampering

| ID | Component | Threat | Likelihood | Impact | Mitigation | Verifying control |
|---|---|---|---|---|---|---|
| T-1 | Fixed app, `GET /search` | Request input changes the SQL statement or the HTML output. | medium | high | Parameterised SQL; Jinja autoescape on the search template. | Semgrep `sentinel-sqlite-execute-string-built`; `tests/test_apps.py::test_search_injection_payload_matches_nothing`. |
| T-2 | Fixed app, `POST /import` | Crafted payload is deserialised into objects that run code. | medium | high | Only `json.loads` of the decoded payload; invalid input returns 400. No `pickle`. | Semgrep `sentinel-pickle-loads`; `tests/test_apps.py::test_import_rejects_invalid_json`. |
| T-3 | Logs volume (TB3) | A request writes content that alters the structure of a log line or injects fields into the index. | medium | medium | One `json.dumps` per line, so input is escaped and cannot add a new line; Filebeat ndjson parser with `overwrite_keys: true`. | Log event `blocked_input` and `request` lines are parsed in the ingest path; `tests/test_apps.py::test_rejected_request_writes_blocked_input_log`. |
| T-4 | CI, scanner configs (TB5) | A PR edits `.gitleaks.toml` allowlists to hide a real secret. | medium | high | Allowlist is limited to `tests/fixtures/` and `apps/vulnerable/`; any change to the file is visible in the diff. | `.gitleaks.toml` review in PR diff; gitleaks run in `sentinel-security.yml`. |
| T-5 | Elasticsearch data (TB4) | An attacker with local access changes stored log documents. | low | medium | Ports bound to 127.0.0.1; data kept in a named volume; log files mounted read-only into Filebeat and Wazuh. | `tests/test_observability.py` asserts `:ro` on the filebeat config and on the logs volume mounts for filebeat and wazuh. |

### 3.3 Repudiation

| ID | Component | Threat | Likelihood | Impact | Mitigation | Verifying control |
|---|---|---|---|---|---|---|
| R-1 | Fixed app, all routes | A client denies sending a request that was blocked or caused an error. | medium | medium | One JSON line per request with `ts`, `remote_addr`, `path`, `status` and `event`. | Log event `blocked_input` and `error` lines; `tests/test_apps.py::test_rejected_request_writes_blocked_input_log`. |
| R-2 | Log pipeline, Filebeat (TB3, TB4) | Log lines are lost before indexing, so an event cannot be shown later. | medium | medium | Filestream input keeps a registry of read offsets; Filebeat restarts resume from the last offset. | Compose sets `restart: unless-stopped`; Kibana query in `observability/kibana/README-queries.md`. Operators check the `sentinel-logs-*` document count against the log file line count (A-5). |
| R-3 | CI, gate result | A failed or changed gate result is not traceable to a commit. | low | medium | `gate.py` writes `summary.json` for each run, and the report is uploaded as an artifact. | `pipeline/gate.py --fail-on high` exit code; `tests/test_gate.py::test_cli_exit_1_on_fixtures_with_fail_on_high`. |

### 3.4 Information disclosure

| ID | Component | Threat | Likelihood | Impact | Mitigation | Verifying control |
|---|---|---|---|---|---|---|
| I-1 | Fixed app, `GET /files` | Path input reads files outside the bundled `files/` directory. | medium | high | Resolved path must stay inside `FILES_DIR`; otherwise 404. | `tests/test_apps.py::test_files_traversal_returns_404`. |
| I-2 | Fixed app, error responses (TB1) | Debug pages or stack traces leak internals. | medium | medium | `DEBUG` off; `Referrer-Policy: no-referrer`; `X-Content-Type-Options: nosniff`. | `tests/test_apps.py::test_security_headers`; ZAP baseline rule set in `pipeline/zap/rules.tsv`. |
| I-3 | Logs and Elasticsearch (TB3, TB4) | Log lines or indices hold secrets or user data, and the indices are read by someone who should not see them. | medium | high | App logs carry no request bodies and no secret values; `SENTINEL_SECRET_KEY` is read from the environment and never logged. The raw query string is logged in the `query` field, so **residual risk**: a token or personal data sent in a query parameter is stored in the log and indexed in Elasticsearch. Clients must keep secrets out of query parameters. Ports bound to 127.0.0.1; xpack security disabled only for the local demo (A-4). | gitleaks run in `sentinel-security.yml` on the repo; `.gitleaks.toml`; `tests/test_observability.py` asserts every published port starts with `127.0.0.1:`. The query-string logging is not asserted by a test. |
| I-4 | Repo, `.env` files | A real secret is committed to the repo. | medium | high | `.env.example` holds fake values only; `.env` is git-ignored by the operator. | gitleaks (default rules plus `.gitleaks.toml`) in `sentinel-security.yml`; `tests/test_observability.py` checks that `.env.example` holds only the fake placeholder values. |
| I-5 | CI artifacts (TB6) | Scanner reports or the report artifact expose secret values found by gitleaks. | medium | medium | gitleaks findings keep only the rule id and location; the match and secret value are never copied. | `tests/test_gate.py::test_gitleaks_never_copies_secret_or_match` and `tests/test_gate.py::test_cli_summary_contains_no_redacted_fixture_string`. |

### 3.5 Denial of service

| ID | Component | Threat | Likelihood | Impact | Mitigation | Verifying control |
|---|---|---|---|---|---|---|
| D-1 | Fixed app, POST routes (TB1) | A very large body exhausts memory. | medium | medium | Request body capped at 1 MiB. | `MAX_CONTENT_LENGTH` in `apps/fixed/sentinel_fixed/__init__.py`, listed in `apps/fixed/FIXES.md` (CWE-400). No automated test asserts the limit yet (gap). |
| D-2 | Fixed app, all routes | A client floods requests and fills the log volume. | medium | medium | Rate limiting is not in scope for the demo (A-6). Log rotation is an operator control. | Frequency rule `100102` in `observability/wazuh/local_rules.xml` fires at 10 or more `blocked_input` events from one `remote_addr` in 60 s. |
| D-3 | Log stack, Elasticsearch | Index growth or a JVM memory limit stops ingestion. | medium | low | `ES_JAVA_OPTS` heap is set from the environment; Elasticsearch health check gates Filebeat and Kibana start. | `tests/test_observability.py` asserts `ES_JAVA_OPTS` is read from the environment and the `elasticsearch` healthcheck exists. |
| D-4 | CI runner | A scanner or ZAP run hangs and blocks the pipeline. | medium | low | Scanner steps run with job timeouts in the workflow. | `timeout-minutes` in `sentinel-security.yml` (manual review; not asserted by a test). |

### 3.6 Elevation of privilege

| ID | Component | Threat | Likelihood | Impact | Mitigation | Verifying control |
|---|---|---|---|---|---|---|
| E-1 | Fixed app, `GET /ping` (TB1) | Input reaches a shell and runs commands on the host. | medium | high | Host allowlist `^[A-Za-z0-9.-]{1,253}$`; no shell or subprocess. | Semgrep `sentinel-subprocess-shell-true`; `tests/test_apps.py::test_ping_rejects_host_with_shell_metacharacters`. |
| E-2 | Fixed app container | The app process runs as root and can change the image or host files. | low | high | Dockerfile runs as a non-root `sentinel` user. Vulnerable variant runs as root on purpose (demo). | Trivy image scan in `sentinel-security.yml`; Dockerfile `USER sentinel` directive, checked by `tests/test_observability.py::test_dockerfile_creates_and_chowns_compose_log_dir` (structure only; the image is not built). |
| E-3 | Fixed app, `DEBUG` and `SECRET_KEY` | Debug mode or a known key allows code execution or session forgery. | low | high | `DEBUG=False`; `SENTINEL_SECRET_KEY` from the environment, otherwise random per process. | Semgrep `sentinel-flask-debug-true`; `tests/test_apps.py::test_security_headers` for the app; compose sets `SENTINEL_SECRET_KEY` to an empty default, so no key is committed. |
| E-4 | Wazuh manager (profile `wazuh`) | The manager container gets write access to the logs it reads and can alter evidence. | low | medium | Logs volume is mounted read-only; the rules file is mounted read-only. | `tests/test_observability.py` asserts `:ro` on the wazuh rules file and logs volume mount. |

## 4. Assumptions

- A-1. The stack runs on a single developer machine, with ports bound to `127.0.0.1`.
- A-2. The operator reads `.env.example` and creates their own local `.env`. The
  example values are fake placeholders.
- A-3. GitHub branch protection and required reviews are configured by the repo
  owner. The threat model does not verify them.
- A-4. Elasticsearch runs with `xpack.security.enabled=false`. This is acceptable
  only for the local demo. Enabling security is required before any shared use.
- A-5. Filebeat delivers each log line at least once. Duplicate documents are
  possible after a restart; counts are approximate.
- A-6. The demo app is not exposed to the internet. Rate limiting and WAF rules
  are not part of the app.
- A-7. Scanner results come from real runs in GitHub Actions or from a local run
  with the scanners installed. Test fixtures are labelled as fixtures.

## 5. Verification status

- The controls listed above are checked by pytest (`tests/`) for structure and
  behaviour, and by the scanners in CI for code and config.
- `docker compose config` and `docker compose up` have not been run in the
  local development environment, because docker is not installed there. Compose
  checks are structure-only until they run in an environment with docker.
- Scanner results are not reproduced in this document. Numbers come only from
  `reports/`.

## 6. Out of scope

- Production hardening of Elasticsearch and Kibana (TLS, users, roles, API keys).
- Multi-node clusters, backups and disaster recovery.
- Cloud deployment, managed services, and any paid service.
- The Linux host hardening checklist (covered by the `hardening/` milestone).
- Supply-chain threats for base images beyond the Trivy scan.
- Physical access to the host and the host operating system.
- Browser-side threats such as malicious extensions.
