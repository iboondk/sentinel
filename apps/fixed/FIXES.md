# Sentinel fixed app: controls

Each row is a control in the fixed variant (`sentinel_fixed`) and the planted flaw it closes in the demo app.

| Control | CWE closed | Route |
|---|---|---|
| Parameterised SQL with `?` placeholders and LIKE wildcards escaped | CWE-89 | `GET /search`, `POST /login` |
| Jinja autoescaping on the search template | CWE-79 | `GET /search` |
| Passwords stored as `pbkdf2_sha256` hashes (600,000 iterations, per-user salt) | CWE-256, CWE-522 | `POST /login` |
| Constant-time comparison with `hmac.compare_digest`; dummy hash for unknown users | CWE-208 | `POST /login` |
| Host allowlist `^[A-Za-z0-9.-]{1,253}$`, else 400; no shell or subprocess is used | CWE-78 | `GET /ping` |
| Resolved path must stay inside `sentinel_fixed/files/`, else 404 | CWE-22 | `GET /files` |
| Payload is base64 decoded and parsed with `json.loads` only; invalid input gives 400 | CWE-502 | `POST /import` |
| Request body capped at 1 MiB | CWE-400 | all POST routes |
| `SECRET_KEY` from `SENTINEL_SECRET_KEY`, else random per process | CWE-798 | app config |
| `DEBUG` off | CWE-215 | app config |
| `X-Content-Type-Options: nosniff` | CWE-693 | all responses |
| `X-Frame-Options: DENY` | CWE-1021 | all responses |
| `Content-Security-Policy: default-src 'self'` | CWE-693 | all responses |
| `Referrer-Policy: no-referrer` | CWE-200 | all responses |
| One JSON log line per request; `event` is `blocked_input`, `error` or `request` | CWE-778 | all routes |

Logs are written to `$SENTINEL_LOG_DIR/fixed.log` (default `./logs`).
