# Sentinel vulnerable app: planted flaws

**This app is insecure on purpose. Never deploy it or expose it beyond `127.0.0.1`.** It exists so the scanners in `sentinel-security.yml` have real findings for the "before" column. The compose stack does not include it.

Every credential and key here is a fake demo value.

| Flaw | CWE | Route | Closed in `apps/fixed` by |
|---|---|---|---|
| SQL built with an f-string from `q` | CWE-89 | `GET /search` | Parameterised query |
| `q` pasted into the template source, never escaped | CWE-79 | `GET /search` | Jinja autoescape, `q` passed as a variable |
| SQL built with an f-string from `username` and `password` | CWE-89 | `POST /login` | Parameterised query |
| Plaintext passwords in the users table | CWE-256 | `POST /login` | `pbkdf2_sha256` hashes |
| `subprocess.run(f"echo pinging {host}", shell=True)` | CWE-78 | `GET /ping` | Host allowlist, no shell |
| `open(os.path.join(FILES_DIR, name))` with no containment check | CWE-22 | `GET /files` | Resolved path must stay inside `files/` |
| `pickle.loads` on the decoded request body | CWE-502 | `POST /import` | `json.loads` only |
| Hard-coded `SECRET_KEY` | CWE-798 | app config | Read from `SENTINEL_SECRET_KEY` |
| `DEBUG = True` | CWE-215 | app config | `DEBUG = False` |
| No security headers | CWE-693, CWE-1021 | all responses | CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy` |
| Old `Flask`, `Werkzeug`, `Jinja2` pins with public CVEs | CWE-1104 | `requirements.txt` | Current pins |
| Unpinned base image, runs as root | CWE-250 | `Dockerfile` | Pinned slim base, non-root user |

Each exploitable flaw has a test in `tests/test_vulnerable_app.py` that proves it works. The exploits are harmless: the shell injection runs `echo`, the pickle payload calls `str.upper`, and the traversal reads the fixed app's bundled readme.
