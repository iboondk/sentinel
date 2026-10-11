"""Sentinel vulnerable variant. INTENTIONALLY INSECURE. NEVER DEPLOY.

The same API as apps/fixed, with each flaw left open so the scanners have
something real to find. Every planted flaw is listed in
apps/vulnerable/VULNERABILITIES.md with its CWE and route. The seeded users and
the secret key below are fake demo values.
"""

from __future__ import annotations

import base64
import json
import os
import pickle
import sqlite3
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

VARIANT = "vulnerable"
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
SEED_USERS = {"alice": "wonderland", "bob": "builder"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_app(log_dir=None) -> Flask:
    app = Flask(__name__)
    # CWE-798 / CWE-215: hard-coded (fake) secret key and debug mode on.
    app.config["SECRET_KEY"] = "sentinel-demo-hardcoded-key-not-real"
    app.config["DEBUG"] = True

    log_path = Path(log_dir if log_dir is not None else os.environ.get("SENTINEL_LOG_DIR") or "logs")
    log_path.mkdir(parents=True, exist_ok=True)
    log_file = log_path / f"{VARIANT}.log"
    log_lock = threading.Lock()

    # CWE-256: passwords stored in plaintext.
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    for name, pw in SEED_USERS.items():
        conn.execute(f"INSERT INTO users (username, password) VALUES ('{name}', '{pw}')")
    conn.commit()
    db_lock = threading.Lock()

    @app.after_request
    def _log(response):
        status = response.status_code
        record = {
            "ts": _utc_now(),
            "variant": VARIANT,
            "method": request.method,
            "path": request.path,
            "query": request.query_string.decode("utf-8", "replace"),
            "status": status,
            "remote_addr": request.remote_addr,
            "event": "error" if status >= 500 else "request",
        }
        try:
            with log_lock, log_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        except OSError:
            app.logger.exception("could not write request log")
        return response

    @app.get("/health")
    def health():
        return jsonify(status="ok", variant=VARIANT)

    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        # CWE-89: SQL built with an f-string.
        with db_lock:
            rows = conn.execute(
                f"SELECT username FROM users WHERE username LIKE '%{q}%' ORDER BY username"
            ).fetchall()
        items = "".join(f"<li>{row[0]}</li>" for row in rows) or "<li>No matches</li>"
        # CWE-79: q is pasted into the template source, so it is never escaped.
        page = (
            "<!doctype html>\n<title>Sentinel search</title>\n"
            f"<h1>Results for {q}</h1>\n<ul>\n{items}\n</ul>\n"
        )
        return render_template_string(page)

    @app.post("/login")
    def login():
        payload = request.get_json(silent=True) or {}
        username = payload.get("username", "")
        password = payload.get("password", "")
        # CWE-89 + CWE-256: injectable WHERE clause over plaintext passwords.
        with db_lock:
            row = conn.execute(
                f"SELECT username FROM users WHERE username = '{username}' "
                f"AND password = '{password}'"
            ).fetchone()
        if row is None:
            return jsonify(error="invalid credentials"), 401
        return jsonify(status="ok", user=row[0]), 200

    @app.get("/ping")
    def ping():
        host = request.args.get("host", "")
        # CWE-78: user input reaches a shell. The command only echoes, so the
        # injected part is what runs.
        result = subprocess.run(
            f"echo pinging {host}", shell=True, capture_output=True, text=True, timeout=5
        )
        return jsonify(host=host, status="accepted", output=result.stdout)

    @app.get("/files")
    def files():
        name = request.args.get("name", "")
        # CWE-22: no check that the joined path stays inside FILES_DIR.
        try:
            with open(os.path.join(FILES_DIR, name), "rb") as fh:
                data = fh.read()
        except OSError:
            return jsonify(error="not found"), 404
        return app.response_class(data, mimetype="application/octet-stream")

    @app.post("/import")
    def import_data():
        payload = request.get_json(silent=True) or {}
        raw = base64.b64decode(payload.get("data", ""))
        # CWE-502: untrusted bytes go straight into pickle.
        document = pickle.loads(raw)
        return jsonify(status="imported", kind=type(document).__name__), 200

    return app
