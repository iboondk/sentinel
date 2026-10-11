"""Sentinel fixed variant: the same API as the demo app with the flaws closed.

Each control is listed in apps/fixed/FIXES.md together with its CWE and route.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from flask import Flask, abort, g, jsonify, render_template_string, request, send_file

VARIANT = "fixed"
FILES_DIR = Path(__file__).resolve().parent / "files"
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
PBKDF2_ITERATIONS = 600_000
SEED_USERS = {"alice": "wonderland", "bob": "builder"}
MAX_BODY_BYTES = 1024 * 1024
MAX_USERNAME_LEN = 64
MAX_PASSWORD_LEN = 256

SEARCH_TEMPLATE = """<!doctype html>
<title>Sentinel search</title>
<h1>Results for {{ q }}</h1>
<ul>
{% for name in results %}<li>{{ name }}</li>{% else %}<li>No matches</li>{% endfor %}
</ul>
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(stored: str, password: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(candidate, bytes.fromhex(digest_hex))
    except ValueError:
        return False


@lru_cache(maxsize=1)
def _seed_hashes() -> dict[str, str]:
    # Hashing is slow by design; compute the seed hashes once per process.
    return {name: _hash_password(pw) for name, pw in SEED_USERS.items()}


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    # Used for unknown usernames so the response time does not reveal which names exist.
    return _hash_password("sentinel-dummy-password")


def _resolve_log_dir(log_dir: str | os.PathLike | None) -> Path:
    if log_dir is not None:
        return Path(log_dir)
    return Path(os.environ.get("SENTINEL_LOG_DIR") or "logs")


def create_app(log_dir: str | os.PathLike | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SENTINEL_SECRET_KEY") or secrets.token_hex(32),
        DEBUG=False,
        MAX_CONTENT_LENGTH=MAX_BODY_BYTES,
        SENTINEL_LOG_DIR=str(_resolve_log_dir(log_dir)),
    )
    app.jinja_env.autoescape = True

    log_path = Path(app.config["SENTINEL_LOG_DIR"])
    log_path.mkdir(parents=True, exist_ok=True)
    log_file = log_path / f"{VARIANT}.log"
    log_lock = threading.Lock()

    # One in-memory database per app instance. check_same_thread is off because
    # the dev server may use several threads; every access holds db_lock.
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, "
        "password_hash TEXT NOT NULL)"
    )
    for name, pw_hash in _seed_hashes().items():
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (name, pw_hash))
    conn.commit()
    db_lock = threading.Lock()

    @app.after_request
    def _headers_and_log(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "no-referrer"

        status = response.status_code
        if getattr(g, "blocked", False):
            event = "blocked_input"
        elif status >= 500:
            event = "error"
        else:
            event = "request"
        record = {
            "ts": _utc_now(),
            "variant": VARIANT,
            "method": request.method,
            "path": request.path,
            "query": request.query_string.decode("utf-8", "replace"),
            "status": status,
            "remote_addr": request.remote_addr,
            "event": event,
        }
        try:
            line = json.dumps(record, separators=(",", ":"))
            with log_lock:
                with log_file.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError:
            app.logger.exception("could not write request log")
        return response

    @app.get("/health")
    def health():
        return jsonify(status="ok", variant=VARIANT)

    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        # Escape LIKE wildcards so the user input is matched literally.
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with db_lock:
            rows = conn.execute(
                "SELECT username FROM users WHERE username LIKE ? ESCAPE '\\' ORDER BY username",
                (f"%{escaped}%",),
            ).fetchall()
        return render_template_string(SEARCH_TEMPLATE, q=q, results=[row[0] for row in rows])

    @app.post("/login")
    def login():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            g.blocked = True
            return jsonify(error="invalid credentials"), 401
        username = payload.get("username")
        password = payload.get("password")
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or len(username) > MAX_USERNAME_LEN
            or len(password) > MAX_PASSWORD_LEN
        ):
            g.blocked = True
            return jsonify(error="invalid credentials"), 401

        with db_lock:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
        stored = row[0] if row else _dummy_hash()
        password_ok = _verify_password(stored, password)
        if row is None or not password_ok:
            return jsonify(error="invalid credentials"), 401
        return jsonify(status="ok", user=username), 200

    @app.get("/ping")
    def ping():
        # Validation only: the host is never passed to a shell or a subprocess.
        host = request.args.get("host", "")
        if not HOST_RE.fullmatch(host):
            g.blocked = True
            return jsonify(error="invalid host"), 400
        return jsonify(host=host, status="accepted")

    @app.get("/files")
    def files():
        name = request.args.get("name", "")
        base = FILES_DIR.resolve()
        try:
            target = (base / name).resolve()
        except (ValueError, OSError):
            g.blocked = True
            abort(404)
        if not target.is_relative_to(base):
            g.blocked = True
            abort(404)
        if not target.is_file():
            abort(404)
        return send_file(target, as_attachment=True, download_name=target.name)

    @app.post("/import")
    def import_data():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), str):
            g.blocked = True
            return jsonify(error="expected JSON object with base64 'data'"), 400
        try:
            raw = base64.b64decode(payload["data"], validate=True)
            document = json.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):
            g.blocked = True
            return jsonify(error="invalid payload"), 400
        return jsonify(status="imported", kind=type(document).__name__), 200

    return app
