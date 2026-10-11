"""Proves each planted flaw in apps/vulnerable can be exploited (harmlessly)."""

import base64
import json
import pickle


def test_health(vuln_client):
    resp = vuln_client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok", "variant": "vulnerable"}


def test_no_security_headers(vuln_client):
    resp = vuln_client.get("/health")
    assert "Content-Security-Policy" not in resp.headers
    assert "X-Frame-Options" not in resp.headers


def test_search_sql_injection_dumps_every_user(vuln_client):
    resp = vuln_client.get("/search", query_string={"q": "zzz' OR '1'='1' --"})
    assert resp.status_code == 200
    assert b"<li>alice</li>" in resp.data
    assert b"<li>bob</li>" in resp.data


def test_search_reflects_script_unescaped(vuln_client):
    resp = vuln_client.get("/search", query_string={"q": "<script>alert(1)</script>"})
    assert b"<script>alert(1)</script>" in resp.data


def test_login_accepts_correct_password(vuln_client):
    resp = vuln_client.post("/login", json={"username": "alice", "password": "wonderland"})
    assert resp.status_code == 200


def test_login_sql_injection_bypasses_password(vuln_client):
    resp = vuln_client.post("/login", json={"username": "alice' --", "password": "wrong"})
    assert resp.status_code == 200
    assert resp.get_json()["user"] == "alice"


def test_ping_command_injection_runs_second_command(vuln_client):
    resp = vuln_client.get("/ping", query_string={"host": "example.com; echo INJECTED"})
    assert resp.status_code == 200
    assert "INJECTED\n" in resp.get_json()["output"].splitlines(keepends=True)


def test_files_path_traversal_escapes_files_dir(vuln_client):
    resp = vuln_client.get(
        "/files", query_string={"name": "../../../fixed/sentinel_fixed/files/readme.txt"}
    )
    assert resp.status_code == 200
    assert b"fixed variant" in resp.data


def test_import_unpickles_attacker_payload(vuln_client):
    class Payload:
        def __reduce__(self):
            return (str.upper, ("pwned",))

    data = base64.b64encode(pickle.dumps(Payload())).decode("ascii")
    resp = vuln_client.post("/import", json={"data": data})
    assert resp.status_code == 200
    assert resp.get_json()["kind"] == "str"


def test_hardcoded_secret_and_debug(vuln_client):
    app = vuln_client.application
    assert app.config["SECRET_KEY"] == "sentinel-demo-hardcoded-key-not-real"
    assert app.config["DEBUG"] is True


def test_request_is_logged_with_shared_schema(vuln_client, tmp_path):
    vuln_client.get("/health")
    records = [
        json.loads(line)
        for line in (tmp_path / "vulnerable.log").read_text(encoding="utf-8").splitlines()
    ]
    assert records[-1]["variant"] == "vulnerable"
    assert set(records[-1]) == {
        "ts", "variant", "method", "path", "query", "status", "remote_addr", "event",
    }


def test_vulnerable_app_is_not_in_compose():
    from pathlib import Path

    compose = Path(__file__).resolve().parent.parent / "observability" / "docker-compose.yml"
    assert "apps/vulnerable" not in compose.read_text(encoding="utf-8")
