import base64
import json


def read_log(tmp_path):
    lines = (tmp_path / "fixed.log").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok", "variant": "fixed"}


def test_security_headers(client):
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Content-Security-Policy"] == "default-src 'self'"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_valid_search_returns_matching_user(client):
    resp = client.get("/search", query_string={"q": "alice"})
    assert resp.status_code == 200
    assert b"<li>alice</li>" in resp.data
    assert b"bob" not in resp.data


def test_search_injection_payload_matches_nothing(client):
    resp = client.get("/search", query_string={"q": "' OR '1'='1"})
    assert resp.status_code == 200
    assert b"<li>alice</li>" not in resp.data
    assert b"<li>bob</li>" not in resp.data
    assert b"No matches" in resp.data


def test_login_accepts_correct_password(client):
    resp = client.post("/login", json={"username": "alice", "password": "wonderland"})
    assert resp.status_code == 200


def test_login_rejects_wrong_password(client):
    resp = client.post("/login", json={"username": "alice", "password": "nope"})
    assert resp.status_code == 401


def test_ping_rejects_host_with_shell_metacharacters(client):
    resp = client.get("/ping", query_string={"host": "example.com;id"})
    assert resp.status_code == 400


def test_ping_accepts_valid_host(client):
    resp = client.get("/ping", query_string={"host": "example.com"})
    assert resp.status_code == 200
    assert resp.get_json() == {"host": "example.com", "status": "accepted"}


def test_files_traversal_returns_404(client):
    resp = client.get("/files", query_string={"name": "../../../../etc/passwd"})
    assert resp.status_code == 404


def test_files_serves_bundled_readme(client):
    resp = client.get("/files", query_string={"name": "readme.txt"})
    assert resp.status_code == 200


def test_import_rejects_invalid_json(client):
    data = base64.b64encode(b"{not json").decode("ascii")
    resp = client.post("/import", json={"data": data})
    assert resp.status_code == 400


def test_import_accepts_valid_json(client):
    data = base64.b64encode(b'{"a": 1}').decode("ascii")
    resp = client.post("/import", json={"data": data})
    assert resp.status_code == 200
    assert resp.get_json()["kind"] == "dict"


def test_rejected_request_writes_blocked_input_log(client, tmp_path):
    client.get("/ping", query_string={"host": "bad host!"})
    records = read_log(tmp_path)
    assert records, "expected at least one log line"
    last = records[-1]
    assert last["event"] == "blocked_input"
    assert last["status"] == 400
    assert last["variant"] == "fixed"
    assert last["method"] == "GET"
    assert last["path"] == "/ping"
    assert set(last) == {
        "ts", "variant", "method", "path", "query", "status", "remote_addr", "event",
    }
