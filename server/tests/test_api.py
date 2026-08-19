"""End-to-end REST API tests against the Starlette app (no network)."""
import pytest
from starlette.testclient import TestClient

from confsync_server import auth, db
from confsync_server.app import create_app
from confsync_server.config import ServerSettings


@pytest.fixture()
def server(tmp_path):
    settings = ServerSettings(
        home=str(tmp_path),
        external_url="http://testserver",
        github_client_id="unused-in-tests",
    )
    app = create_app(settings)

    # Create two users with API keys directly in the DB.
    conn = db.connect(settings.db_path)
    keys = {}
    for login_name, gh_id in (("alice", 1001), ("bob", 1002)):
        user = db.upsert_user(conn, gh_id, login_name, login_name, "")
        db.allow_login(conn, login_name)
        key = auth.generate_api_key()
        db.create_api_key(conn, user["id"], "test", key)
        keys[login_name] = key
    conn.close()

    with TestClient(app) as client:
        yield client, keys


def _hdr(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def test_whoami(server):
    client, keys = server
    resp = client.get("/api/v1/whoami", headers=_hdr(keys["alice"]))
    assert resp.status_code == 200
    assert resp.json()["login"] == "alice"


def test_missing_and_bad_key_rejected(server):
    client, _ = server
    assert client.get("/api/v1/documents").status_code == 401
    assert client.get("/api/v1/documents",
                      headers=_hdr("cs_wrong")).status_code == 401


def test_push_pull_roundtrip(server):
    client, keys = server
    h = _hdr(keys["alice"])
    resp = client.put("/api/v1/documents/flexgate/config.yaml",
                      json={"content": "server:\n  port: 8765\n"}, headers=h)
    assert resp.status_code == 200
    assert resp.json()["version"] == 1

    resp = client.get("/api/v1/documents/flexgate/config.yaml", headers=h)
    assert resp.status_code == 200
    data = resp.json()
    assert data["content"] == "server:\n  port: 8765\n"
    assert data["version"] == 1


def test_versioning_and_history(server):
    client, keys = server
    h = _hdr(keys["alice"])
    for i in range(3):
        client.put("/api/v1/documents/app/notes.txt",
                   json={"content": f"v{i + 1} content"}, headers=h)

    hist = client.get("/api/v1/documents/app/notes.txt/history", headers=h).json()["history"]
    assert [r["version"] for r in hist] == [2, 1]

    old = client.get("/api/v1/documents/app/notes.txt/history/1", headers=h).json()
    assert old["content"] == "v1 content"

    latest = client.get("/api/v1/documents/app/notes.txt", headers=h).json()
    assert latest["content"] == "v3 content"
    assert latest["version"] == 3


def test_list_and_delete(server):
    client, keys = server
    h = _hdr(keys["alice"])
    client.put("/api/v1/documents/app/a", json={"content": "1"}, headers=h)
    client.put("/api/v1/documents/app/b", json={"content": "2"}, headers=h)
    docs = client.get("/api/v1/documents", headers=h).json()["documents"]
    assert {(d["app"], d["name"]) for d in docs} == {("app", "a"), ("app", "b")}

    assert client.delete("/api/v1/documents/app/a", headers=h).status_code == 200
    assert client.get("/api/v1/documents/app/a", headers=h).status_code == 404
    # history is gone too
    assert client.get("/api/v1/documents/app/a/history", headers=h).json()["history"] == []


def test_user_isolation(server):
    client, keys = server
    client.put("/api/v1/documents/app/secret",
               json={"content": "alice only"}, headers=_hdr(keys["alice"]))
    resp = client.get("/api/v1/documents/app/secret", headers=_hdr(keys["bob"]))
    assert resp.status_code == 404
    assert client.get("/api/v1/documents", headers=_hdr(keys["bob"])).json()["documents"] == []


def test_put_validation(server):
    client, keys = server
    h = _hdr(keys["alice"])
    assert client.put("/api/v1/documents/app/x",
                      json={"nope": 1}, headers=h).status_code == 400
    big = "x" * (4 * 1024 * 1024 + 1)
    assert client.put("/api/v1/documents/app/x",
                      json={"content": big}, headers=h).status_code == 413


def test_revoked_key_rejected(server, tmp_path):
    client, keys = server
    # revoke alice's key at the db layer
    settings = client.app.state.settings
    conn = db.connect(settings.db_path)
    user = conn.execute("SELECT * FROM users WHERE login = 'alice'").fetchone()
    key_id = db.list_api_keys(conn, user["id"])[0]["id"]
    db.revoke_api_key(conn, user["id"], key_id)
    conn.close()
    assert client.get("/api/v1/documents", headers=_hdr(keys["alice"])).status_code == 401


def test_web_requires_login(server):
    client, _ = server
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
