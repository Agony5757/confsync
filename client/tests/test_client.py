import json

import httpx
import pytest

from confsync import ConfsyncClient, ConfsyncError, load_client, login
from confsync.core import validate_server_url


def test_validate_server_url():
    assert validate_server_url("https://conf.example.com/") == "https://conf.example.com"
    assert validate_server_url("http://localhost:8930") == "http://localhost:8930"
    assert validate_server_url("http://127.0.0.1:8930") == "http://127.0.0.1:8930"
    with pytest.raises(ConfsyncError):
        validate_server_url("http://conf.example.com")  # plaintext remote
    with pytest.raises(ConfsyncError):
        validate_server_url("not-a-url")


def test_credentials_roundtrip(tmp_path, monkeypatch):
    creds = tmp_path / "credentials.json"
    monkeypatch.setenv("CONFSYNC_CREDENTIALS", str(creds))
    client = login("https://conf.example.com", "cs_" + "a" * 48, verify=False)
    client.close()
    assert creds.exists()
    import stat as stat_mod
    assert stat_mod.S_IMODE(creds.stat().st_mode) == 0o600

    loaded = load_client()
    assert loaded.server_url == "https://conf.example.com"
    loaded.close()


def test_load_client_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFSYNC_CREDENTIALS", str(tmp_path / "nope.json"))
    with pytest.raises(ConfsyncError):
        load_client()


def test_login_rejects_bad_key_format(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFSYNC_CREDENTIALS", str(tmp_path / "c.json"))
    with pytest.raises(ConfsyncError):
        login("https://conf.example.com", "not-a-cs-key", verify=False)


def _mock_app(request: httpx.Request) -> httpx.Response:
    """Tiny in-memory confsync server for client tests."""
    if request.headers.get("Authorization") != "Bearer cs_good":
        return httpx.Response(401, json={"error": "invalid or revoked API key"})
    store = _mock_app.store
    if request.url.path == "/api/v1/whoami":
        return httpx.Response(200, json={"login": "alice", "name": "Alice"})
    if request.method == "PUT":
        body = json.loads(request.content)
        parts = request.url.path.split("/", 4)  # /api/v1/documents/app/name
        store[parts[3] + "/" + parts[4]] = body["content"]
        return httpx.Response(200, json={"version": 1})
    if request.method == "GET" and request.url.path.startswith("/api/v1/documents/"):
        parts = request.url.path.split("/", 4)
        key = parts[3] + "/" + parts[4]
        if key not in store:
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json={"version": 1, "content": store[key]})
    return httpx.Response(404, json={"error": "unknown"})


_mock_app.store = {}


def _mock_client() -> ConfsyncClient:
    return ConfsyncClient("https://conf.example.com", "cs_good",
                          transport=httpx.MockTransport(_mock_app))


def test_client_push_pull_against_mock():
    with _mock_client() as c:
        assert c.whoami()["login"] == "alice"
        assert c.push("app", "cfg.yaml", "a: 1") == 1
        assert c.pull("app", "cfg.yaml") == "a: 1"
        with pytest.raises(ConfsyncError):
            c.pull("app", "missing")


def test_client_auth_error():
    with ConfsyncClient("https://conf.example.com", "cs_bad",
                        transport=httpx.MockTransport(_mock_app)) as c:
        with pytest.raises(ConfsyncError, match="invalid or revoked"):
            c.whoami()
