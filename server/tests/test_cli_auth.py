"""Browser-assisted CLI login: loopback callback + one-time authorization code."""
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

from confsync_server import auth, db
from confsync_server.app import create_app
from confsync_server.config import ServerSettings

GH_PROFILE = {"id": 1001, "login": "Agony5757", "name": "Agony",
              "avatar_url": "", "email": "agony@example.com"}
CALLBACK = "http://127.0.0.1:49151/callback"


@pytest.fixture()
def client(tmp_path):
    settings = ServerSettings(home=str(tmp_path), external_url="http://testserver",
                              github_client_id="gh-id")
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


def _start_github(client, callback=CALLBACK, cli_state="cli-state"):
    resp = client.get("/auth/cli/github", params={
        "redirect_uri": callback, "state": cli_state,
    }, follow_redirects=False)
    assert resp.status_code == 307
    location = resp.headers["location"]
    assert location.startswith("https://github.com/login/oauth/authorize")
    return parse_qs(urlparse(location).query)["state"][0]


def test_cli_login_page_requires_loopback_callback(client):
    for callback in ("https://example.com/callback", "http://127.0.0.1/callback",
                     "http://10.0.0.1:1234/callback"):
        resp = client.get("/auth/cli/login", params={
            "redirect_uri": callback, "state": "cli-state",
        })
        assert "CLI callback must be" in resp.text

    resp = client.get("/auth/cli/login", params={
        "redirect_uri": CALLBACK, "state": "cli-state",
    })
    assert resp.status_code == 200
    assert "Authorize the confsync CLI" in resp.text
    assert "/auth/cli/github?" in resp.text


def test_browser_login_exchange_returns_one_time_api_key(client, monkeypatch):
    async def fake_exchange(client_id, client_secret, code, redirect_uri):
        return "oauth-token"

    async def fake_fetch(token):
        return dict(GH_PROFILE)

    monkeypatch.setattr(auth, "exchange_code", fake_exchange)
    monkeypatch.setattr(auth, "fetch_github_user", fake_fetch)

    provider_state = _start_github(client)
    resp = client.get("/auth/github/callback", params={
        "code": "oauth-code", "state": provider_state,
    }, follow_redirects=False)
    assert resp.status_code == 303
    callback = parse_qs(urlparse(resp.headers["location"]).query)
    assert resp.headers["location"].startswith(CALLBACK)
    assert callback["state"] == ["cli-state"]
    code = callback["code"][0]

    exchanged = client.post("/api/v1/auth/exchange",
                            json={"code": code, "name": "test cli"})
    assert exchanged.status_code == 200
    data = exchanged.json()
    assert data["username"] == "Agony5757"
    assert data["api_key"].startswith("cs_")

    who = client.get("/api/v1/whoami",
                     headers={"Authorization": f"Bearer {data['api_key']}"})
    assert who.status_code == 200
    assert who.json()["username"] == "Agony5757"

    reused = client.post("/api/v1/auth/exchange", json={"code": code})
    assert reused.status_code == 401

    conn = db.connect(client.app.state.settings.db_path)
    key = db.list_api_keys(conn, 1)[0]
    assert key["name"] == "test cli"
    assert db.decrypt_api_key(key, client.app.state.master_key) == data["api_key"]
    conn.close()


def test_provider_error_is_returned_to_cli_callback(client, monkeypatch):
    async def fake_exchange(client_id, client_secret, code, redirect_uri):
        raise ValueError("GitHub token exchange failed: nope")

    monkeypatch.setattr(auth, "exchange_code", fake_exchange)

    provider_state = _start_github(client)
    resp = client.get("/auth/github/callback", params={
        "code": "bad-code", "state": provider_state,
    }, follow_redirects=False)
    assert resp.status_code == 303
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["state"] == ["cli-state"]
    assert query["error"] == ["GitHub token exchange failed: nope"]


def test_exchange_rejects_bad_code(client):
    resp = client.post("/api/v1/auth/exchange", json={"code": "missing"})
    assert resp.status_code == 401
    assert "invalid or expired" in resp.json()["error"]
