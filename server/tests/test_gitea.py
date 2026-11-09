"""Gitea login: OAuth web flow, access-token API auth, account linking."""
import sqlite3
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

from confsync_server import auth, db
from confsync_server.app import create_app
from confsync_server.config import ServerSettings, load_settings

GITEA_URL = "http://git.example.com"
GITEA_PROFILE = {"id": 7, "login": "gitea-user", "name": "Gitea User",
                 "avatar_url": f"{GITEA_URL}/avatars/7",
                 "email": "gitea-user@example.com"}


@pytest.fixture()
def gitea_server(tmp_path):
    settings = ServerSettings(
        home=str(tmp_path),
        external_url="http://testserver",
        github_client_id="gh-id",
        gitea_url=GITEA_URL,
        gitea_client_id="gt-id",
        gitea_client_secret="gt-secret",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        yield client


def _patch_fetch(monkeypatch, token="good-token", profile=GITEA_PROFILE):
    async def fake_fetch(gitea_url, access_token):
        if access_token != token:
            raise ValueError("Gitea rejected the access token (invalid or revoked).")
        return dict(profile)
    monkeypatch.setattr(auth, "fetch_gitea_user", fake_fetch)


def _oauth_state(client) -> str:
    resp = client.get("/auth/gitea/login", follow_redirects=False)
    assert resp.status_code == 307
    loc = resp.headers["location"]
    assert loc.startswith(f"{GITEA_URL}/login/oauth/authorize")
    return parse_qs(urlparse(loc).query)["state"][0]


# ── settings ──────────────────────────────────────────────────────

def test_settings_gitea_yaml_and_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "server.yaml").write_text(
        "gitea:\n  url: https://git.example.com/\n  client_id: id1\n  client_secret: sec1\n"
    )
    monkeypatch.setenv("CONFSYNC_HOME", str(home))
    s = load_settings()
    assert s.gitea_url == "https://git.example.com"  # trailing slash stripped
    assert s.gitea_client_id == "id1"
    assert s.gitea_configured

    monkeypatch.setenv("CONFSYNC_GITEA_CLIENT_ID", "id2")
    s = load_settings()
    assert s.gitea_client_id == "id2"

    # a home without gitea config is not configured
    bare = tmp_path / "bare"
    bare.mkdir()
    monkeypatch.setenv("CONFSYNC_HOME", str(bare))
    assert not load_settings().gitea_configured


def test_build_gitea_authorize_url():
    url = auth.build_gitea_authorize_url(
        GITEA_URL, "cid", "https://cb.example.com/cb", "st ate"
    )
    parts = urlparse(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{GITEA_URL}/login/oauth/authorize"
    assert parse_qs(parts.query) == {
        "client_id": ["cid"],
        "redirect_uri": ["https://cb.example.com/cb"],
        "response_type": ["code"],
        "state": ["st ate"],
        "scope": ["read:user"],
    }


# ── account resolution ────────────────────────────────────────────

def test_first_gitea_login_creates_admin_account(tmp_path):
    from confsync_server.app import _resolve_account
    conn = db.connect(str(tmp_path / "t.db"))
    assert db.is_login_allowed(conn, "anyone")  # empty db → bootstrap open
    account = _resolve_account(conn, "gitea", GITEA_PROFILE)
    assert account["is_admin"] == 1
    assert account["username"] == "gitea-user"
    assert [i["provider"] for i in db.list_identities(conn, account["uid"])] == ["gitea"]

    # logging in again resolves to the same account, no duplicate
    again = _resolve_account(conn, "gitea", GITEA_PROFILE)
    assert again["uid"] == account["uid"]
    assert db.count_accounts(conn) == 1
    conn.close()


def test_bootstrap_account_adopts_gitea_identity(tmp_path):
    from confsync_server.app import _resolve_account
    conn = db.connect(str(tmp_path / "t.db"))
    boot = db.create_account(conn, "carol")   # e.g. confsync-server bootstrap
    db.allow_login(conn, "carol")
    account = _resolve_account(conn, "gitea",
                               {"id": 3003, "login": "carol", "name": "Carol",
                                "avatar_url": "", "email": ""})
    assert account["uid"] == boot["uid"]
    assert db.count_accounts(conn) == 1
    conn.close()


def test_gitea_and_github_same_email_share_account(tmp_path):
    from confsync_server.app import _resolve_account
    conn = db.connect(str(tmp_path / "t.db"))
    gh = _resolve_account(conn, "github",
                          {"id": 1001, "login": "Agony5757", "name": "A",
                           "avatar_url": "", "email": "me@example.com"})
    db.bind_email(conn, gh["uid"], "me@example.com")
    gt = _resolve_account(conn, "gitea",
                          {"id": 7, "login": "agony", "name": "A",
                           "avatar_url": "", "email": "me@example.com"})
    assert gt["uid"] == gh["uid"]  # email binding linked both providers
    assert {i["provider"] for i in db.list_identities(conn, gh["uid"])} == {"github", "gitea"}
    conn.close()


# ── web: OAuth login ──────────────────────────────────────────────

def test_login_page_shows_both_providers(gitea_server):
    resp = gitea_server.get("/login")
    assert resp.status_code == 200
    assert "Sign in with GitHub" in resp.text
    assert "Sign in with Gitea" in resp.text


def test_gitea_login_redirects_with_state(gitea_server):
    resp = gitea_server.get("/auth/gitea/login", follow_redirects=False)
    assert resp.status_code == 307
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["client_id"] == ["gt-id"]
    assert q["redirect_uri"] == ["http://testserver/auth/gitea/callback"]


def test_gitea_oauth_callback_logs_in(gitea_server, monkeypatch):
    async def fake_exchange(gitea_url, client_id, client_secret, code, redirect_uri):
        assert (client_id, client_secret) == ("gt-id", "gt-secret")
        assert redirect_uri == "http://testserver/auth/gitea/callback"
        return "oauth-token"

    _patch_fetch(monkeypatch, token="oauth-token")
    monkeypatch.setattr(auth, "exchange_gitea_code", fake_exchange)

    state = _oauth_state(gitea_server)
    resp = gitea_server.get(f"/auth/gitea/callback?code=c&state={state}")
    assert resp.status_code == 200  # followed the redirect to /
    assert "gitea-user" in resp.text  # nav shows the logged-in account

    conn = db.connect(gitea_server.app.state.settings.db_path)
    row = conn.execute(
        "SELECT a.*, i.provider FROM accounts a"
        " JOIN identities i ON i.uid = a.uid WHERE a.username = 'gitea-user'"
    ).fetchone()
    conn.close()
    assert row["provider"] == "gitea" and row["is_admin"] == 1


def test_gitea_oauth_callback_rejects_bad_state(gitea_server):
    resp = gitea_server.get("/auth/gitea/callback?code=c&state=bogus")
    assert "Invalid OAuth state" in resp.text


def test_gitea_oauth_denied_when_not_allowlisted(gitea_server, monkeypatch):
    conn = db.connect(gitea_server.app.state.settings.db_path)
    db.create_account(conn, "admin")  # accounts exist → allowlist applies
    conn.close()

    async def fake_exchange(gitea_url, client_id, client_secret, code, redirect_uri):
        return "oauth-token"

    _patch_fetch(monkeypatch, token="oauth-token")
    monkeypatch.setattr(auth, "exchange_gitea_code", fake_exchange)

    state = _oauth_state(gitea_server)
    resp = gitea_server.get(f"/auth/gitea/callback?code=c&state={state}")
    assert "not on the allowlist" in resp.text


# ── REST API: Gitea access tokens ─────────────────────────────────

def test_api_accepts_gitea_token_with_cache(gitea_server, monkeypatch):
    calls = {"gitea_hits": 0}

    async def fake_fetch(gitea_url, access_token):
        calls["gitea_hits"] += 1
        if access_token != "gt-token":
            raise ValueError("Gitea rejected the access token (invalid or revoked).")
        return dict(GITEA_PROFILE)

    monkeypatch.setattr(auth, "fetch_gitea_user", fake_fetch)
    h = {"Authorization": "Bearer gt-token"}

    resp = gitea_server.get("/api/v1/whoami", headers=h)
    assert resp.status_code == 200
    assert resp.json() == {"username": "gitea-user", "login": "gitea-user",
                           "name": "Gitea User"}

    # second call is served from the cache — Gitea hit only once
    assert gitea_server.get("/api/v1/documents", headers=h).status_code == 200
    assert calls["gitea_hits"] == 1

    # the token drives the full document lifecycle
    gitea_server.put("/api/v1/documents/app/cfg", json={"content": "x"}, headers=h)
    resp = gitea_server.get("/api/v1/documents/app/cfg", headers=h)
    assert resp.json()["content"] == "x"


def test_api_rejects_invalid_gitea_token(gitea_server, monkeypatch):
    _patch_fetch(monkeypatch, token="good-token")
    resp = gitea_server.get("/api/v1/whoami",
                            headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401


def test_api_gitea_token_respects_allowlist(gitea_server, monkeypatch):
    conn = db.connect(gitea_server.app.state.settings.db_path)
    db.create_account(conn, "admin")  # accounts exist → allowlist applies
    conn.close()
    _patch_fetch(monkeypatch, token="good-token")
    resp = gitea_server.get("/api/v1/whoami",
                            headers={"Authorization": "Bearer good-token"})
    assert resp.status_code == 403
    assert "not on the allowlist" in resp.json()["error"]


def test_api_non_cs_token_rejected_without_gitea(tmp_path):
    settings = ServerSettings(home=str(tmp_path), external_url="http://testserver",
                              github_client_id="gh-id")
    app = create_app(settings)
    with TestClient(app) as client:
        resp = client.get("/api/v1/whoami",
                          headers={"Authorization": "Bearer gitea-style-token"})
        assert resp.status_code == 401
