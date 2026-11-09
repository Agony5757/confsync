"""Account model: uid/username/email bindings, identity linking, isolation,
migration from the pre-0.3 users table."""
import sqlite3

import pytest
from starlette.testclient import TestClient

from confsync_server import db
from confsync_server.app import create_app
from confsync_server.config import ServerSettings

GH = {"id": 1001, "login": "Agony5757", "name": "GH Name", "avatar_url": "", "email": ""}
GT = {"id": 7, "login": "agony", "name": "GT Name", "avatar_url": "",
      "email": "agony@example.com"}


def test_account_basics_and_username_dedup(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    a1 = db.create_account(conn, "agony")
    db.bind_email(conn, a1["uid"], "A@Example.com")
    assert a1["is_admin"] == 1  # first account is admin
    assert db.get_account_by_email(conn, "a@example.com")["uid"] == a1["uid"]

    a2 = db.create_account(conn, "agony")  # same name → deduped
    assert a2["username"] == "agony-2"
    assert db.count_accounts(conn) == 2
    conn.close()


def test_email_binding_rules(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    a = db.create_account(conn, "alice")
    assert db.bind_email(conn, a["uid"], "alice@example.com")
    assert not db.bind_email(conn, a["uid"], "alice@example.com")  # idempotent

    b = db.create_account(conn, "bob")
    with pytest.raises(ValueError):  # bound to another account
        db.bind_email(conn, b["uid"], "alice@example.com")
    with pytest.raises(ValueError):  # not an email
        db.bind_email(conn, b["uid"], "nope")

    assert db.unbind_email(conn, a["uid"], "ALICE@EXAMPLE.COM")
    assert not db.unbind_email(conn, a["uid"], "alice@example.com")
    conn.close()


def test_username_uniqueness_case_insensitive_lookup(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    db.create_account(conn, "alice")
    assert db.get_account_by_email(conn, "") is None
    assert db.get_account_by_username(conn, "alice")["username"] == "alice"
    assert db.get_account_by_username(conn, "carol") is None
    conn.close()


def test_migration_preserves_uid_and_link_identities(tmp_path):
    """Old users table → accounts keep their numeric id (ciphertext AAD!) and
    gain identity rows for their linked providers. The 0.2 schema declares
    FOREIGN KEYs on sessions/api_keys/documents pointing at users — the
    migration rebuilds them against accounts."""
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript("""\
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    github_id INTEGER NOT NULL UNIQUE,
    gitea_id INTEGER,
    login TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at REAL    NOT NULL
);
CREATE TABLE api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    name         TEXT    NOT NULL DEFAULT '',
    key_hash     TEXT    NOT NULL UNIQUE,
    prefix       TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    last_used_at REAL,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE documents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    app        TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    ciphertext BLOB    NOT NULL,
    version    INTEGER NOT NULL,
    updated_at REAL    NOT NULL,
    UNIQUE (user_id, app, name)
);
INSERT INTO users (github_id, gitea_id, login, is_admin, created_at)
VALUES (1, NULL, 'gh-only', 1, 100);
INSERT INTO users (github_id, gitea_id, login, is_admin, created_at)
VALUES (2, 7, 'both', 0, 101);
INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('h1', 1, 9e18);
INSERT INTO api_keys (user_id, name, key_hash, prefix, created_at)
VALUES (2, 'k', 'kh', 'cs_1234', 100);
INSERT INTO documents (user_id, app, name, ciphertext, version, updated_at)
VALUES (1, 'app', 'doc', X'00', 1, 100);
""")
    conn.commit()
    conn.close()

    conn = db.connect(path)
    tables = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "users" not in tables
    assert "sessions_old" not in tables

    gh_only = db.get_account_by_username(conn, "gh-only")
    both = db.get_account_by_username(conn, "both")
    assert gh_only["uid"] == 1 and gh_only["is_admin"] == 1  # uid preserved
    assert both["uid"] == 2
    assert {i["provider"] for i in db.list_identities(conn, 1)} == {"github"}
    assert {i["provider"] for i in db.list_identities(conn, 2)} == {"github", "gitea"}
    # child rows carried over to the same uid, FKs now reference accounts
    assert conn.execute("SELECT user_id FROM documents").fetchone()["user_id"] == 1
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0] == 1
    # inserts into the rebuilt tables still satisfy FK enforcement
    db.create_session(conn, 1, "tok")
    conn.close()


# ── app-level: login → account resolution & isolation ────────────

@pytest.fixture()
def app_server(tmp_path):
    settings = ServerSettings(home=str(tmp_path), external_url="http://testserver",
                              github_client_id="gh-id")
    app = create_app(settings)
    with TestClient(app) as client:
        yield client


def test_resolver_links_by_email(app_server, monkeypatch):
    conn = db.connect(app_server.app.state.settings.db_path)
    account = db.create_account(conn, "agony")
    db.bind_email(conn, account["uid"], "agony@example.com")
    conn.close()

    from confsync_server.app import _resolve_account

    conn = db.connect(app_server.app.state.settings.db_path)
    account = _resolve_account(conn, "gitea", GT)
    assert account is not None
    assert account["username"] == "agony"          # matched by email binding
    ids = db.list_identities(conn, account["uid"])
    assert {i["provider"] for i in ids} == {"gitea"}
    assert db.count_accounts(conn) == 1            # no second account created
    conn.close()


def test_resolver_creates_allowlisted_account(app_server):
    from confsync_server.app import _resolve_account

    conn = db.connect(app_server.app.state.settings.db_path)
    db.create_account(conn, "admin")  # admin exists → allowlist applies
    db.allow_login(conn, "newbie")
    assert db.is_login_allowed(conn, "newbie")

    account = _resolve_account(conn, "github", {"id": 42, "login": "newbie",
                                                "name": "", "avatar_url": "",
                                                "email": ""})
    assert account is not None and account["username"] == "newbie"
    assert db.count_accounts(conn) == 2

    denied = _resolve_account(conn, "github", {"id": 43, "login": "stranger",
                                               "name": "", "avatar_url": "",
                                               "email": ""})
    assert denied is None  # not allowlisted → no account
    conn.close()


def test_resolver_identity_wins_over_email(app_server):
    """An identity already linked to account A is not hijacked by account B
    binding the same email."""
    from confsync_server.app import _resolve_account

    conn = db.connect(app_server.app.state.settings.db_path)
    a = db.create_account(conn, "a")
    db.link_identity(conn, a["uid"], "gitea", 7, "agony", "agony@example.com")
    b = db.create_account(conn, "b")
    db.bind_email(conn, b["uid"], "agony@example.com")  # email on another account

    account = _resolve_account(conn, "gitea", GT)  # gitea id 7 → account a
    assert account["uid"] == a["uid"]
    conn.close()


def test_accounts_see_different_documents(tmp_path):
    settings = ServerSettings(home=str(tmp_path), external_url="http://testserver",
                              github_client_id="gh-id")
    app = create_app(settings)
    with TestClient(app) as client:
        conn = db.connect(settings.db_path)
        keys = {}
        for username in ("alice", "bob"):
            db.allow_login(conn, username)
            account = db.create_account(conn, username)
            key = "cs_" + username
            db.create_api_key(conn, account["uid"], "t", key)
            keys[username] = key
        conn.close()

        ha = {"Authorization": f"Bearer {keys['alice']}"}
        hb = {"Authorization": f"Bearer {keys['bob']}"}
        assert client.put("/api/v1/documents/app/secret",
                          json={"content": "alice only"}, headers=ha).status_code == 200
        assert client.get("/api/v1/documents/app/secret",
                          headers=hb).status_code == 404
        assert client.get("/api/v1/documents", headers=hb).json()["documents"] == []
        assert client.get("/api/v1/documents/app/secret",
                          headers=ha).json()["content"] == "alice only"
        who = client.get("/api/v1/whoami", headers=ha).json()
        assert who == {"username": "alice", "login": "alice", "name": ""}


def test_admin_manages_accounts_and_emails(app_server):
    # log in as admin via OAuth simulation: bootstrap → first login is admin
    from confsync_server.app import _resolve_account
    settings = app_server.app.state.settings
    conn = db.connect(settings.db_path)
    admin = _resolve_account(conn, "github", GH)
    assert admin["is_admin"] == 1
    token = "sess-tok"
    db.create_session(conn, admin["uid"], token)
    conn.close()
    cookies = {"confsync_session": token}

    resp = app_server.get("/admin", cookies=cookies)
    assert resp.status_code == 200
    assert "Agony5757" in resp.text

    # create an account with an email
    resp = app_server.post("/admin/accounts/create", cookies=cookies,
                           data={"username": "carol", "emails": "carol@example.com"},
                           follow_redirects=False)
    assert resp.status_code == 303
    resp = app_server.get("/admin", cookies=cookies)
    assert "carol@example.com" in resp.text

    # duplicate email on another account is rejected with an error
    resp = app_server.post("/admin/accounts/create", cookies=cookies,
                           data={"username": "dave", "emails": "carol@example.com"},
                           follow_redirects=False)
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]

    # unbind → email lookup misses again
    conn = db.connect(settings.db_path)
    carol = db.get_account_by_username(conn, "carol")
    conn.close()
    app_server.post(f"/admin/accounts/{carol['uid']}/emails/remove",
                    cookies=cookies, data={"email": "carol@example.com"})
    conn = db.connect(settings.db_path)
    assert db.get_account_by_email(conn, "carol@example.com") is None
    conn.close()
