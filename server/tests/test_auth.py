"""API/auth data-layer tests: key storage, sessions, OAuth helpers."""
import asyncio
import time

import httpx
import pytest

from confsync_server import auth, db

MASTER_KEY = b"k" * 32


def _conn(tmp_path):
    return db.connect(str(tmp_path / "test.db"))


def _make_account(conn, username="alice", github_id=1001):
    account = db.create_account(conn, username)
    db.link_identity(conn, account["uid"], "github", github_id, username)
    return db.get_account_by_uid(conn, account["uid"])


def test_first_account_becomes_admin_and_allowed(tmp_path):
    conn = _conn(tmp_path)
    assert db.is_login_allowed(conn, "anyone")  # empty db → bootstrap open
    account = _make_account(conn)
    assert account["is_admin"] == 1
    assert db.is_login_allowed(conn, "alice")
    assert not db.is_login_allowed(conn, "mallory")
    conn.close()


def test_second_account_not_admin(tmp_path):
    conn = _conn(tmp_path)
    _make_account(conn)
    db.allow_login(conn, "bob")
    account2 = db.create_account(conn, "bob")
    assert account2["is_admin"] == 0
    conn.close()


def test_api_key_lifecycle(tmp_path):
    conn = _conn(tmp_path)
    account = _make_account(conn)
    key = auth.generate_api_key()
    assert key.startswith("cs_") and len(key) == 51

    db.create_api_key(conn, account["uid"], "laptop", key, master_key=MASTER_KEY)
    found = db.get_user_by_api_key(conn, key)
    assert found["username"] == "alice"

    # unknown key rejected
    assert db.get_user_by_api_key(conn, "cs_nonexistent") is None

    # revoke → rejected
    key_id = db.list_api_keys(conn, account["uid"])[0]["id"]
    assert db.revoke_api_key(conn, account["uid"], key_id)
    assert db.get_user_by_api_key(conn, key) is None
    conn.close()


def test_api_key_stores_hash_and_ciphertext_not_plaintext(tmp_path):
    conn = _conn(tmp_path)
    account = _make_account(conn)
    key = auth.generate_api_key()
    db.create_api_key(conn, account["uid"], "laptop", key, master_key=MASTER_KEY)
    row = conn.execute("SELECT * FROM api_keys").fetchone()
    assert key not in row["key_hash"]
    assert key.encode() not in row["key_ciphertext"]
    assert row["prefix"] == key[:8]
    listed = db.list_api_keys(conn, account["uid"])[0]
    assert db.decrypt_api_key(listed, MASTER_KEY) == key
    conn.close()


def test_session_expiry(tmp_path):
    conn = _conn(tmp_path)
    account = _make_account(conn)
    token = auth.generate_session_token()
    db.create_session(conn, account["uid"], token)
    assert db.get_session_user(conn, token)["username"] == "alice"

    # force expiry
    conn.execute("UPDATE sessions SET expires_at = ?", (time.time() - 1,))
    conn.commit()
    assert db.get_session_user(conn, token) is None
    conn.close()


def _mock_http(monkeypatch, handler):
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )


def test_github_network_error_is_normalized(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection failed", request=request)

    _mock_http(monkeypatch, handler)
    with pytest.raises(ValueError, match="GitHub user fetch failed"):
        asyncio.run(auth.fetch_github_user("oauth-token"))


def test_github_unexpected_email_response_is_normalized(monkeypatch):
    def handler(request):
        if request.url == auth.GITHUB_USER_URL:
            return httpx.Response(200, json={
                "id": 1001, "login": "alice", "email": None,
            })
        assert request.url == auth.GITHUB_EMAILS_URL
        return httpx.Response(200, json={"message": "unexpected"})

    _mock_http(monkeypatch, handler)
    with pytest.raises(ValueError, match="GitHub email fetch"):
        asyncio.run(auth.fetch_github_user("oauth-token"))
