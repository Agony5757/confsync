"""API/auth data-layer tests: key hashing, sessions, allowlist bootstrap."""
import time

from confsync_server import auth, db


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

    db.create_api_key(conn, account["uid"], "laptop", key)
    found = db.get_user_by_api_key(conn, key)
    assert found["username"] == "alice"

    # unknown key rejected
    assert db.get_user_by_api_key(conn, "cs_nonexistent") is None

    # revoke → rejected
    key_id = db.list_api_keys(conn, account["uid"])[0]["id"]
    assert db.revoke_api_key(conn, account["uid"], key_id)
    assert db.get_user_by_api_key(conn, key) is None
    conn.close()


def test_api_key_only_hash_stored(tmp_path):
    conn = _conn(tmp_path)
    account = _make_account(conn)
    key = auth.generate_api_key()
    db.create_api_key(conn, account["uid"], "laptop", key)
    row = conn.execute("SELECT * FROM api_keys").fetchone()
    assert key not in row["key_hash"]
    assert row["prefix"] == key[:8]
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
