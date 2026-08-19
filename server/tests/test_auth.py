"""API/auth data-layer tests: key hashing, sessions, allowlist bootstrap."""
import time

from confsync_server import auth, db


def _conn(tmp_path):
    return db.connect(str(tmp_path / "test.db"))


def _make_user(conn, login="alice", github_id=1001):
    return db.upsert_user(conn, github_id, login, "Alice", "")


def test_first_user_becomes_admin_and_allowed(tmp_path):
    conn = _conn(tmp_path)
    assert db.is_login_allowed(conn, "anyone")  # empty db → bootstrap open
    user = _make_user(conn)
    assert user["is_admin"] == 1
    assert db.is_login_allowed(conn, "alice")
    assert not db.is_login_allowed(conn, "mallory")
    conn.close()


def test_second_user_not_admin(tmp_path):
    conn = _conn(tmp_path)
    _make_user(conn)
    db.allow_login(conn, "bob")
    user2 = db.upsert_user(conn, 1002, "bob", "Bob", "")
    assert user2["is_admin"] == 0
    conn.close()


def test_api_key_lifecycle(tmp_path):
    conn = _conn(tmp_path)
    user = _make_user(conn)
    key = auth.generate_api_key()
    assert key.startswith("cs_") and len(key) == 51

    db.create_api_key(conn, user["id"], "laptop", key)
    found = db.get_user_by_api_key(conn, key)
    assert found["login"] == "alice"

    # unknown key rejected
    assert db.get_user_by_api_key(conn, "cs_nonexistent") is None

    # revoke → rejected
    key_id = db.list_api_keys(conn, user["id"])[0]["id"]
    assert db.revoke_api_key(conn, user["id"], key_id)
    assert db.get_user_by_api_key(conn, key) is None
    conn.close()


def test_api_key_only_hash_stored(tmp_path):
    conn = _conn(tmp_path)
    user = _make_user(conn)
    key = auth.generate_api_key()
    db.create_api_key(conn, user["id"], "laptop", key)
    row = conn.execute("SELECT * FROM api_keys").fetchone()
    assert key not in row["key_hash"]
    assert row["prefix"] == key[:8]
    conn.close()


def test_session_expiry(tmp_path):
    conn = _conn(tmp_path)
    user = _make_user(conn)
    token = auth.generate_session_token()
    db.create_session(conn, user["id"], token)
    assert db.get_session_user(conn, token)["login"] == "alice"

    # force expiry
    conn.execute("UPDATE sessions SET expires_at = ?", (time.time() - 1,))
    conn.commit()
    assert db.get_session_user(conn, token) is None
    conn.close()


def test_bootstrap_user_adopts_github_id(tmp_path):
    conn = _conn(tmp_path)
    boot = db.create_bootstrap_user(conn, "carol")
    assert boot["is_admin"] == 1
    assert boot["github_id"] < 0

    # same login again → no duplicate
    assert db.create_bootstrap_user(conn, "carol")["id"] == boot["id"]

    # first OAuth login adopts the placeholder row: docs/keys carry over
    user = db.upsert_user(conn, 3003, "carol", "Carol", "")
    assert user["id"] == boot["id"]
    assert user["github_id"] == 3003
    assert db.count_users(conn) == 1
    conn.close()
