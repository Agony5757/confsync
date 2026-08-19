"""SQLite data layer: users, sessions, API keys, encrypted documents.

Secrets at rest: only sha256 hashes of session tokens and API keys are stored;
document contents are AES-256-GCM ciphertexts (see crypto.py).
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time

SCHEMA = """\
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    github_id  INTEGER NOT NULL UNIQUE,
    login      TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL DEFAULT '',
    avatar_url TEXT    NOT NULL DEFAULT '',
    is_admin   INTEGER NOT NULL DEFAULT 0,
    created_at REAL    NOT NULL
);
CREATE TABLE IF NOT EXISTS allowed_logins (
    login TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at REAL    NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    name         TEXT    NOT NULL DEFAULT '',
    key_hash     TEXT    NOT NULL UNIQUE,
    prefix       TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    last_used_at REAL,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS documents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    app        TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    ciphertext BLOB    NOT NULL,
    version    INTEGER NOT NULL,
    updated_at REAL    NOT NULL,
    UNIQUE (user_id, app, name)
);
CREATE TABLE IF NOT EXISTS document_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    app        TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    version    INTEGER NOT NULL,
    ciphertext BLOB    NOT NULL,
    saved_at   REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_doc ON document_history (user_id, app, name, version);
"""

SESSION_TTL = 30 * 24 * 3600  # 30 days
HISTORY_KEEP = 20


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    return conn


# ── users / allowlist ─────────────────────────────────────────────

def get_user_by_github_id(conn: sqlite3.Connection, github_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE github_id = ?", (github_id,)).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def count_users(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]


def seed_allowed_logins(conn: sqlite3.Connection, logins: list[str]) -> None:
    """Seed the allowlist from config (idempotent; never removes entries)."""
    for login in logins:
        conn.execute("INSERT OR IGNORE INTO allowed_logins (login) VALUES (?)", (login,))
    conn.commit()


def is_login_allowed(conn: sqlite3.Connection, login: str) -> bool:
    """Allowed when the users table is empty (bootstrap: first login becomes
    admin) or when the login is on the allowlist."""
    if count_users(conn) == 0:
        return True
    row = conn.execute("SELECT login FROM allowed_logins WHERE login = ?", (login,)).fetchone()
    return row is not None


def upsert_user(conn: sqlite3.Connection, github_id: int, login: str,
                name: str, avatar_url: str) -> sqlite3.Row:
    """Insert or refresh a user from their GitHub profile. The very first
    user becomes admin and is added to the allowlist."""
    existing = get_user_by_github_id(conn, github_id)
    now = time.time()
    if existing:
        conn.execute(
            "UPDATE users SET login = ?, name = ?, avatar_url = ? WHERE id = ?",
            (login, name, avatar_url, existing["id"]),
        )
        conn.commit()
        return get_user_by_id(conn, existing["id"])
    # A CLI-bootstrapped user (placeholder negative github_id) adopts its real
    # GitHub id on first OAuth login, keeping its documents and API keys.
    by_login = conn.execute("SELECT * FROM users WHERE login = ?", (login,)).fetchone()
    if by_login is not None and by_login["github_id"] < 0:
        conn.execute(
            "UPDATE users SET github_id = ?, name = ?, avatar_url = ? WHERE id = ?",
            (github_id, name, avatar_url, by_login["id"]),
        )
        conn.commit()
        return get_user_by_id(conn, by_login["id"])
    is_admin = 1 if count_users(conn) == 0 else 0
    cur = conn.execute(
        "INSERT INTO users (github_id, login, name, avatar_url, is_admin, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (github_id, login, name, avatar_url, is_admin, now),
    )
    if is_admin:
        conn.execute("INSERT OR IGNORE INTO allowed_logins (login) VALUES (?)", (login,))
    conn.commit()
    return get_user_by_id(conn, cur.lastrowid)


def create_bootstrap_user(conn: sqlite3.Connection, login: str) -> sqlite3.Row:
    """Create a CLI-only user (placeholder negative github_id) so an API key
    can be issued before GitHub OAuth is set up. On first OAuth login the row
    adopts the real github_id (see upsert_user)."""
    import secrets

    existing = conn.execute("SELECT * FROM users WHERE login = ?", (login,)).fetchone()
    if existing is not None:
        return existing
    is_admin = 1 if count_users(conn) == 0 else 0
    cur = conn.execute(
        "INSERT INTO users (github_id, login, name, avatar_url, is_admin, created_at)"
        " VALUES (?, ?, '', '', ?, ?)",
        (-(secrets.randbelow(2**62) + 1), login, is_admin, time.time()),
    )
    conn.execute("INSERT OR IGNORE INTO allowed_logins (login) VALUES (?)", (login,))
    conn.commit()
    return get_user_by_id(conn, cur.lastrowid)


def allow_login(conn: sqlite3.Connection, login: str) -> None:
    conn.execute("INSERT OR IGNORE INTO allowed_logins (login) VALUES (?)", (login,))
    conn.commit()


def disallow_login(conn: sqlite3.Connection, login: str) -> None:
    conn.execute("DELETE FROM allowed_logins WHERE login = ?", (login,))
    conn.commit()


def list_allowed_logins(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT login FROM allowed_logins ORDER BY login").fetchall()
    return [r["login"] for r in rows]


# ── web sessions ──────────────────────────────────────────────────

def create_session(conn: sqlite3.Connection, user_id: int, token: str) -> None:
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        (hash_token(token), user_id, time.time() + SESSION_TTL),
    )
    conn.commit()


def get_session_user(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    row = conn.execute(
        "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?",
        (hash_token(token),),
    ).fetchone()
    if row is None:
        return None
    if row["expires_at"] < time.time():
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
        conn.commit()
        return None
    return get_user_by_id(conn, row["user_id"])


def delete_session(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
    conn.commit()


# ── API keys ──────────────────────────────────────────────────────

def create_api_key(conn: sqlite3.Connection, user_id: int, name: str,
                   plaintext_key: str) -> None:
    conn.execute(
        "INSERT INTO api_keys (user_id, name, key_hash, prefix, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (user_id, name, hash_token(plaintext_key), plaintext_key[:8], time.time()),
    )
    conn.commit()


def get_user_by_api_key(conn: sqlite3.Connection, plaintext_key: str) -> sqlite3.Row | None:
    row = conn.execute(
        "SELECT id, user_id, revoked FROM api_keys WHERE key_hash = ?",
        (hash_token(plaintext_key),),
    ).fetchone()
    if row is None or row["revoked"]:
        return None
    conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (time.time(), row["id"]))
    conn.commit()
    return get_user_by_id(conn, row["user_id"])


def list_api_keys(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, name, prefix, created_at, last_used_at, revoked FROM api_keys"
        " WHERE user_id = ? ORDER BY id",
        (user_id,),
    ).fetchall()


def revoke_api_key(conn: sqlite3.Connection, user_id: int, key_id: int) -> bool:
    cur = conn.execute(
        "UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?",
        (key_id, user_id),
    )
    conn.commit()
    return cur.rowcount > 0


# ── documents ─────────────────────────────────────────────────────

def put_document(conn: sqlite3.Connection, user_id: int, app: str, name: str,
                 ciphertext: bytes) -> int:
    """Insert or replace a document; archives the previous version. Returns
    the new version number."""
    now = time.time()
    row = conn.execute(
        "SELECT version, ciphertext FROM documents WHERE user_id = ? AND app = ? AND name = ?",
        (user_id, app, name),
    ).fetchone()
    if row is None:
        new_version = 1
        conn.execute(
            "INSERT INTO documents (user_id, app, name, ciphertext, version, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, app, name, ciphertext, new_version, now),
        )
    else:
        new_version = row["version"] + 1
        conn.execute(
            "INSERT INTO document_history (user_id, app, name, version, ciphertext, saved_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, app, name, row["version"], row["ciphertext"], now),
        )
        conn.execute(
            "UPDATE documents SET ciphertext = ?, version = ?, updated_at = ?"
            " WHERE user_id = ? AND app = ? AND name = ?",
            (ciphertext, new_version, now, user_id, app, name),
        )
        # prune history beyond HISTORY_KEEP
        conn.execute(
            "DELETE FROM document_history WHERE user_id = ? AND app = ? AND name = ?"
            " AND version NOT IN ("
            "   SELECT version FROM document_history"
            "   WHERE user_id = ? AND app = ? AND name = ?"
            "   ORDER BY version DESC LIMIT ?"
            " )",
            (user_id, app, name, user_id, app, name, HISTORY_KEEP),
        )
    conn.commit()
    return new_version


def get_document(conn: sqlite3.Connection, user_id: int, app: str, name: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM documents WHERE user_id = ? AND app = ? AND name = ?",
        (user_id, app, name),
    ).fetchone()


def list_documents(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT app, name, version, updated_at, length(ciphertext) AS size"
        " FROM documents WHERE user_id = ? ORDER BY app, name",
        (user_id,),
    ).fetchall()


def delete_document(conn: sqlite3.Connection, user_id: int, app: str, name: str) -> bool:
    cur = conn.execute(
        "DELETE FROM documents WHERE user_id = ? AND app = ? AND name = ?",
        (user_id, app, name),
    )
    conn.execute(
        "DELETE FROM document_history WHERE user_id = ? AND app = ? AND name = ?",
        (user_id, app, name),
    )
    conn.commit()
    return cur.rowcount > 0


def list_history(conn: sqlite3.Connection, user_id: int, app: str, name: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT version, saved_at, length(ciphertext) AS size FROM document_history"
        " WHERE user_id = ? AND app = ? AND name = ? ORDER BY version DESC",
        (user_id, app, name),
    ).fetchall()


def get_history_version(conn: sqlite3.Connection, user_id: int, app: str, name: str,
                        version: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM document_history"
        " WHERE user_id = ? AND app = ? AND name = ? AND version = ?",
        (user_id, app, name, version),
    ).fetchone()
