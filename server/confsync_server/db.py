"""SQLite data layer: accounts, identities, sessions, API keys, documents.

Secrets at rest: only sha256 hashes of session tokens and API keys are stored;
document contents are AES-256-GCM ciphertexts (see crypto.py).

Identity model: a single ``accounts`` table owns everything a user has
(documents, keys, sessions) under one ``uid`` + ``username`` with any number
of bound emails (``email_binding_list``, a JSON array). Provider logins
(GitHub, Gitea) are rows in ``identities`` mapped to an account — by provider
user id first, else by a matching bound email, else a new account is created.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time

SCHEMA = """\
CREATE TABLE IF NOT EXISTS accounts (
    uid       INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    NOT NULL UNIQUE,
    email_binding_list TEXT NOT NULL DEFAULT '[]',
    name      TEXT    NOT NULL DEFAULT '',
    avatar_url TEXT    NOT NULL DEFAULT '',
    is_admin  INTEGER NOT NULL DEFAULT 0,
    created_at REAL   NOT NULL
);
CREATE TABLE IF NOT EXISTS identities (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    uid          INTEGER NOT NULL REFERENCES accounts(uid),
    provider     TEXT    NOT NULL,
    provider_uid TEXT    NOT NULL,
    login        TEXT    NOT NULL DEFAULT '',
    email        TEXT    NOT NULL DEFAULT '',
    linked_at    REAL    NOT NULL,
    UNIQUE (provider, provider_uid)
);
CREATE TABLE IF NOT EXISTS allowed_logins (
    login TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES accounts(uid),
    expires_at REAL    NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES accounts(uid),
    name         TEXT    NOT NULL DEFAULT '',
    key_hash     TEXT    NOT NULL UNIQUE,
    prefix       TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    last_used_at REAL,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS documents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES accounts(uid),
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
    _migrate(conn)
    return conn


# Child tables referencing accounts, used by the pre-0.3 migration to
# rebuild rows whose FOREIGN KEY clauses pointed at the old users table.
_CHILD_DDL = {
    "sessions": """\
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES accounts(uid),
    expires_at REAL    NOT NULL
)""",
    "api_keys": """\
CREATE TABLE api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES accounts(uid),
    name         TEXT    NOT NULL DEFAULT '',
    key_hash     TEXT    NOT NULL UNIQUE,
    prefix       TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    last_used_at REAL,
    revoked      INTEGER NOT NULL DEFAULT 0
)""",
    "documents": """\
CREATE TABLE documents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES accounts(uid),
    app        TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    ciphertext BLOB    NOT NULL,
    version    INTEGER NOT NULL,
    updated_at REAL    NOT NULL,
    UNIQUE (user_id, app, name)
)""",
}


def _migrate(conn: sqlite3.Connection) -> None:
    """Schema migrations for databases created before the account model.

    Pre-0.3 databases keyed everything to a ``users`` table (one row per
    provider login, github_id/gitea_id columns). Each row becomes an account
    **keeping its numeric id as uid** — document ciphertexts bind the user id
    as AAD, so renumbering would make them undecryptable — and its provider
    ids become ``identities`` rows.
    """
    tables = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "users" in tables:
        conn.commit()  # PRAGMA foreign_keys is a no-op inside a transaction
        conn.execute("PRAGMA foreign_keys=OFF")
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        if "gitea_id" not in cols:  # 0.1.x database
            conn.execute("ALTER TABLE users ADD COLUMN gitea_id INTEGER")
        for u in conn.execute("SELECT * FROM users").fetchall():
            conn.execute(
                "INSERT INTO accounts (uid, username, name, avatar_url,"
                " is_admin, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (u["id"], u["login"], u["name"], u["avatar_url"],
                 u["is_admin"], u["created_at"]),
            )
            if u["github_id"] > 0:
                conn.execute(
                    "INSERT OR IGNORE INTO identities (uid, provider, provider_uid,"
                    " login, linked_at) VALUES (?, 'github', ?, ?, ?)",
                    (u["id"], str(u["github_id"]), u["login"], u["created_at"]),
                )
            if u["gitea_id"] is not None:
                conn.execute(
                    "INSERT OR IGNORE INTO identities (uid, provider, provider_uid,"
                    " login, linked_at) VALUES (?, 'gitea', ?, ?, ?)",
                    (u["id"], str(u["gitea_id"]), u["login"], u["created_at"]),
                )
        # Child tables still carry FOREIGN KEY clauses pointing at ``users``;
        # rebuild them against accounts (identical columns) before dropping it.
        for name, ddl in _CHILD_DDL.items():
            conn.execute(f"ALTER TABLE {name} RENAME TO {name}_old")
            conn.execute(ddl)
            conn.execute(f"INSERT INTO {name} SELECT * FROM {name}_old")
            conn.execute(f"DROP TABLE {name}_old")
        conn.execute("DROP TABLE users")
        conn.commit()
        conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_provider_uid"
        " ON identities (provider, provider_uid)"
    )
    conn.commit()


# ── accounts / identities / allowlist ─────────────────────────────

def _emails(row: sqlite3.Row) -> list[str]:
    return json.loads(row["email_binding_list"])


def get_account_by_uid(conn: sqlite3.Connection, uid: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM accounts WHERE uid = ?", (uid,)).fetchone()


def get_account_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM accounts WHERE username = ?", (username,)).fetchone()


def get_account_by_email(conn: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    """Account whose email_binding_list contains this (case-insensitive) email."""
    email = email.strip().lower()
    for row in conn.execute("SELECT uid, email_binding_list FROM accounts").fetchall():
        if email in (e.strip().lower() for e in _emails(row)):
            return get_account_by_uid(conn, row["uid"])
    return None


def count_accounts(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()["n"]


def list_accounts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT a.*, GROUP_CONCAT("
        "  i.provider || ':' || i.login, ' · ') AS identities"
        " FROM accounts a LEFT JOIN identities i ON i.uid = a.uid"
        " GROUP BY a.uid ORDER BY a.uid"
    ).fetchall()
    return [{**dict(r), "emails": _emails(r)} for r in rows]


def _unique_username(conn: sqlite3.Connection, username: str) -> str:
    """``username`` itself, or ``username-2``, ``username-3``, … if taken."""
    candidate, n = username, 1
    while get_account_by_username(conn, candidate) is not None:
        n += 1
        candidate = f"{username}-{n}"
    return candidate


def create_account(conn: sqlite3.Connection, username: str, name: str = "",
                   avatar_url: str = "") -> sqlite3.Row:
    """Create an account; the very first account becomes admin. Emails are
    bound separately via bind_email (which enforces uniqueness)."""
    username = _unique_username(conn, username)
    is_admin = 1 if count_accounts(conn) == 0 else 0
    cur = conn.execute(
        "INSERT INTO accounts (username, email_binding_list, name, avatar_url,"
        " is_admin, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (username, json.dumps([]), name, avatar_url, is_admin, time.time()),
    )
    if is_admin:
        conn.execute(
            "INSERT OR IGNORE INTO allowed_logins (login) VALUES (?)", (username,))
    conn.commit()
    return get_account_by_uid(conn, cur.lastrowid)


def set_account_admin(conn: sqlite3.Connection, uid: int, flag: bool) -> None:
    conn.execute("UPDATE accounts SET is_admin = ? WHERE uid = ?", (1 if flag else 0, uid))
    conn.commit()


def update_account_profile(conn: sqlite3.Connection, uid: int, name: str,
                           avatar_url: str) -> None:
    if name or avatar_url:
        conn.execute(
            "UPDATE accounts SET name = CASE WHEN ? != '' THEN ? ELSE name END,"
            " avatar_url = CASE WHEN ? != '' THEN ? ELSE avatar_url END WHERE uid = ?",
            (name, name, avatar_url, avatar_url, uid),
        )
        conn.commit()


def bind_email(conn: sqlite3.Connection, uid: int, email: str) -> bool:
    """Add an email binding (stored lowercase, deduplicated). False if it was
    already bound to this account."""
    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValueError(f"'{email}' is not a valid email address")
    row = get_account_by_uid(conn, uid)
    if row is None:
        raise LookupError(f"no account uid={uid}")
    emails = _emails(row)
    if email in emails:
        return False
    if get_account_by_email(conn, email) is not None:
        raise ValueError(f"'{email}' is already bound to another account")
    emails.append(email)
    conn.execute(
        "UPDATE accounts SET email_binding_list = ? WHERE uid = ?",
        (json.dumps(emails), uid),
    )
    conn.commit()
    return True


def unbind_email(conn: sqlite3.Connection, uid: int, email: str) -> bool:
    row = get_account_by_uid(conn, uid)
    if row is None:
        raise LookupError(f"no account uid={uid}")
    emails = [e for e in _emails(row) if e.strip().lower() != email.strip().lower()]
    if len(emails) == len(_emails(row)):
        return False
    conn.execute(
        "UPDATE accounts SET email_binding_list = ? WHERE uid = ?",
        (json.dumps(emails), uid),
    )
    conn.commit()
    return True


# ── identities ────────────────────────────────────────────────────

def get_identity(conn: sqlite3.Connection, provider: str,
                 provider_uid: int | str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM identities WHERE provider = ? AND provider_uid = ?",
        (provider, str(provider_uid)),
    ).fetchone()


def link_identity(conn: sqlite3.Connection, uid: int, provider: str,
                  provider_uid: int | str, login: str = "", email: str = "") -> None:
    conn.execute(
        "INSERT OR IGNORE INTO identities (uid, provider, provider_uid, login,"
        " email, linked_at) VALUES (?, ?, ?, ?, ?, ?)",
        (uid, provider, str(provider_uid), login, email, time.time()),
    )
    conn.commit()


def touch_identity(conn: sqlite3.Connection, identity_id: int, login: str,
                   email: str) -> None:
    """Refresh the informational login/email captured at link time."""
    conn.execute(
        "UPDATE identities SET login = ?, email = ? WHERE id = ?",
        (login, email, identity_id),
    )
    conn.commit()


def list_identities(conn: sqlite3.Connection, uid: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM identities WHERE uid = ? ORDER BY id", (uid,)
    ).fetchall()


def seed_allowed_logins(conn: sqlite3.Connection, logins: list[str]) -> None:
    """Seed the allowlist from config (idempotent; never removes entries)."""
    for login in logins:
        conn.execute("INSERT OR IGNORE INTO allowed_logins (login) VALUES (?)", (login,))
    conn.commit()


def is_login_allowed(conn: sqlite3.Connection, username: str) -> bool:
    """Allowed when no accounts exist yet (bootstrap: first login becomes
    admin) or when the username is on the allowlist. The allowlist gates
    *creation* of new accounts; existing accounts always pass."""
    if count_accounts(conn) == 0:
        return True
    row = conn.execute(
        "SELECT login FROM allowed_logins WHERE login = ?", (username,)
    ).fetchone()
    return row is not None


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
    return get_account_by_uid(conn, row["user_id"])


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
    return get_account_by_uid(conn, row["user_id"])


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
