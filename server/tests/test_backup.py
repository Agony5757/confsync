"""confsync-server backup command: hot sqlite snapshot + master key copy."""
import os
import sqlite3

import pytest

from confsync_server import db
from confsync_server.cli import cmd_backup
from confsync_server.config import load_settings


def test_backup_captures_db_and_key(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    monkeypatch.setenv("CONFSYNC_HOME", str(home))
    settings = load_settings()

    conn = db.connect(settings.db_path)
    db.upsert_user(conn, 1001, "alice", "Alice", "")
    conn.close()
    (home / "master.key").write_bytes(b"k" * 32)

    out = tmp_path / "backup"
    cmd_backup(type("Args", (), {"out": str(out)})())

    # db snapshot is a consistent, usable copy
    snap = sqlite3.connect(str(out / "server.db"))
    snap.row_factory = sqlite3.Row
    row = snap.execute("SELECT login FROM users").fetchone()
    snap.close()
    assert row["login"] == "alice"

    # master key copied with restrictive permissions
    assert (out / "master.key").read_bytes() == b"k" * 32
    mode = os.stat(out / "master.key").st_mode & 0o777
    assert mode == 0o600

    assert "backup written to" in capsys.readouterr().out


def test_backup_notes_env_master_key(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("CONFSYNC_HOME", str(home))
    monkeypatch.setenv("CONFSYNC_MASTER_KEY",
                       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB")

    db.connect(load_settings().db_path).close()
    cmd_backup(type("Args", (), {"out": str(tmp_path / "bk")})())

    out = capsys.readouterr().out
    assert "back it up separately" in out
    assert not (tmp_path / "bk" / "master.key").exists()


def test_backup_default_path_is_timestamped(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CONFSYNC_HOME", str(tmp_path / "home"))
    settings = load_settings()
    db.connect(settings.db_path).close()

    cmd_backup(type("Args", (), {"out": None})())

    backups = list((tmp_path / "home" / "backups").iterdir())
    assert len(backups) == 1
    assert backups[0].name.startswith("confsync-")
    assert (backups[0] / "server.db").exists()


def test_backup_missing_db_exits(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CONFSYNC_HOME", str(tmp_path / "empty"))
    with pytest.raises(SystemExit):
        cmd_backup(type("Args", (), {"out": None})())
    assert "no database" in capsys.readouterr().err
