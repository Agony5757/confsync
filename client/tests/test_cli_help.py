"""CLI `confsync help [topic]` — offline help docs."""
import sys

import pytest

from confsync import cli
from confsync.cli import HELP_OVERVIEW, HELP_TOPICS


def _run(argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["confsync"] + argv)
    cli.main()


def test_help_overview(monkeypatch, capsys):
    _run(["help"], monkeypatch)
    out = capsys.readouterr().out
    assert "Quick start" in out
    assert "confsync login" in out
    for topic in HELP_TOPICS:
        assert topic in out


def test_help_every_topic(monkeypatch, capsys):
    for topic, text in HELP_TOPICS.items():
        _run(["help", topic], monkeypatch)
        out = capsys.readouterr().out
        assert text.splitlines()[0] in out


def test_help_auth_mentions_both_credential_kinds():
    assert "cs_" in HELP_TOPICS["auth"]
    assert "Gitea access token" in HELP_TOPICS["auth"]


def test_help_upgrade_mentions_compatibility():
    assert "0.2.0" in HELP_TOPICS["upgrade"]
    assert "/api/v1/version" in HELP_TOPICS["upgrade"]


def test_help_unknown_topic_fails_with_list(monkeypatch, capsys):
    with pytest.raises(SystemExit) as exc:
        _run(["help", "nope"], monkeypatch)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "unknown help topic" in err
    assert ", ".join(HELP_TOPICS) in err


def test_overview_lists_commands():
    for cmd in ("login", "push", "pull", "list", "history", "delete"):
        assert cmd in HELP_OVERVIEW
