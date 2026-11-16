"""Browser-assisted login: loopback receiver, code exchange, CLI command."""
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from confsync import cli
from confsync.auth import browser_login, exchange_cli_code
from confsync.core import ConfsyncError


def test_exchange_cli_code_posts_one_time_code():
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "api_key": "cs_" + "k" * 48, "username": "alice", "name": "Alice",
        })

    data = exchange_cli_code("https://conf.example.com", "one-time-code",
                             key_name="cli @ test", transport=httpx.MockTransport(handler))
    assert seen["path"] == "/api/v1/auth/exchange"
    assert seen["body"] == {"code": "one-time-code", "name": "cli @ test"}
    assert data["api_key"].startswith("cs_")


def test_exchange_cli_code_reports_server_error():
    def handler(request):
        return httpx.Response(401, json={"error": "invalid or expired code"})

    with pytest.raises(ConfsyncError, match="invalid or expired code"):
        exchange_cli_code("https://conf.example.com", "bad",
                          transport=httpx.MockTransport(handler))


class _FakeClient:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def whoami(self):
        return {"username": "alice", "login": "alice", "name": "Alice"}


def test_browser_login_receives_loopback_callback(monkeypatch):
    captured = {}

    def fake_open(url):
        query = parse_qs(urlparse(url).query)
        captured["authorize_url"] = url
        redirect = query["redirect_uri"][0]
        resp = httpx.get(redirect, params={
            "code": "one-time-code", "state": query["state"][0],
        })
        assert resp.status_code == 200
        assert "Login complete" in resp.text
        return True

    def fake_exchange(server_url, code, *, key_name, timeout=30.0, transport=None):
        captured["exchange"] = (server_url, code, key_name)
        return {"api_key": "cs_good", "username": "alice"}

    def fake_login(server_url, api_key):
        captured["saved"] = (server_url, api_key)
        return _FakeClient()

    monkeypatch.setattr("confsync.auth.webbrowser.open", fake_open)
    monkeypatch.setattr("confsync.auth.exchange_cli_code", fake_exchange)
    monkeypatch.setattr("confsync.auth.login", fake_login)

    who = browser_login("https://conf.example.com/", key_name="cli @ laptop")

    assert captured["authorize_url"].startswith("https://conf.example.com/auth/cli/login?")
    assert captured["exchange"][0] == "https://conf.example.com"
    assert captured["exchange"][1] == "one-time-code"
    assert captured["exchange"][2] == "cli @ laptop"
    assert captured["saved"] == ("https://conf.example.com", "cs_good")
    assert who["username"] == "alice"
    assert who["api_key"] == "cs_good"


def test_browser_login_returns_provider_error(monkeypatch):
    def fake_open(url):
        query = parse_qs(urlparse(url).query)
        httpx.get(query["redirect_uri"][0], params={
            "error": "access denied", "state": query["state"][0],
        })
        return True

    def unexpected_exchange(*args, **kwargs):
        raise AssertionError("exchange must not run after an error callback")

    monkeypatch.setattr("confsync.auth.webbrowser.open", fake_open)
    monkeypatch.setattr("confsync.auth.exchange_cli_code", unexpected_exchange)
    with pytest.raises(ConfsyncError, match="access denied"):
        browser_login("https://conf.example.com")


def test_auth_login_command_prints_result(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("CONFSYNC_CREDENTIALS", str(tmp_path / "credentials.json"))
    monkeypatch.setattr(cli, "browser_login", lambda *args, **kwargs: {
        "username": "alice", "login": "alice", "api_key": "cs_good",
    })
    cli.cmd_auth_login(SimpleNamespace(
        server="https://conf.example.com", no_browser=False, timeout=600,
        key_name=None,
    ))
    out = capsys.readouterr().out
    assert "Logged in as alice @ https://conf.example.com" in out
    assert str(tmp_path / "credentials.json") in out
