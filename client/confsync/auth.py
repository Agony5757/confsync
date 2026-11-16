"""Browser-assisted CLI login: temporary loopback receiver + code exchange."""
from __future__ import annotations

import secrets
import socket
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from confsync.core import ConfsyncError, validate_server_url
from confsync.credentials import login

_CALLBACK_PATH = "/callback"


class _CallbackHandler(BaseHTTPRequestHandler):
    server_version = "confsync-cli"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        if self.server.result or parsed.path != _CALLBACK_PATH:
            self._respond("<h1>confsync CLI</h1><p>Waiting for authorization.</p>")
            return

        params = parse_qs(parsed.query)
        code = (params.get("code") or [""])[0]
        error = (params.get("error") or [""])[0]
        state = (params.get("state") or [""])[0]
        if state != self.server.expected_state:
            error = "callback state mismatch"
            code = ""
        if code and not error:
            self.server.result = {"code": code}
            body = ("<h1>Login complete</h1>"
                    "<p>You can close this tab and return to the terminal.</p>")
        else:
            self.server.result = {"error": error or "authorization failed"}
            body = (f"<h1>Login failed</h1><p>{error or 'authorization failed'}</p>")
        self.server.done.set()
        self._respond(body)

    def _respond(self, body: str) -> None:
        content = (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                   f"<title>confsync CLI</title></head><body>{body}</body></html>")
        data = content.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args) -> None:
        pass


class _CallbackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, expected_state: str):
        super().__init__(("127.0.0.1", 0), _CallbackHandler)
        self.expected_state = expected_state
        self.result: dict[str, str] | None = None
        self.done = threading.Event()


def exchange_cli_code(server_url: str, code: str, *, key_name: str = "cli login",
                      timeout: float = 30.0,
                      transport: httpx.BaseTransport | None = None) -> dict:
    """Exchange the one-time browser-authorization code for an API key."""
    try:
        with httpx.Client(base_url=server_url + "/api/v1", timeout=timeout,
                          transport=transport, trust_env=False) as client:
            resp = client.post("/auth/exchange", json={"code": code, "name": key_name})
    except httpx.HTTPError as exc:
        raise ConfsyncError(f"cannot reach {server_url}: {exc}") from exc
    try:
        data = resp.json()
    except ValueError:
        raise ConfsyncError(
            f"unexpected response from server (HTTP {resp.status_code}): "
            f"{resp.text[:200]}"
        ) from None
    if resp.status_code >= 400:
        raise ConfsyncError(data.get("error") or f"HTTP {resp.status_code}")
    if not isinstance(data.get("api_key"), str) or not data["api_key"]:
        raise ConfsyncError("server returned no API key")
    return data


def browser_login(server_url: str, *, open_browser: bool = True,
                  timeout: float = 600.0, key_name: str | None = None) -> dict:
    """Authorize the CLI in a browser and save the resulting API key.

    Opens ``/auth/cli/login`` on the server with a loopback redirect. The user
    confirms access with GitHub/Gitea; the browser receives only a one-time
    code, which this process exchanges for a normal confsync API key.
    """
    server_url = validate_server_url(server_url)
    state = secrets.token_urlsafe(24)
    callback_server = _CallbackServer(state)
    callback_thread = threading.Thread(
        target=callback_server.serve_forever, name="confsync-auth-callback", daemon=True
    )
    callback_thread.start()
    callback_url = (f"http://127.0.0.1:{callback_server.server_address[1]}"
                    f"{_CALLBACK_PATH}")
    authorize_url = server_url + "/auth/cli/login?" + urlencode({
        "redirect_uri": callback_url,
        "state": state,
    })
    name = (key_name or f"cli @ {socket.gethostname()}").strip()[:100] or "cli login"

    print(f"Authorize confsync in your browser:\n  {authorize_url}")
    if open_browser:
        webbrowser.open(authorize_url)
    print("Waiting for authorization (Ctrl+C to cancel)...")

    try:
        if not callback_server.done.wait(timeout):
            raise ConfsyncError(
                f"timed out after {timeout:.0f}s waiting for browser authorization"
            )
    except KeyboardInterrupt:
        raise ConfsyncError("login canceled") from None
    finally:
        callback_server.shutdown()
        callback_server.server_close()
        callback_thread.join(timeout=2)

    result = callback_server.result or {}
    if result.get("error"):
        raise ConfsyncError(result["error"])
    code = result.get("code", "")
    if not code:
        raise ConfsyncError("browser callback returned no authorization code")

    exchanged = exchange_cli_code(server_url, code, key_name=name)
    with login(server_url, exchanged["api_key"]) as client:
        who = client.whoami()
    return {**who, "api_key": exchanged["api_key"]}
