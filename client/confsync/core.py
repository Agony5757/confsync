"""ConfsyncClient — thin synchronous wrapper over the confsync REST API."""
from __future__ import annotations

from urllib.parse import quote, urlparse

import httpx

API_BASE = "/api/v1"


class ConfsyncError(Exception):
    """Raised on any confsync server error (auth, not-found, network...)."""


def validate_server_url(server_url: str) -> str:
    """Require https (plaintext http allowed only for localhost). Returns the
    normalized URL (no trailing slash)."""
    url = server_url.rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ConfsyncError(f"invalid server URL: {server_url!r}")
    host = parsed.hostname or ""
    if parsed.scheme == "http" and host not in ("localhost", "127.0.0.1", "::1"):
        raise ConfsyncError(
            f"refusing plaintext http for non-localhost server: {url}. "
            "Use https (put the server behind a TLS reverse proxy)."
        )
    return url


class ConfsyncClient:
    def __init__(self, server_url: str, api_key: str, timeout: float = 30.0,
                 transport: httpx.BaseTransport | None = None):
        self.server_url = validate_server_url(server_url)
        # trust_env=False: never route through env-configured proxies —
        # deterministic TLS to the configured server, no credential leakage
        # through $ALL_PROXY/$HTTPS_PROXY.
        self._client = httpx.Client(
            base_url=self.server_url + API_BASE,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
            transport=transport,
            trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ConfsyncClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── low level ─────────────────────────────────────────────────

    def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            resp = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise ConfsyncError(f"cannot reach {self.server_url}: {exc}") from exc
        try:
            data = resp.json()
        except ValueError:
            raise ConfsyncError(
                f"unexpected response from server (HTTP {resp.status_code}): "
                f"{resp.text[:200]}"
            )
        if resp.status_code >= 400:
            raise ConfsyncError(data.get("error") or f"HTTP {resp.status_code}")
        return data

    @staticmethod
    def _doc_path(app: str, name: str) -> str:
        return f"/documents/{quote(app, safe='')}/{quote(name, safe='')}"

    # ── public API ────────────────────────────────────────────────

    def whoami(self) -> dict:
        """Verify the API key; returns {"login": ..., "name": ...}."""
        return self._request("GET", "/whoami")

    def list(self) -> list[dict]:
        """List my documents: [{app, name, version, updated_at, size}]."""
        return self._request("GET", "/documents")["documents"]

    def pull(self, app: str, name: str, version: int | None = None) -> str:
        """Fetch a document's plaintext content (latest or a history version)."""
        path = self._doc_path(app, name)
        if version is not None:
            path += f"/history/{version}"
        return self._request("GET", path)["content"]

    def pull_meta(self, app: str, name: str) -> dict:
        """Full document record: {app, name, version, updated_at, content}."""
        return self._request("GET", self._doc_path(app, name))

    def push(self, app: str, name: str, content: str) -> int:
        """Store content as a new version; returns the new version number."""
        data = self._request("PUT", self._doc_path(app, name), json={"content": content})
        return int(data["version"])

    def delete(self, app: str, name: str) -> None:
        self._request("DELETE", self._doc_path(app, name))

    def history(self, app: str, name: str) -> list[dict]:
        """[{version, saved_at, size}], newest first."""
        return self._request("GET", self._doc_path(app, name) + "/history")["history"]
