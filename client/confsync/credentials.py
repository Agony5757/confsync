"""Shared client credentials: ~/.confsync/credentials.json (mode 0600).

All apps that embed confsync (flexgate, your other repos, the CLI) read the
same credentials file, so ``confsync login`` once works everywhere. Override
the path with CONFSYNC_CREDENTIALS (used by tests).
"""
from __future__ import annotations

import json
import os

from confsync.core import ConfsyncClient, ConfsyncError, validate_server_url

CREDENTIALS_ENV = "CONFSYNC_CREDENTIALS"


def get_credentials_path() -> str:
    env = os.environ.get(CREDENTIALS_ENV, "").strip()
    if env:
        return env
    return os.path.join(os.path.expanduser("~/.confsync"), "credentials.json")


def login(server_url: str, api_key: str, *, verify: bool = True) -> ConfsyncClient:
    """Validate and persist credentials; returns a ready client.

    With verify=True (default) the key is checked against the server first.
    """
    server_url = validate_server_url(server_url)
    if not api_key.startswith("cs_"):
        raise ConfsyncError("API keys start with 'cs_'; create one in the web UI (/keys).")
    client = ConfsyncClient(server_url, api_key)
    if verify:
        client.whoami()  # raises ConfsyncError on a bad key

    path = get_credentials_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps({"server_url": server_url, "api_key": api_key},
                                indent=2).encode() + b"\n")
    finally:
        os.close(fd)
    return client


def load_client() -> ConfsyncClient:
    """Build a client from the shared credentials file."""
    path = get_credentials_path()
    if not os.path.exists(path):
        raise ConfsyncError(
            f"no credentials at {path}. Run: confsync login --server <url>"
        )
    with open(path) as f:
        data = json.load(f)
    try:
        return ConfsyncClient(data["server_url"], data["api_key"])
    except KeyError as exc:
        raise ConfsyncError(f"credentials file {path} is missing {exc}") from exc
