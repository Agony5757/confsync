"""GitHub OAuth flow and token/API-key generation helpers."""
from __future__ import annotations

import secrets
import string

import httpx

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

_KEY_ALPHABET = string.ascii_letters + string.digits
KEY_PREFIX = "cs_"


def generate_api_key() -> str:
    """New API key: ``cs_`` + 48 random base62 chars. Plaintext is shown to
    the user once; only its sha256 is stored server-side."""
    return KEY_PREFIX + "".join(secrets.choice(_KEY_ALPHABET) for _ in range(48))


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def generate_oauth_state() -> str:
    return secrets.token_urlsafe(24)


def build_authorize_url(client_id: str, redirect_uri: str, state: str) -> str:
    return (
        f"{GITHUB_AUTHORIZE_URL}?client_id={client_id}"
        f"&redirect_uri={redirect_uri}&state={state}&scope=read:user"
    )


async def exchange_code(client_id: str, client_secret: str, code: str,
                        redirect_uri: str) -> str:
    """Exchange an OAuth code for a GitHub access token."""
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
        )
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise ValueError(f"GitHub token exchange failed: {data.get('error_description') or data}")
    return token


async def fetch_github_user(access_token: str) -> dict:
    """Return the GitHub profile: {id, login, name, avatar_url}."""
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(
            GITHUB_USER_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )
    if resp.status_code != 200:
        raise ValueError(f"GitHub user fetch failed: HTTP {resp.status_code}")
    data = resp.json()
    return {
        "id": int(data["id"]),
        "login": str(data["login"]),
        "name": str(data.get("name") or ""),
        "avatar_url": str(data.get("avatar_url") or ""),
    }
