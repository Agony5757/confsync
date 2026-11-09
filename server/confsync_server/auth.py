"""GitHub/Gitea OAuth flows and token/API-key generation helpers."""
from __future__ import annotations

import secrets
import string
from urllib.parse import urlencode

import httpx

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"
GITHUB_SCOPE = "read:user user:email"

GITEA_AUTHORIZE_PATH = "/login/oauth/authorize"
GITEA_TOKEN_PATH = "/login/oauth/access_token"
GITEA_USER_PATH = "/api/v1/user"
GITEA_SCOPE = "read:user"

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
        f"&redirect_uri={redirect_uri}&state={state}&scope={GITHUB_SCOPE.replace(' ', '%20')}"
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
    """Return the GitHub profile: {id, login, name, avatar_url, email}.

    ``email`` may be '' when it is private and the user:email scope was not
    granted — callers treat email as optional for account linking."""
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(
            GITHUB_USER_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        emails_resp = await client.get(
            GITHUB_EMAILS_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if resp.status_code != 200:
        raise ValueError(f"GitHub user fetch failed: HTTP {resp.status_code}")
    data = resp.json()
    email = str(data.get("email") or "")
    if not email and emails_resp.status_code == 200:
        for e in emails_resp.json():
            if e.get("primary") and e.get("verified"):
                email = str(e.get("email") or "")
                break
    return {
        "id": int(data["id"]),
        "login": str(data["login"]),
        "name": str(data.get("name") or ""),
        "avatar_url": str(data.get("avatar_url") or ""),
        "email": email,
    }


def build_gitea_authorize_url(gitea_url: str, client_id: str, redirect_uri: str,
                              state: str) -> str:
    query = urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
        "scope": GITEA_SCOPE,
    })
    return f"{gitea_url}{GITEA_AUTHORIZE_PATH}?{query}"


async def exchange_gitea_code(gitea_url: str, client_id: str, client_secret: str,
                              code: str, redirect_uri: str) -> str:
    """Exchange an OAuth code for a Gitea access token."""
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            f"{gitea_url}{GITEA_TOKEN_PATH}",
            json={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
        )
    data = resp.json()
    token = data.get("access_token")
    if resp.status_code != 200 or not token:
        raise ValueError(
            f"Gitea token exchange failed: {data.get('error_description') or data.get('error') or data}"
        )
    return token


async def fetch_gitea_user(gitea_url: str, access_token: str) -> dict:
    """Return the Gitea profile: {id, login, name, avatar_url}.

    Also used to verify plain Gitea access tokens (personal tokens) for API
    auth: a non-200 response means the token is invalid or revoked."""
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(
            f"{gitea_url}{GITEA_USER_PATH}",
            headers={"Authorization": f"token {access_token}"},
        )
    if resp.status_code == 401:
        raise ValueError("Gitea rejected the access token (invalid or revoked).")
    if resp.status_code != 200:
        raise ValueError(f"Gitea user fetch failed: HTTP {resp.status_code}")
    data = resp.json()
    avatar = str(data.get("avatar_url") or "")
    if avatar and not avatar.startswith(("http://", "https://")):
        avatar = f"{gitea_url}/{avatar.lstrip('/')}"
    return {
        "id": int(data["id"]),
        "login": str(data["login"]),
        "name": str(data.get("full_name") or ""),
        "avatar_url": avatar,
        "email": str(data.get("email") or "").strip().lower(),
    }
