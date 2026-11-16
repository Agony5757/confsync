"""GitHub/Gitea OAuth flows and token/API-key generation helpers."""
from __future__ import annotations

import base64
import hashlib
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
    """New API key: ``cs_`` + 48 random base62 chars."""
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


def _json_object(resp: httpx.Response, provider: str) -> dict:
    try:
        data = resp.json()
    except ValueError:
        raise ValueError(
            f"{provider} returned invalid JSON (HTTP {resp.status_code})."
        ) from None
    if not isinstance(data, dict):
        raise ValueError(f"{provider} returned an unexpected JSON response.")
    return data


async def exchange_code(client_id: str, client_secret: str, code: str,
                        redirect_uri: str) -> str:
    """Exchange an OAuth code for a GitHub access token."""
    try:
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
    except httpx.HTTPError as exc:
        raise ValueError(f"GitHub token exchange failed: {exc}") from exc
    data = _json_object(resp, "GitHub")
    token = data.get("access_token")
    if resp.status_code != 200 or not token:
        detail = (data.get("error_description") or data.get("error")
                  or f"HTTP {resp.status_code}")
        raise ValueError(f"GitHub token exchange failed: {detail}")
    return token


async def fetch_github_user(access_token: str) -> dict:
    """Return the GitHub profile: {id, login, name, avatar_url, email}.

    ``email`` may be '' when it is private and the user:email scope was not
    granted — callers treat email as optional for account linking."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(GITHUB_USER_URL, headers=headers)
            if resp.status_code != 200:
                raise ValueError(f"GitHub user fetch failed: HTTP {resp.status_code}")
            data = _json_object(resp, "GitHub")
            email = str(data.get("email") or "").strip().lower()
            if not email:
                emails_resp = await client.get(GITHUB_EMAILS_URL, headers=headers)
                if emails_resp.status_code == 200:
                    try:
                        emails = emails_resp.json()
                    except ValueError:
                        raise ValueError("GitHub email fetch returned invalid JSON.") from None
                    if not isinstance(emails, list):
                        raise ValueError("GitHub email fetch returned an unexpected response.")
                    for item in emails:
                        if (isinstance(item, dict) and item.get("primary")
                                and item.get("verified")):
                            email = str(item.get("email") or "").strip().lower()
                            break
    except httpx.HTTPError as exc:
        raise ValueError(f"GitHub user fetch failed: {exc}") from exc
    try:
        github_id = int(data["id"])
        login = str(data["login"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("GitHub user response is missing the account id or login.") from None
    return {
        "id": github_id,
        "login": login,
        "name": str(data.get("name") or ""),
        "avatar_url": str(data.get("avatar_url") or ""),
        "email": email,
    }


def generate_pkce_verifier() -> str:
    return secrets.token_urlsafe(48)


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def build_gitea_authorize_url(gitea_url: str, client_id: str, redirect_uri: str,
                              state: str, code_challenge: str = "") -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
        "scope": GITEA_SCOPE,
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    return f"{gitea_url}{GITEA_AUTHORIZE_PATH}?{urlencode(params)}"


async def exchange_gitea_code(gitea_url: str, client_id: str, client_secret: str,
                              code: str, redirect_uri: str,
                              code_verifier: str = "") -> str:
    """Exchange an OAuth code for a Gitea access token."""
    form = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    if code_verifier:
        form["code_verifier"] = code_verifier
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                f"{gitea_url}{GITEA_TOKEN_PATH}",
                data=form,
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise ValueError(f"Gitea token exchange failed: {exc}") from exc
    data = _json_object(resp, "Gitea")
    token = data.get("access_token")
    if resp.status_code != 200 or not token:
        detail = (data.get("error_description") or data.get("error")
                  or f"HTTP {resp.status_code}")
        raise ValueError(f"Gitea token exchange failed: {detail}")
    return token


async def fetch_gitea_user(gitea_url: str, access_token: str) -> dict:
    """Return the Gitea profile: {id, login, name, avatar_url, email}.

    Also used to verify plain Gitea access tokens (personal tokens) for API
    auth: a non-200 response means the token is invalid or revoked."""
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                f"{gitea_url}{GITEA_USER_PATH}",
                headers={"Authorization": f"token {access_token}"},
            )
    except httpx.HTTPError as exc:
        raise ValueError(f"Gitea user fetch failed: {exc}") from exc
    if resp.status_code == 401:
        raise ValueError("Gitea rejected the access token (invalid or revoked).")
    if resp.status_code != 200:
        raise ValueError(f"Gitea user fetch failed: HTTP {resp.status_code}")
    data = _json_object(resp, "Gitea")
    try:
        gitea_id = int(data["id"])
        login = str(data["login"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("Gitea user response is missing the account id or login.") from None
    avatar = str(data.get("avatar_url") or "")
    if avatar and not avatar.startswith(("http://", "https://")):
        avatar = f"{gitea_url}/{avatar.lstrip('/')}"
    return {
        "id": gitea_id,
        "login": login,
        "name": str(data.get("full_name") or ""),
        "avatar_url": avatar,
        "email": str(data.get("email") or "").strip().lower(),
    }
