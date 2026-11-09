"""Starlette application: REST API (/api/v1) + server-rendered Web UI."""
from __future__ import annotations

import html
import sqlite3
import time
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from confsync_server import __version__, auth, crypto, db
from confsync_server.config import ServerSettings, load_settings

SESSION_COOKIE = "confsync_session"
MAX_CONTENT_BYTES = 4 * 1024 * 1024
GITEA_TOKEN_CACHE_TTL = 5 * 60  # re-verify Gitea API tokens at most this often

# ── rendering ─────────────────────────────────────────────────────

_CSS = """
body { font-family: -apple-system, "Segoe UI", sans-serif; max-width: 960px;
       margin: 2rem auto; padding: 0 1rem; color: #24292f; }
nav { display: flex; gap: 1rem; align-items: baseline; border-bottom: 1px solid #ddd;
      padding-bottom: .5rem; margin-bottom: 1.5rem; }
nav .brand { font-weight: 700; }
nav .spacer { flex: 1; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #eee; }
th { background: #f6f8fa; }
textarea { width: 100%; box-sizing: border-box; font-family: ui-monospace, monospace;
           font-size: 13px; }
input[type=text] { padding: .3rem .5rem; }
button, .btn { padding: .3rem .8rem; border: 1px solid #ccc; border-radius: 6px;
               background: #f6f8fa; cursor: pointer; text-decoration: none; color: inherit; }
button.primary { background: #1f883d; color: #fff; border-color: #1f883d; }
button.danger { color: #cf222e; }
code.key { background: #fff8c5; padding: .4rem .6rem; border-radius: 6px;
           display: inline-block; margin: .5rem 0; }
.flash { background: #dafbe1; border: 1px solid #1f883d; padding: .5rem .8rem;
         border-radius: 6px; margin-bottom: 1rem; }
.error { background: #ffebe9; border: 1px solid #cf222e; padding: .5rem .8rem;
         border-radius: 6px; margin-bottom: 1rem; }
.muted { color: #656d76; font-size: .9em; }
form.inline { display: inline; }
p .btn { margin-right: .5rem; }
"""


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _page(title: str, body: str, user=None, flash: str = "", error: str = "") -> Response:
    if user is not None:
        admin_link = '<a href="/admin">Admin</a>' if user["is_admin"] else ""
        nav = f"""
        <nav>
          <span class="brand">confsync</span>
          <a href="/">Documents</a>
          <a href="/keys">API Keys</a>
          {admin_link}
          <span class="spacer"></span>
          <span class="muted">{_e(user['username'])}</span>
          <a href="/logout">Logout</a>
        </nav>"""
    else:
        nav = '<nav><span class="brand">confsync</span></nav>'
    flash_html = f'<div class="flash">{_e(flash)}</div>' if flash else ""
    error_html = f'<div class="error">{_e(error)}</div>' if error else ""
    page = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)} · confsync</title>
<style>{_CSS}</style>
</head><body>
{nav}
{flash_html}{error_html}
{body}
</body></html>"""
    return Response(page, media_type="text/html")


def _redirect(url: str, flash: str = "", error: str = "") -> RedirectResponse:
    params = []
    if flash:
        params.append(f"flash={flash}")
    if error:
        params.append(f"error={error}")
    if params:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{'&'.join(params)}"
    return RedirectResponse(url, status_code=303)


# ── context helpers ───────────────────────────────────────────────

def _settings(request: Request) -> ServerSettings:
    return request.app.state.settings


def _master_key(request: Request) -> bytes:
    return request.app.state.master_key


def _open_db(request: Request):
    return db.connect(_settings(request).db_path)


def _session_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    conn = _open_db(request)
    try:
        return db.get_session_user(conn, token)
    finally:
        conn.close()


def _require_web_user(request: Request):
    """Returns (user, response). response is a redirect when not logged in."""
    user = _session_user(request)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    return user, None


async def _require_api_user(request: Request):
    """Returns (user, response). response is a 401/403 JSON when unauthorized.

    Bearer tokens are either a confsync API key (``cs_…``) or, when Gitea is
    configured, a Gitea access token verified against the Gitea instance."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None, JSONResponse({"error": "missing bearer token"}, status_code=401)
    token = header[len("Bearer "):]
    s = _settings(request)
    if not token.startswith(auth.KEY_PREFIX):
        if not s.gitea_configured:
            return None, JSONResponse({"error": "invalid or revoked API key"}, status_code=401)
        return await _gitea_token_user(request, token)
    conn = _open_db(request)
    try:
        user = db.get_user_by_api_key(conn, token)
    finally:
        conn.close()
    if user is None:
        return None, JSONResponse({"error": "invalid or revoked API key"}, status_code=401)
    return user, None


async def _gitea_token_user(request: Request, token: str):
    """Authenticate a Gitea access token: verify it against the Gitea API,
    gate the login on the allowlist, and map it to a confsync user
    (auto-provisioned on first use). Verified tokens are cached briefly, so a
    token revoked in Gitea stays valid for at most GITEA_TOKEN_CACHE_TTL."""
    s = _settings(request)
    cache = request.app.state.gitea_token_cache
    token_hash = db.hash_token(token)
    cached = cache.get(token_hash)
    if cached is not None and cached[1] > time.time():
        user_id = cached[0]
    else:
        try:
            profile = await auth.fetch_gitea_user(s.gitea_url, token)
        except ValueError as exc:
            return None, JSONResponse({"error": str(exc)}, status_code=401)
        conn = _open_db(request)
        try:
            account = _resolve_account(conn, "gitea", profile)
            if account is None:
                return None, JSONResponse(
                    {"error": f"Gitea user '{profile['login']}' is not on the allowlist"},
                    status_code=403,
                )
        finally:
            conn.close()
        user_id = account["uid"]
        if len(cache) > 1024:
            cache.clear()
        cache[token_hash] = (user_id, time.time() + GITEA_TOKEN_CACHE_TTL)

    conn = _open_db(request)
    try:
        user = db.get_account_by_uid(conn, user_id)
    finally:
        conn.close()
    if user is None:
        return None, JSONResponse({"error": "invalid or revoked API key"}, status_code=401)
    return user, None


def _decrypt_doc(request: Request, row) -> str:
    aad = crypto.document_aad(row["user_id"], row["app"], row["name"])
    return crypto.decrypt(_master_key(request), row["ciphertext"], aad).decode()


def _store_doc(request: Request, user_id: int, app: str, name: str, content: str) -> int:
    aad = crypto.document_aad(user_id, app, name)
    blob = crypto.encrypt(_master_key(request), content.encode(), aad)
    conn = _open_db(request)
    try:
        return db.put_document(conn, user_id, app, name, blob)
    finally:
        conn.close()


def _flash_error(request: Request) -> dict:
    return {
        "flash": request.query_params.get("flash", ""),
        "error": request.query_params.get("error", ""),
    }


# ── web: auth ─────────────────────────────────────────────────────

async def login_page(request: Request) -> Response:
    if _session_user(request) is not None:
        return RedirectResponse("/", status_code=303)
    s = _settings(request)
    buttons = []
    if s.github_client_id:
        buttons.append('<a class="btn" href="/auth/github/login">Sign in with GitHub</a>')
    if s.gitea_configured:
        buttons.append('<a class="btn" href="/auth/gitea/login">Sign in with Gitea</a>')
    if not buttons:
        body = ("<p class='error'>No login provider is configured on this server "
                "(missing github.client_id or gitea.url + gitea.client_id).</p>")
        return _page("Login", body)
    body = f"""
    <h1>Sign in</h1>
    <p>{''.join(buttons)}</p>
    """
    return _page("Login", body)


async def github_login(request: Request) -> Response:
    s = _settings(request)
    if not s.github_client_id:
        return _page("Error", "", error="GitHub OAuth is not configured.")
    state = auth.generate_oauth_state()
    request.app.state.oauth_states.add(state)
    url = auth.build_authorize_url(
        s.github_client_id, f"{s.external_url}/auth/github/callback", state
    )
    return RedirectResponse(url)


async def gitea_login(request: Request) -> Response:
    s = _settings(request)
    if not s.gitea_configured:
        return _page("Error", "", error="Gitea OAuth is not configured.")
    state = auth.generate_oauth_state()
    request.app.state.oauth_states.add(state)
    url = auth.build_gitea_authorize_url(
        s.gitea_url, s.gitea_client_id, f"{s.external_url}/auth/gitea/callback", state
    )
    return RedirectResponse(url)


def _check_oauth_state(request: Request) -> str | None:
    """Returns an error message when the OAuth state is missing/unknown."""
    state = request.query_params.get("state", "")
    states = request.app.state.oauth_states
    if not state or state not in states:
        return "Invalid OAuth state; try logging in again."
    states.discard(state)
    return None


def _resolve_account(conn, provider: str, profile: dict):
    """Map a provider profile (OAuth login or verified token) to an account:
    an existing identity row → its account; else a matching bound email →
    that account (linking the new identity to it); else a brand-new account
    whose candidate username must pass the allowlist. Returns None when the
    login would create a new account that is not allowlisted."""
    identity = db.get_identity(conn, provider, profile["id"])
    if identity is not None:
        db.touch_identity(conn, identity["id"], profile["login"], profile.get("email", ""))
        db.update_account_profile(conn, identity["uid"], profile["name"],
                                  profile["avatar_url"])
        return db.get_account_by_uid(conn, identity["uid"])
    email = profile.get("email") or ""
    if email:
        account = db.get_account_by_email(conn, email)
        if account is not None:
            db.link_identity(conn, account["uid"], provider, profile["id"],
                             profile["login"], email)
            db.update_account_profile(conn, account["uid"], profile["name"],
                                      profile["avatar_url"])
            return db.get_account_by_uid(conn, account["uid"])
    if not db.is_login_allowed(conn, profile["login"]):
        return None
    # A pre-created account with exactly this username (e.g. ``confsync-server
    # bootstrap``) adopts the identity on its first login with this provider.
    account = db.get_account_by_username(conn, profile["login"])
    if account is not None:
        linked = {i["provider"] for i in db.list_identities(conn, account["uid"])}
        if provider not in linked:
            db.link_identity(conn, account["uid"], provider, profile["id"],
                             profile["login"], email)
            db.update_account_profile(conn, account["uid"], profile["name"],
                                      profile["avatar_url"])
            return db.get_account_by_uid(conn, account["uid"])
    account = db.create_account(conn, profile["login"], name=profile["name"],
                                avatar_url=profile["avatar_url"])
    db.link_identity(conn, account["uid"], provider, profile["id"],
                     profile["login"], email)
    return account


def _login_profile(request: Request, provider: str, profile: dict) -> Response:
    """Resolve the OAuth profile to an account (allowlist gates new accounts)
    and start a web session."""
    conn = _open_db(request)
    try:
        account = _resolve_account(conn, provider, profile)
        if account is None:
            return _page(
                "Access denied", "",
                error=f"{provider.title()} login '{profile['login']}' would create a "
                      f"new account, but that username is not on the allowlist.")
        session_token = auth.generate_session_token()
        db.create_session(conn, account["uid"], session_token)
    finally:
        conn.close()
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, session_token,
        max_age=db.SESSION_TTL, httponly=True, samesite="lax",
        secure=_settings(request).external_url.startswith("https://"),
    )
    return resp


async def github_callback(request: Request) -> Response:
    s = _settings(request)
    if (err := _check_oauth_state(request)) is not None:
        return _page("Error", "", error=err)
    code = request.query_params.get("code", "")
    if not code:
        return _page("Error", "", error="Missing OAuth code from GitHub.")

    try:
        token = await auth.exchange_code(
            s.github_client_id, s.github_client_secret, code,
            f"{s.external_url}/auth/github/callback",
        )
        profile = await auth.fetch_github_user(token)
    except ValueError as exc:
        return _page("Error", "", error=str(exc))

    return _login_profile(request, "github", profile)


async def gitea_callback(request: Request) -> Response:
    s = _settings(request)
    if (err := _check_oauth_state(request)) is not None:
        return _page("Error", "", error=err)
    code = request.query_params.get("code", "")
    if not code:
        return _page("Error", "", error="Missing OAuth code from Gitea.")

    try:
        token = await auth.exchange_gitea_code(
            s.gitea_url, s.gitea_client_id, s.gitea_client_secret, code,
            f"{s.external_url}/auth/gitea/callback",
        )
        profile = await auth.fetch_gitea_user(s.gitea_url, token)
    except ValueError as exc:
        return _page("Error", "", error=str(exc))

    return _login_profile(request, "gitea", profile)


async def logout(request: Request) -> Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        conn = _open_db(request)
        try:
            db.delete_session(conn, token)
        finally:
            conn.close()
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ── web: documents ────────────────────────────────────────────────

async def web_index(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    conn = _open_db(request)
    try:
        docs = db.list_documents(conn, user["uid"])
    finally:
        conn.close()
    rows = "".join(
        f"<tr><td>{_e(d['app'])}</td>"
        f"<td><a href='/docs/{_e(d['app'])}/{_e(d['name'])}'>{_e(d['name'])}</a></td>"
        f"<td>v{d['version']}</td><td>{_fmt_ts(d['updated_at'])}</td>"
        f"<td>{d['size']} B</td></tr>"
        for d in docs
    )
    table = ("<table><tr><th>App</th><th>Name</th><th>Version</th>"
             f"<th>Updated</th><th>Size</th></tr>{rows}</table>" if rows
             else "<p class='muted'>No documents yet. Push one with the confsync CLI "
                  "or your app's integration.</p>")
    body = f"<h1>Documents</h1>{table}"
    return _page("Documents", body, user, **_flash_error(request))


async def web_doc_view(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    app, name = request.path_params["app"], request.path_params["name"]
    version_q = request.query_params.get("version")
    conn = _open_db(request)
    try:
        row = db.get_document(conn, user["uid"], app, name)
        if row is None:
            return _page("Not found", "", user, error=f"No document {app}/{name}.")
        history = db.list_history(conn, user["uid"], app, name)
        if version_q:
            hrow = db.get_history_version(conn, user["uid"], app, name, int(version_q))
            if hrow is None:
                return _page("Not found", "", user, error=f"No version {version_q}.")
            content, shown_version = _decrypt_doc(request, hrow), hrow["version"]
        else:
            content, shown_version = _decrypt_doc(request, row), row["version"]
    finally:
        conn.close()

    hist_rows = "".join(
        f"<tr><td>v{h['version']}</td><td>{_fmt_ts(h['saved_at'])}</td>"
        f"<td>{h['size']} B</td>"
        f"<td><a href='/docs/{_e(app)}/{_e(name)}?version={h['version']}'>view</a></td>"
        f"<td><form class='inline' method='post' action='/docs/{_e(app)}/{_e(name)}/rollback'>"
        f"<input type='hidden' name='version' value='{h['version']}'>"
        f"<button type='submit'>rollback to this</button></form></td></tr>"
        for h in history
    )
    hist_table = (f"<h2>History</h2><table><tr><th>Version</th><th>Saved</th><th>Size</th>"
                  f"<th></th><th></th></tr>{hist_rows}</table>" if hist_rows else "")
    body = f"""
    <h1>{_e(app)} / {_e(name)} <span class="muted">(showing v{shown_version})</span></h1>
    <form method="post" action="/docs/{_e(app)}/{_e(name)}">
      <textarea name="content" rows="24">{_e(content)}</textarea>
      <p>
        <button class="primary" type="submit">Save (new version)</button>
        <a class="btn" href="/docs/{_e(app)}/{_e(name)}/raw">Download</a>
      </p>
    </form>
    <form method="post" action="/docs/{_e(app)}/{_e(name)}/delete"
          onsubmit="return confirm('Delete this document and its history?')">
      <button class="danger" type="submit">Delete document</button>
    </form>
    {hist_table}
    """
    return _page(f"{app}/{name}", body, user, **_flash_error(request))


async def web_doc_save(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    app, name = request.path_params["app"], request.path_params["name"]
    form = await request.form()
    content = str(form.get("content", ""))
    if len(content.encode()) > MAX_CONTENT_BYTES:
        return _page("Too large", "", user, error="Content exceeds 4 MB limit.")
    version = _store_doc(request, user["uid"], app, name, content)
    return _redirect(f"/docs/{app}/{name}", flash=f"Saved as v{version}.")


async def web_doc_raw(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    app, name = request.path_params["app"], request.path_params["name"]
    version_q = request.query_params.get("version")
    conn = _open_db(request)
    try:
        if version_q:
            row = db.get_history_version(conn, user["uid"], app, name, int(version_q))
        else:
            row = db.get_document(conn, user["uid"], app, name)
        if row is None:
            return PlainTextResponse("not found", status_code=404)
        content = _decrypt_doc(request, row)
    finally:
        conn.close()
    return PlainTextResponse(content, headers={
        "Content-Disposition": f'attachment; filename="{name.split("/")[-1]}"'
    })


async def web_doc_delete(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    app, name = request.path_params["app"], request.path_params["name"]
    conn = _open_db(request)
    try:
        db.delete_document(conn, user["uid"], app, name)
    finally:
        conn.close()
    return _redirect("/", flash=f"Deleted {app}/{name}.")


async def web_doc_rollback(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    app, name = request.path_params["app"], request.path_params["name"]
    form = await request.form()
    version = int(form.get("version", "0"))
    conn = _open_db(request)
    try:
        hrow = db.get_history_version(conn, user["uid"], app, name, version)
        if hrow is None:
            return _page("Not found", "", user, error=f"No history version {version}.")
        content = _decrypt_doc(request, hrow)
    finally:
        conn.close()
    new_version = _store_doc(request, user["uid"], app, name, content)
    return _redirect(f"/docs/{app}/{name}",
                     flash=f"Rolled back to v{version} content (saved as v{new_version}).")


# ── web: API keys ─────────────────────────────────────────────────

async def web_keys(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    conn = _open_db(request)
    try:
        keys = db.list_api_keys(conn, user["uid"])
    finally:
        conn.close()
    rows = ""
    for k in keys:
        if k["revoked"]:
            action = ""
            status = "revoked"
        else:
            action = (
                f"<form class='inline' method='post' action='/keys/{k['id']}/revoke'>"
                f"<button class='danger' type='submit'>Revoke</button></form>"
            )
            status = ""
        rows += (
            f"<tr><td>{_e(k['name'])}</td><td><code>{_e(k['prefix'])}…</code></td>"
            f"<td>{_fmt_ts(k['created_at'])}</td><td>{_fmt_ts(k['last_used_at'])}</td>"
            f"<td>{status}</td><td>{action}</td></tr>"
        )
    table = ("<table><tr><th>Name</th><th>Prefix</th><th>Created</th><th>Last used</th>"
             f"<th></th><th></th></tr>{rows}</table>" if rows
             else "<p class='muted'>No API keys yet.</p>")
    body = f"""
    <h1>API Keys</h1>
    {table}
    <h2>Create key</h2>
    <form method="post" action="/keys/create">
      <input type="text" name="name" placeholder="key name (e.g. laptop)" required>
      <button class="primary" type="submit">Create</button>
    </form>
    """
    return _page("API Keys", body, user, **_flash_error(request))


async def web_key_create(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    form = await request.form()
    name = str(form.get("name", "")).strip() or "default"
    plaintext = auth.generate_api_key()
    conn = _open_db(request)
    try:
        db.create_api_key(conn, user["uid"], name, plaintext)
    finally:
        conn.close()
    body = f"""
    <h1>API key created</h1>
    <p>Copy it now — it will <b>not</b> be shown again:</p>
    <code class="key">{_e(plaintext)}</code>
    <p>Use it with: <code>confsync login --server {_e(_settings(request).external_url)}</code></p>
    <p><a class="btn" href="/keys">Back to keys</a></p>
    """
    return _page("Key created", body, user)


async def web_key_revoke(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    key_id = int(request.path_params["key_id"])
    conn = _open_db(request)
    try:
        db.revoke_api_key(conn, user["uid"], key_id)
    finally:
        conn.close()
    return _redirect("/keys", flash="Key revoked.")


# ── web: admin ────────────────────────────────────────────────────

async def web_admin(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    if not user["is_admin"]:
        return _page("Forbidden", "", user, error="Admin only.")
    conn = _open_db(request)
    try:
        accounts = db.list_accounts(conn)
        allowed = db.list_allowed_logins(conn)
    finally:
        conn.close()
    rows = ""
    for a in accounts:
        admin_badge = " <b>· admin</b>" if a["is_admin"] else ""
        emails = " · ".join(
            f"{_e(e)} <form class='inline' method='post'"
            f" action='/admin/accounts/{a['uid']}/emails/remove'>"
            f"<input type='hidden' name='email' value='{_e(e)}'>"
            f"<button type='submit'>×</button></form>"
            for e in a["emails"]
        ) or "<span class='muted'>none</span>"
        rows += (
            f"<tr><td>{a['uid']}</td>"
            f"<td><b>{_e(a['username'])}</b>{admin_badge}"
            f"<br><span class='muted'>{_e(a['identities'] or 'no linked logins')}</span></td>"
            f"<td>{emails}</td>"
            f"<td><form class='inline' method='post' action='/admin/accounts/{a['uid']}/emails/add'>"
            f"<input type='text' name='email' placeholder='add email' required>"
            f"<button type='submit'>Bind</button></form></td>"
            f"<td><form class='inline' method='post' action='/admin/accounts/{a['uid']}/admin'>"
            f"<button type='submit'>{'Revoke admin' if a['is_admin'] else 'Make admin'}</button></form></td>"
            f"</tr>"
        )
    accounts_table = (
        "<table><tr><th>uid</th><th>username</th><th>email bindings</th>"
        f"<th></th><th></th></tr>{rows}</table>"
    )
    allow_rows = "".join(
        f"<tr><td>{_e(login)}</td>"
        f"<td><form class='inline' method='post' action='/admin/disallow'>"
        f"<input type='hidden' name='login' value='{_e(login)}'>"
        f"<button class='danger' type='submit'>Remove</button></form></td></tr>"
        for login in allowed
    )
    body = f"""
    <h1>Admin — accounts</h1>
    <p class="muted">Each account has one uid + username and any number of bound
    emails. GitHub/Gitea logins map to an account by linked identity, or by
    email binding; documents are private to an account.</p>
    {accounts_table}
    <h2>Create account</h2>
    <form method="post" action="/admin/accounts/create">
      <input type="text" name="username" placeholder="username" required>
      <input type="text" name="emails" placeholder="emails, comma separated (optional)">
      <button class="primary" type="submit">Create</button>
    </form>
    <h2>Allowlist (usernames that may self-register)</h2>
    <table><tr><th>Username</th><th></th></tr>{allow_rows}</table>
    <form method="post" action="/admin/allow">
      <input type="text" name="login" placeholder="username (as they log in on GitHub/Gitea)" required>
      <button class="primary" type="submit">Allow</button>
    </form>
    """
    return _page("Admin", body, user, **_flash_error(request))


def _admin_action(request: Request):
    """Returns (user, response). response is set when not an admin."""
    user, resp = _require_web_user(request)
    if resp:
        return None, resp
    if not user["is_admin"]:
        return None, _page("Forbidden", "", user, error="Admin only.")
    return user, None


async def web_admin_account_create(request: Request) -> Response:
    user, resp = _admin_action(request)
    if resp:
        return resp
    form = await request.form()
    username = str(form.get("username", "")).strip()
    emails = [e.strip() for e in str(form.get("emails", "")).split(",") if e.strip()]
    if not username:
        return _redirect("/admin", error="Username is required.")
    conn = _open_db(request)
    try:
        try:
            account = db.create_account(conn, username)
            for e in emails:
                db.bind_email(conn, account["uid"], e)
        except (ValueError, LookupError, sqlite3.IntegrityError) as exc:
            return _redirect("/admin", error=f"Cannot create account: {exc}")
    finally:
        conn.close()
    return _redirect("/admin", flash=f"Created account '{account['username']}' (uid {account['uid']}).")


async def web_admin_email_add(request: Request) -> Response:
    user, resp = _admin_action(request)
    if resp:
        return resp
    uid = int(request.path_params["uid"])
    form = await request.form()
    email = str(form.get("email", "")).strip()
    conn = _open_db(request)
    try:
        try:
            added = db.bind_email(conn, uid, email)
        except (ValueError, LookupError) as exc:
            return _redirect("/admin", error=f"Cannot bind email: {exc}")
    finally:
        conn.close()
    flash = f"Bound {email}." if added else f"{email} was already bound."
    return _redirect("/admin", flash=flash)


async def web_admin_email_remove(request: Request) -> Response:
    user, resp = _admin_action(request)
    if resp:
        return resp
    uid = int(request.path_params["uid"])
    form = await request.form()
    email = str(form.get("email", "")).strip()
    conn = _open_db(request)
    try:
        removed = db.unbind_email(conn, uid, email)
    finally:
        conn.close()
    if not removed:
        return _redirect("/admin", error=f"{email} was not bound to uid {uid}.")
    return _redirect("/admin", flash=f"Unbound {email} from uid {uid}.")


async def web_admin_account_admin(request: Request) -> Response:
    user, resp = _admin_action(request)
    if resp:
        return resp
    uid = int(request.path_params["uid"])
    conn = _open_db(request)
    try:
        account = db.get_account_by_uid(conn, uid)
        if account is None:
            return _redirect("/admin", error=f"No account uid={uid}.")
        if uid == user["uid"]:
            return _redirect("/admin", error="You cannot revoke your own admin.")
        db.set_account_admin(conn, uid, not account["is_admin"])
    finally:
        conn.close()
    verb = "granted admin to" if not account["is_admin"] else "revoked admin from"
    return _redirect("/admin", flash=f"{verb} uid {uid} ({account['username']}).")


async def web_admin_allow(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    if not user["is_admin"]:
        return _page("Forbidden", "", user, error="Admin only.")
    form = await request.form()
    login = str(form.get("login", "")).strip()
    if login:
        conn = _open_db(request)
        try:
            db.allow_login(conn, login)
        finally:
            conn.close()
    return _redirect("/admin", flash=f"Allowed {login}.")


async def web_admin_disallow(request: Request) -> Response:
    user, resp = _require_web_user(request)
    if resp:
        return resp
    if not user["is_admin"]:
        return _page("Forbidden", "", user, error="Admin only.")
    form = await request.form()
    login = str(form.get("login", "")).strip()
    conn = _open_db(request)
    try:
        db.disallow_login(conn, login)
    finally:
        conn.close()
    return _redirect("/admin", flash=f"Removed {login}.")


# ── REST API ──────────────────────────────────────────────────────

async def api_version(request: Request) -> Response:
    """Public server version — lets clients/operators check what is running
    before authenticating (used by the upgrade procedure)."""
    return JSONResponse({"server": __version__})


async def api_whoami(request: Request) -> Response:
    user, resp = await _require_api_user(request)
    if resp:
        return resp
    return JSONResponse({"username": user["username"], "login": user["username"],
                         "name": user["name"]})


async def api_list(request: Request) -> Response:
    user, resp = await _require_api_user(request)
    if resp:
        return resp
    conn = _open_db(request)
    try:
        docs = db.list_documents(conn, user["uid"])
    finally:
        conn.close()
    return JSONResponse({"documents": [
        {"app": d["app"], "name": d["name"], "version": d["version"],
         "updated_at": d["updated_at"], "size": d["size"]}
        for d in docs
    ]})


async def api_get(request: Request) -> Response:
    user, resp = await _require_api_user(request)
    if resp:
        return resp
    app, name = request.path_params["app"], request.path_params["name"]
    conn = _open_db(request)
    try:
        row = db.get_document(conn, user["uid"], app, name)
        if row is None:
            return JSONResponse({"error": f"no document {app}/{name}"}, status_code=404)
        return JSONResponse({
            "app": app, "name": name, "version": row["version"],
            "updated_at": row["updated_at"], "content": _decrypt_doc(request, row),
        })
    finally:
        conn.close()


async def api_put(request: Request) -> Response:
    user, resp = await _require_api_user(request)
    if resp:
        return resp
    app, name = request.path_params["app"], request.path_params["name"]
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON body"}, status_code=400)
    content = body.get("content")
    if not isinstance(content, str):
        return JSONResponse({"error": "body must be {\"content\": \"...\"}"}, status_code=400)
    if len(content.encode()) > MAX_CONTENT_BYTES:
        return JSONResponse({"error": "content exceeds 4 MB limit"}, status_code=413)
    version = _store_doc(request, user["uid"], app, name, content)
    return JSONResponse({"app": app, "name": name, "version": version})


async def api_delete(request: Request) -> Response:
    user, resp = await _require_api_user(request)
    if resp:
        return resp
    app, name = request.path_params["app"], request.path_params["name"]
    conn = _open_db(request)
    try:
        existed = db.delete_document(conn, user["uid"], app, name)
    finally:
        conn.close()
    if not existed:
        return JSONResponse({"error": f"no document {app}/{name}"}, status_code=404)
    return JSONResponse({"deleted": f"{app}/{name}"})


async def api_history(request: Request) -> Response:
    user, resp = await _require_api_user(request)
    if resp:
        return resp
    app, name = request.path_params["app"], request.path_params["name"]
    conn = _open_db(request)
    try:
        rows = db.list_history(conn, user["uid"], app, name)
    finally:
        conn.close()
    return JSONResponse({"history": [
        {"version": r["version"], "saved_at": r["saved_at"], "size": r["size"]}
        for r in rows
    ]})


async def api_history_get(request: Request) -> Response:
    user, resp = await _require_api_user(request)
    if resp:
        return resp
    app, name = request.path_params["app"], request.path_params["name"]
    version = int(request.path_params["version"])
    conn = _open_db(request)
    try:
        row = db.get_history_version(conn, user["uid"], app, name, version)
        if row is None:
            return JSONResponse({"error": f"no version {version}"}, status_code=404)
        return JSONResponse({
            "app": app, "name": name, "version": version,
            "saved_at": row["saved_at"], "content": _decrypt_doc(request, row),
        })
    finally:
        conn.close()


# ── app factory ───────────────────────────────────────────────────

def create_app(settings: ServerSettings | None = None) -> Starlette:
    settings = settings or load_settings()
    master_key = crypto.load_or_create_master_key(settings.home)

    @asynccontextmanager
    async def lifespan(app: Starlette):
        conn = db.connect(settings.db_path)
        try:
            db.seed_allowed_logins(conn, settings.allowed_users)
        finally:
            conn.close()
        yield

    # Specific routes must precede the generic {name:path} routes.
    routes = [
        Route("/", web_index),
        Route("/login", login_page),
        Route("/auth/github/login", github_login),
        Route("/auth/github/callback", github_callback),
        Route("/auth/gitea/login", gitea_login),
        Route("/auth/gitea/callback", gitea_callback),
        Route("/logout", logout),
        Route("/keys", web_keys),
        Route("/keys/create", web_key_create, methods=["POST"]),
        Route("/keys/{key_id:int}/revoke", web_key_revoke, methods=["POST"]),
        Route("/admin", web_admin),
        Route("/admin/allow", web_admin_allow, methods=["POST"]),
        Route("/admin/disallow", web_admin_disallow, methods=["POST"]),
        Route("/admin/accounts/create", web_admin_account_create, methods=["POST"]),
        Route("/admin/accounts/{uid:int}/emails/add", web_admin_email_add, methods=["POST"]),
        Route("/admin/accounts/{uid:int}/emails/remove", web_admin_email_remove, methods=["POST"]),
        Route("/admin/accounts/{uid:int}/admin", web_admin_account_admin, methods=["POST"]),
        Route("/docs/{app}/{name:path}/raw", web_doc_raw),
        Route("/docs/{app}/{name:path}/rollback", web_doc_rollback, methods=["POST"]),
        Route("/docs/{app}/{name:path}/delete", web_doc_delete, methods=["POST"]),
        Route("/docs/{app}/{name:path}", web_doc_view),
        Route("/docs/{app}/{name:path}", web_doc_save, methods=["POST"]),
        Route("/api/v1/version", api_version),
        Route("/api/v1/whoami", api_whoami),
        Route("/api/v1/documents", api_list),
        Route("/api/v1/documents/{app}/{name:path}/history/{version:int}", api_history_get),
        Route("/api/v1/documents/{app}/{name:path}/history", api_history),
        Route("/api/v1/documents/{app}/{name:path}", api_get, methods=["GET"]),
        Route("/api/v1/documents/{app}/{name:path}", api_put, methods=["PUT"]),
        Route("/api/v1/documents/{app}/{name:path}", api_delete, methods=["DELETE"]),
    ]

    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.settings = settings
    app.state.master_key = master_key
    app.state.oauth_states = set()
    app.state.gitea_token_cache = {}
    return app
