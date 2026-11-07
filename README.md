# confsync

Self-hosted config sync for your own tools. A small server stores config files
as encrypted documents (one per app, e.g. `flexgate/config.yaml`); a lightweight
client library lets any of your repos push/pull them — one `confsync login`
works for every app.

```
your app (flexgate, ...)                     server (Docker, behind nginx TLS)
  import confsync
  client = confsync.load_client()  ──https──▶  nginx :443
  client.push/pull(app, name, ...)             │ proxy_pass 127.0.0.1:8930
                                               ▼
                                         confsync-server (container)
                                           AES-256-GCM ──▶ SQLite (server.db)
```

## Repository layout

| Path | What |
|------|------|
| `client/` | `confsync-client` package (import name `confsync`) — library + `confsync` CLI. Only depends on httpx. |
| `server/` | `confsync-server` package (import name `confsync_server`) — Starlette app + `confsync-server` CLI. |
| `deploy/` | Docker deployment: `Dockerfile`, `docker-compose.yml`, nginx vhost template. |

Upgrading an existing deployment? See [MIGRATION.md](MIGRATION.md).

## Security model

- **Transport**: TLS terminated at the reverse proxy (nginx + certbot). The
  client refuses plaintext `http://` for non-localhost servers and never uses
  env-configured proxies (`trust_env=False`).
- **At rest**: every document is encrypted with AES-256-GCM under a server-side
  master key (auto-generated at `$CONFSYNC_HOME/master.key`, mode 0600, or the
  `CONFSYNC_MASTER_KEY` env var, base64). The document identity
  (`user/app/name`) is bound as AAD. SQLite only ever holds ciphertext.
- **Auth**: GitHub OAuth for the Web UI (session cookies: HttpOnly, Secure,
  SameSite=Lax; only sha256 of the session token is stored). A self-hosted
  **Gitea** can be used instead of (or alongside) GitHub: same OAuth flow for
  the Web UI, and its access tokens are accepted directly by the REST API.
  API keys (`cs_…`) for CLI/library access — only sha256 is stored, the
  plaintext is shown once at creation. Access is restricted to an allowlist
  of logins (GitHub or Gitea); the first user to log in becomes admin.
- **History**: every push archives the previous version (last 20 kept), with
  view/rollback in the Web UI.

## Server deployment (Docker)

Prereqs: a host with Docker and nginx + certbot; a DNS name pointing at it
(the examples use `confsync.tool.chenzhaoyun.com`).

1. Create a GitHub OAuth App at <https://github.com/settings/developers>:
   - Homepage URL: `https://confsync.tool.chenzhaoyun.com`
   - Authorization callback URL: `https://confsync.tool.chenzhaoyun.com/auth/github/callback`
   (Prefer Gitea? Skip this step — see "Gitea login" below.)
2. Copy `deploy/.env.example` to `deploy/.env` and fill in the client
   id/secret (and optionally `CONFSYNC_ALLOWED_USERS`).
3. Build and start:
   ```bash
   cd deploy && docker compose up -d --build
   docker compose logs -f   # first run generates the master key in the volume
   ```
4. Install the nginx vhost (`deploy/nginx.confsync.conf`) into
   `/etc/nginx/sites-available/`, symlink into `sites-enabled/`, reload nginx,
   then issue the certificate:
   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   sudo certbot --nginx -d confsync.tool.chenzhaoyun.com
   ```
5. Open `https://confsync.tool.chenzhaoyun.com`, sign in with GitHub (first
   login becomes admin), and create an API key under **API Keys**.

### Gitea login

A self-hosted Gitea can replace GitHub as the identity provider (the Web UI
shows whichever providers are configured):

1. In Gitea, create an OAuth2 application under
   *Settings → Applications → Manage OAuth2 Applications*:
   - Redirect URL: `https://confsync.tool.chenzhaoyun.com/auth/gitea/callback`
2. Fill `CONFSYNC_GITEA_URL` (the Gitea base URL, e.g.
   `https://git.example.com`), `CONFSYNC_GITEA_CLIENT_ID` and
   `CONFSYNC_GITEA_CLIENT_SECRET` in `deploy/.env` and restart. The login
   page now offers **Sign in with Gitea**.
3. REST API auth also accepts Gitea access tokens: create one under
   *Settings → Applications → Access Tokens* (scope `read:user` is enough)
   and use it where an API key would go:
   ```bash
   confsync login --server https://confsync.tool.chenzhaoyun.com   # paste the Gitea token
   ```
   The server verifies each token against your Gitea (cached ~5 min) and
   maps it to the confsync user with the same login — no API key needed.
   Logins are gated by the same allowlist as OAuth.

Bare-metal alternative (no Docker): `pip install ./server`, write
`~/.confsync-server/server.yaml` (see `deploy/server.yaml.example`), then
`confsync-server service install` for a systemd user unit.

Server config: `$CONFSYNC_HOME/server.yaml` (default `~/.confsync-server/`),
every key overridable by env (`CONFSYNC_HOST`, `CONFSYNC_PORT`,
`CONFSYNC_EXTERNAL_URL`, `CONFSYNC_GITHUB_CLIENT_ID`,
`CONFSYNC_GITHUB_CLIENT_SECRET`, `CONFSYNC_GITEA_URL`,
`CONFSYNC_GITEA_CLIENT_ID`, `CONFSYNC_GITEA_CLIENT_SECRET`,
`CONFSYNC_ALLOWED_USERS`, `CONFSYNC_MASTER_KEY`).

## Client

```bash
pip install ./client          # or: uv tool install ./client

confsync login --server https://confsync.tool.chenzhaoyun.com   # paste API key (or a Gitea access token)
confsync push --app flexgate --name config.yaml --file ~/.flexgate/config.yaml
confsync pull --app flexgate --name config.yaml                 # to stdout
confsync pull --app flexgate --name config.yaml --version 3     # history version
confsync list
confsync history --app flexgate --name config.yaml
confsync help            # offline docs: auth, upgrade, api, server, troubleshooting
```

Credentials live at `~/.confsync/credentials.json` (mode 0600) and are shared
by every app using the library.

## Embedding in your own app

```python
from confsync import load_client, ConfsyncError

try:
    with load_client() as client:          # shared credentials, zero config
        client.push(app="myapp", name="settings.yaml", content=text)
        text = client.pull(app="myapp", name="settings.yaml")
        docs = client.list()
except ConfsyncError as e:
    ...  # not logged in / server unreachable / etc.
```

Or with explicit credentials:

```python
from confsync import ConfsyncClient
client = ConfsyncClient("https://confsync.tool.chenzhaoyun.com", api_key="cs_...")
```

REST API (all under `/api/v1`, `Authorization: Bearer cs_…` — a Gitea
access token also works when the server has Gitea configured):

| Method | Path | Purpose |
|---|---|---|
| GET | `/version` | public server version (no auth) |
| GET | `/whoami` | verify the key |
| GET | `/documents` | list documents |
| GET/PUT/DELETE | `/documents/{app}/{name}` | pull / push (`{"content": "..."}`) / delete |
| GET | `/documents/{app}/{name}/history` | version list |
| GET | `/documents/{app}/{name}/history/{version}` | fetch an old version |

## Development

```bash
cd server && uv venv --python 3.12 && uv pip install -e '.[dev]' && .venv/bin/python -m pytest
cd client && uv venv --python 3.12 && uv pip install -e '.[dev]' && .venv/bin/python -m pytest
```
