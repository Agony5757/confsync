"""confsync client CLI: login / push / pull / list / history / help."""
from __future__ import annotations

import argparse
import getpass
import sys

from confsync import __version__
from confsync.core import ConfsyncError
from confsync.credentials import get_credentials_path, load_client, login


def _fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


HELP_TOPICS = {
    "auth": """\
confsync help: auth — logging in

  confsync login --server https://confsync.example.com [--api-key KEY]

Credentials are saved to ~/.confsync/credentials.json (mode 0600) and shared
by every tool that imports confsync. Override the path with
$CONFSYNC_CREDENTIALS. Re-login anytime; logout = delete the file.

Two kinds of credentials are accepted:

  1. API key (cs_...)   Create one in the web UI under /keys. Shown once;
                        only its hash is stored server-side.
  2. Gitea access token If the server has Gitea configured, paste a token
                        from Gitea (Settings -> Applications -> Access
                        Tokens, scope read:user is enough). The server
                        verifies it against your Gitea (cached ~5 min) and
                        maps it to your confsync account (identity or email).

Requires client >= 0.2.0 for Gitea tokens (older clients insist on cs_ keys).\
""",

    "upgrade": """\
confsync help: upgrade — upgrading client and server

Client:
  CLI users       pip install -U confsync-client
                  (or: uv tool upgrade confsync-client)
  Embedded apps   put confsync-client>=0.2.0 in your app's dependencies
  After upgrading nothing else changes: credentials file and REST API are
  stable across versions — no re-login needed.

Compatibility matrix:
  client 0.1.x <-> server 0.2.x   works (API unchanged)
  Gitea-token login               needs client >= 0.2.0 AND server >= 0.2.0

Check what the server runs:
  curl https://<server>/api/v1/version

Server upgrade (Docker): see MIGRATION.md in the confsync repository —
backup (confsync-server backup), update code, docker compose up -d --build,
verify /api/v1/version. DB schema migrations apply automatically on start.\
""",

    "api": """\
confsync help: api — REST reference (all under /api/v1)

Auth: Authorization: Bearer <cs_-key or Gitea access token>

  GET    /version                       public server version
  GET    /whoami                        verify the credential
  GET    /documents                     list documents
  GET    /documents/{app}/{name}        pull            -> {content, version, ...}
  PUT    /documents/{app}/{name}        push            body: {"content": "..."}
  DELETE /documents/{app}/{name}        delete (removes history too)
  GET    /documents/{app}/{name}/history                 version list
  GET    /documents/{app}/{name}/history/{version}       fetch old version

Limits: 4 MB per document; last 20 versions kept. Python shortcut:

  from confsync import load_client
  with load_client() as c:
      c.push(app="myapp", name="config.yaml", content=text)
      text = c.pull(app="myapp", name="config.yaml")\
""",

    "server": """\
confsync help: server — deployment pointers

The server is a small Starlette app, deployed with docker compose behind an
nginx TLS proxy. Everything lives in deploy/ of the confsync repository:

  cd deploy && docker compose up -d --build

Main env vars (deploy/.env):
  CONFSYNC_EXTERNAL_URL              public https URL (OAuth callbacks)
  CONFSYNC_GITHUB_CLIENT_ID/SECRET   GitHub OAuth (web UI login)
  CONFSYNC_GITEA_URL/CLIENT_ID/SECRET  self-hosted Gitea login (optional)
  CONFSYNC_ALLOWED_USERS             comma-separated login allowlist
  CONFSYNC_MASTER_KEY                base64 AES key (else auto-generated in /data)

State (the confsync-data volume, /data in the container):
  server.db    SQLite; documents stored AES-256-GCM encrypted
  master.key   server-side encryption key (0600) — losing it loses all docs

First user to log in becomes admin. Hot backup before upgrades:
  confsync-server backup\
""",

    "troubleshooting": """\
confsync help: troubleshooting

  "no credentials at ..."        not logged in — run confsync login
  401 invalid or revoked API key wrong key, or it was revoked in the web UI
  401 Gitea rejected the access token
                                 token revoked/expired in Gitea; the server
                                 caches verifications for ~5 min
  403 ... not on the allowlist   admin must add your login under /admin
  "refusing plaintext http ..."  the server must be https (localhost excepted
                                 for tests) — put it behind a TLS proxy
  "cannot reach <server>"        network/DNS/TLS problem; confsync never uses
                                 $HTTP(S)_PROXY, check direct connectivity
  push 413                       document exceeds the 4 MB limit

Server-side: docker logs confsync-server; version via
curl https://<server>/api/v1/version; backups via confsync-server backup.\
""",
}

HELP_OVERVIEW = f"""\
confsync {__version__} — sync config documents with a confsync server

Quick start:
  confsync login --server https://confsync.example.com   # cs_ key or Gitea token
  confsync push --app myapp --name config.yaml --file path/to/file
  confsync pull --app myapp --name config.yaml            # to stdout
  confsync list

Commands: login, push, pull, list, history, delete, help

Topics (confsync help <topic>):
  auth            logging in: API keys and Gitea access tokens
  upgrade         upgrading client/server and compatibility notes
  api             REST API reference
  server          server deployment pointers (Docker, env, data)
  troubleshooting common errors and fixes\
"""


def cmd_help(args: argparse.Namespace) -> None:
    topic = args.topic
    if topic is None:
        print(HELP_OVERVIEW)
        return
    text = HELP_TOPICS.get(topic)
    if text is None:
        _fail(f"unknown help topic: {topic!r}\n"
              f"available: {', '.join(HELP_TOPICS)}")
    print(text)


def _client_or_die():
    try:
        return load_client()
    except ConfsyncError as exc:
        _fail(str(exc))


def cmd_login(args: argparse.Namespace) -> None:
    api_key = args.api_key
    if not api_key:
        print(f"Create an API key in the web UI ({args.server}/keys), or use a "
              "Gitea access token if the server has Gitea configured.")
        api_key = getpass.getpass("API key / Gitea token: ").strip()
    try:
        with login(args.server, api_key) as client:
            who = client.whoami()
    except ConfsyncError as exc:
        _fail(str(exc))
    print(f"Logged in as {who['login']} @ {args.server}")
    print(f"Credentials saved to {get_credentials_path()}")


def cmd_push(args: argparse.Namespace) -> None:
    try:
        with open(args.file, encoding="utf-8") as f:
            content = f.read()
    except OSError as exc:
        _fail(f"cannot read {args.file}: {exc}")
    with _client_or_die() as client:
        try:
            version = client.push(args.app, args.name, content)
        except ConfsyncError as exc:
            _fail(str(exc))
    print(f"pushed {args.app}/{args.name} → v{version}")


def cmd_pull(args: argparse.Namespace) -> None:
    with _client_or_die() as client:
        try:
            content = client.pull(args.app, args.name, version=args.version)
        except ConfsyncError as exc:
            _fail(str(exc))
    if args.file:
        with open(args.file, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"wrote {args.app}/{args.name} → {args.file}")
    else:
        sys.stdout.write(content)


def cmd_list(args: argparse.Namespace) -> None:
    with _client_or_die() as client:
        try:
            docs = client.list()
        except ConfsyncError as exc:
            _fail(str(exc))
    if not docs:
        print("no documents")
        return
    for d in docs:
        print(f"{d['app']}/{d['name']}  v{d['version']}  {d['size']}B")


def cmd_history(args: argparse.Namespace) -> None:
    with _client_or_die() as client:
        try:
            rows = client.history(args.app, args.name)
        except ConfsyncError as exc:
            _fail(str(exc))
    if not rows:
        print("no history")
        return
    for r in rows:
        print(f"v{r['version']}  {r['size']}B  saved {r['saved_at']:.0f}")


def cmd_delete(args: argparse.Namespace) -> None:
    with _client_or_die() as client:
        try:
            client.delete(args.app, args.name)
        except ConfsyncError as exc:
            _fail(str(exc))
    print(f"deleted {args.app}/{args.name}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="confsync",
        description="confsync client — sync config documents with a confsync server",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="group")

    p = sub.add_parser("login", help="Save server URL + API key (shared credentials)")
    p.add_argument("--server", required=True, help="e.g. https://confsync.example.com")
    p.add_argument("--api-key", help="API key (cs_...); prompted if omitted")

    p = sub.add_parser("push", help="Upload a file as a document")
    p.add_argument("--app", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--file", required=True)

    p = sub.add_parser("pull", help="Download a document (stdout or --file)")
    p.add_argument("--app", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--file", help="Write to this path instead of stdout")
    p.add_argument("--version", type=int, help="Pull a history version instead of latest")

    sub.add_parser("list", help="List my documents")

    p = sub.add_parser("history", help="List a document's version history")
    p.add_argument("--app", required=True)
    p.add_argument("--name", required=True)

    p = sub.add_parser("delete", help="Delete a document and its history")
    p.add_argument("--app", required=True)
    p.add_argument("--name", required=True)

    hlp = sub.add_parser("help", help="Show help topics and how-tos")
    hlp.add_argument("topic", nargs="?",
                     help=f"one of: {', '.join(HELP_TOPICS)}")

    args = parser.parse_args()
    handlers = {
        "login": cmd_login, "push": cmd_push, "pull": cmd_pull,
        "list": cmd_list, "history": cmd_history, "delete": cmd_delete,
        "help": cmd_help,
    }
    handler = handlers.get(args.group or "")
    if handler is None:
        parser.print_help()
        sys.exit(0)
    handler(args)


if __name__ == "__main__":
    main()
