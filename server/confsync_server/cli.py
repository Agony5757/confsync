"""confsync-server CLI: serve / service / bootstrap / backup."""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
import time

from confsync_server import __version__
from confsync_server.config import load_settings


def cmd_serve(args: argparse.Namespace) -> None:
    import uvicorn

    from confsync_server.app import create_app

    settings = load_settings()
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port
    app = create_app(settings)
    print(f"confsync-server {__version__} listening on {settings.host}:{settings.port}")
    print(f"home: {settings.home}  db: {settings.db_path}")
    if settings.external_url:
        print(f"external url: {settings.external_url}")
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


def cmd_service(args: argparse.Namespace) -> None:
    from confsync_server import service

    action = args.action
    if action == "install":
        service.install()
    elif action == "uninstall":
        service.uninstall()
    else:
        service.control(action)


def cmd_bootstrap(args: argparse.Namespace) -> None:
    from confsync_server import auth, db

    settings = load_settings()
    conn = db.connect(settings.db_path)
    try:
        account = db.get_account_by_username(conn, args.username) \
            or db.create_account(conn, args.username)
        db.allow_login(conn, args.username)
        key = auth.generate_api_key()
        db.create_api_key(conn, account["uid"], args.name, key)
    finally:
        conn.close()
    print(f"Account '{account['username']}' ready (admin={bool(account['is_admin'])}).")
    print(f"API key (shown once): {key}")


def cmd_backup(args: argparse.Namespace) -> None:
    """Hot backup: consistent sqlite snapshot of server.db + the master key.
    Run this before upgrading the server (see MIGRATION.md)."""
    settings = load_settings()
    if not os.path.exists(settings.db_path):
        print(f"error: no database at {settings.db_path} — is CONFSYNC_HOME correct?",
              file=sys.stderr)
        sys.exit(1)
    out = args.out or os.path.join(
        settings.home, "backups", time.strftime("confsync-%Y%m%d-%H%M%S")
    )
    os.makedirs(out, exist_ok=True)

    db_out = os.path.join(out, "server.db")
    src = sqlite3.connect(settings.db_path)
    dst = sqlite3.connect(db_out)
    try:
        src.backup(dst)  # online backup API: safe while the server is running
    finally:
        src.close()
        dst.close()
    os.chmod(db_out, 0o600)

    key_path = os.path.join(settings.home, "master.key")
    if os.path.exists(key_path):
        key_out = os.path.join(out, "master.key")
        shutil.copyfile(key_path, key_out)
        os.chmod(key_out, 0o600)
        print(f"backup written to {out} (server.db + master.key)")
    else:
        print(f"backup written to {out} (server.db)")
        print("note: master key comes from $CONFSYNC_MASTER_KEY — "
              "back it up separately (secret manager).")
    print(f"restore: stop confsync-server, copy the files back into "
          f"{settings.home}, start again.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="confsync-server",
        description="confsync server — encrypted config document store",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="group")

    serve = sub.add_parser("serve", help="Run the server in the foreground")
    serve.add_argument("--host", help="Override configured listen host")
    serve.add_argument("--port", type=int, help="Override configured listen port")

    svc = sub.add_parser("service", help="Manage the systemd user service (bare-metal)")
    svc.add_argument("action",
                     choices=["install", "start", "stop", "restart", "status", "uninstall"])

    boot = sub.add_parser(
        "bootstrap",
        help="Create an account + API key without OAuth (the account adopts "
             "provider identities on their first login)")
    boot.add_argument("--username", required=True,
                      help="username of the account (linked on first GitHub/Gitea login)")
    boot.add_argument("--name", default="bootstrap", help="API key name")

    backup = sub.add_parser(
        "backup",
        help="Hot backup of server.db + master key (run before upgrades)")
    backup.add_argument("--out", help="Backup directory (default: $CONFSYNC_HOME/backups/<timestamp>)")

    args = parser.parse_args()
    if args.group == "serve":
        cmd_serve(args)
    elif args.group == "service":
        cmd_service(args)
    elif args.group == "bootstrap":
        cmd_bootstrap(args)
    elif args.group == "backup":
        cmd_backup(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
