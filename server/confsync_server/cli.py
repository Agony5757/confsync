"""confsync-server CLI: serve / service."""
from __future__ import annotations

import argparse
import sys

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
        user = db.create_bootstrap_user(conn, args.login)
        key = auth.generate_api_key()
        db.create_api_key(conn, user["id"], args.name, key)
    finally:
        conn.close()
    print(f"User '{args.login}' ready (admin={bool(user['is_admin'])}).")
    print(f"API key (shown once): {key}")


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
        help="Create a user + API key without GitHub OAuth (adopts real GitHub id on first login)")
    boot.add_argument("--login", required=True, help="GitHub login name of the user")
    boot.add_argument("--name", default="bootstrap", help="API key name")

    args = parser.parse_args()
    if args.group == "serve":
        cmd_serve(args)
    elif args.group == "service":
        cmd_service(args)
    elif args.group == "bootstrap":
        cmd_bootstrap(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
