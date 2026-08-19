"""confsync client CLI: login / push / pull / list / history."""
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


def _client_or_die():
    try:
        return load_client()
    except ConfsyncError as exc:
        _fail(str(exc))


def cmd_login(args: argparse.Namespace) -> None:
    api_key = args.api_key
    if not api_key:
        print(f"Create an API key in the web UI: {args.server}/keys")
        api_key = getpass.getpass("API key: ").strip()
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

    args = parser.parse_args()
    handlers = {
        "login": cmd_login, "push": cmd_push, "pull": cmd_pull,
        "list": cmd_list, "history": cmd_history, "delete": cmd_delete,
    }
    handler = handlers.get(args.group or "")
    if handler is None:
        parser.print_help()
        sys.exit(0)
    handler(args)


if __name__ == "__main__":
    main()
