"""Server settings: file ($CONFSYNC_HOME/server.yaml) + env overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_PORT = 8930

HOME_ENV = "CONFSYNC_HOME"


def get_home() -> str:
    """Server home dir: $CONFSYNC_HOME, default ~/.confsync-server."""
    env = os.environ.get(HOME_ENV, "").strip()
    if env:
        return env
    return os.path.expanduser("~/.confsync-server")


@dataclass
class ServerSettings:
    host: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    external_url: str = ""  # e.g. https://confsync.example.com (OAuth callback base)
    github_client_id: str = ""
    github_client_secret: str = ""
    allowed_users: list[str] = field(default_factory=list)  # GitHub logins
    home: str = ""

    @property
    def db_path(self) -> str:
        return os.path.join(self.home, "server.db")


def load_settings(home: str | None = None) -> ServerSettings:
    """Load settings from $CONFSYNC_HOME/server.yaml with env overrides.

    Env overrides: CONFSYNC_HOST, CONFSYNC_PORT, CONFSYNC_EXTERNAL_URL,
    CONFSYNC_GITHUB_CLIENT_ID, CONFSYNC_GITHUB_CLIENT_SECRET,
    CONFSYNC_ALLOWED_USERS (comma-separated).
    """
    import yaml

    home = home or get_home()
    raw: dict = {}
    path = os.path.join(home, "server.yaml")
    if os.path.exists(path):
        with open(path) as f:
            loaded = yaml.safe_load(f)
        if loaded is not None and not isinstance(loaded, dict):
            raise ValueError(f"{path} must be a YAML mapping")
        raw = loaded or {}

    gh = raw.get("github", {}) or {}

    s = ServerSettings(
        host=str(raw.get("host", "127.0.0.1")),
        port=int(raw.get("port", DEFAULT_PORT)),
        external_url=str(raw.get("external_url", "")).rstrip("/"),
        github_client_id=str(gh.get("client_id", "")),
        github_client_secret=str(gh.get("client_secret", "")),
        allowed_users=[str(u) for u in (raw.get("allowed_users", []) or [])],
        home=home,
    )

    env = os.environ
    if env.get("CONFSYNC_HOST"):
        s.host = env["CONFSYNC_HOST"]
    if env.get("CONFSYNC_PORT"):
        s.port = int(env["CONFSYNC_PORT"])
    if env.get("CONFSYNC_EXTERNAL_URL"):
        s.external_url = env["CONFSYNC_EXTERNAL_URL"].rstrip("/")
    if env.get("CONFSYNC_GITHUB_CLIENT_ID"):
        s.github_client_id = env["CONFSYNC_GITHUB_CLIENT_ID"]
    if env.get("CONFSYNC_GITHUB_CLIENT_SECRET"):
        s.github_client_secret = env["CONFSYNC_GITHUB_CLIENT_SECRET"]
    if env.get("CONFSYNC_ALLOWED_USERS"):
        s.allowed_users = [u.strip() for u in env["CONFSYNC_ALLOWED_USERS"].split(",") if u.strip()]

    return s
