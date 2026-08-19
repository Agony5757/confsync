"""systemd user-service management for bare-metal deployments.

Docker (deploy/) is the primary deployment mode; this is the alternative for
hosts without Docker. Mirrors the flexgate service pattern.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

UNIT_NAME = "confsync-server.service"
UNIT_DIR = os.path.expanduser("~/.config/systemd/user")
UNIT_PATH = os.path.join(UNIT_DIR, UNIT_NAME)

UNIT_TEMPLATE = """\
[Unit]
Description=confsync server — encrypted config document store
After=network-online.target

[Service]
ExecStart={exe} serve
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
"""


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True)


def install() -> None:
    exe = shutil.which("confsync-server")
    if exe is None:
        print("confsync-server executable not found in PATH.")
        sys.exit(1)
    os.makedirs(UNIT_DIR, exist_ok=True)
    with open(UNIT_PATH, "w") as f:
        f.write(UNIT_TEMPLATE.format(exe=exe))
    _run(["daemon-reload"])
    proc = _run(["enable", "--now", UNIT_NAME])
    if proc.returncode != 0:
        print(proc.stderr.strip())
        sys.exit(1)
    print(f"Installed and started {UNIT_NAME}.")


def uninstall() -> None:
    _run(["disable", "--now", UNIT_NAME])
    if os.path.exists(UNIT_PATH):
        os.remove(UNIT_PATH)
    _run(["daemon-reload"])
    print(f"Uninstalled {UNIT_NAME}.")


def control(action: str) -> None:
    if action == "status":
        proc = _run(["status", UNIT_NAME])
        print(proc.stdout or proc.stderr)
        return
    proc = _run([action, UNIT_NAME])
    if proc.returncode != 0:
        print(proc.stderr.strip())
        sys.exit(1)
    print(f"{action}: OK")
