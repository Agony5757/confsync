"""confsync client — pull/push encrypted config documents.

Typical usage from another project (e.g. flexgate):

    from confsync import load_client
    client = load_client()                      # shared ~/.confsync credentials
    client.push(app="myapp", name="config.yaml", content=text)
    text = client.pull(app="myapp", name="config.yaml")
"""
from __future__ import annotations

__version__ = "0.1.0"

from confsync.core import ConfsyncClient, ConfsyncError
from confsync.credentials import load_client, login

__all__ = ["ConfsyncClient", "ConfsyncError", "load_client", "login", "__version__"]
