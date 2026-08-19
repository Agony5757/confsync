"""AES-256-GCM encryption for stored documents.

The master key (32 bytes) lives only on the server: it is auto-generated on
first run into ``$CONFSYNC_HOME/master.key`` (mode 0600), or supplied via the
``CONFSYNC_MASTER_KEY`` environment variable (base64).

Every document is encrypted with a fresh random 12-byte nonce. The document
identity (``user_id/app/name``) is bound as AAD so a ciphertext cannot be
replayed under a different document name. Storage format: ``nonce || ct || tag``.
"""
from __future__ import annotations

import base64
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_KEY_ENV = "CONFSYNC_MASTER_KEY"

_NONCE_LEN = 12
_KEY_LEN = 32


def load_or_create_master_key(home: str) -> bytes:
    """Load the master key from env or $CONFSYNC_HOME/master.key.

    Generates and persists a new key (mode 0600) when neither exists.
    """
    env = os.environ.get(MASTER_KEY_ENV, "").strip()
    if env:
        key = base64.b64decode(env)
        if len(key) != _KEY_LEN:
            raise ValueError(f"{MASTER_KEY_ENV} must decode to 32 bytes, got {len(key)}")
        return key

    path = os.path.join(home, "master.key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = base64.b64decode(f.read().strip())
        if len(key) != _KEY_LEN:
            raise ValueError(f"{path} does not contain a valid 32-byte key")
        return key

    os.makedirs(home, exist_ok=True)
    key = secrets.token_bytes(_KEY_LEN)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, base64.b64encode(key) + b"\n")
    finally:
        os.close(fd)
    return key


def document_aad(user_id: int, app: str, name: str) -> bytes:
    """AAD binding a ciphertext to its document identity."""
    return f"{user_id}/{app}/{name}".encode()


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < _NONCE_LEN + 16:
        raise ValueError("ciphertext blob too short")
    return AESGCM(key).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], aad)
