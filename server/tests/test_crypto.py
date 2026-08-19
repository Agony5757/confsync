import base64
import os
import stat

import pytest
from cryptography.exceptions import InvalidTag

from confsync_server import crypto


def test_roundtrip():
    key = b"k" * 32
    aad = b"1/flexgate/config.yaml"
    blob = crypto.encrypt(key, b"secret: value", aad)
    assert crypto.decrypt(key, blob, aad) == b"secret: value"


def test_aad_mismatch_fails():
    key = b"k" * 32
    blob = crypto.encrypt(key, b"data", b"1/app/a")
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, blob, b"1/app/b")


def test_wrong_key_fails():
    blob = crypto.encrypt(b"k" * 32, b"data", b"aad")
    with pytest.raises(InvalidTag):
        crypto.decrypt(b"x" * 32, blob, b"aad")


def test_tampered_ciphertext_fails():
    key = b"k" * 32
    blob = bytearray(crypto.encrypt(key, b"data", b"aad"))
    blob[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, bytes(blob), b"aad")


def test_master_key_created_with_0600(tmp_path, monkeypatch):
    monkeypatch.delenv(crypto.MASTER_KEY_ENV, raising=False)
    home = str(tmp_path / "home")
    key = crypto.load_or_create_master_key(home)
    assert len(key) == 32
    path = os.path.join(home, "master.key")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    # second load returns the same key
    assert crypto.load_or_create_master_key(home) == key


def test_master_key_from_env(tmp_path, monkeypatch):
    key = os.urandom(32)
    monkeypatch.setenv(crypto.MASTER_KEY_ENV, base64.b64encode(key).decode())
    assert crypto.load_or_create_master_key(str(tmp_path)) == key


def test_master_key_env_wrong_length(tmp_path, monkeypatch):
    monkeypatch.setenv(crypto.MASTER_KEY_ENV, base64.b64encode(b"short").decode())
    with pytest.raises(ValueError):
        crypto.load_or_create_master_key(str(tmp_path))
