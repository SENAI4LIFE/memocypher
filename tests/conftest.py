from __future__ import annotations

import os

import pytest

from memocypher import crypto


@pytest.fixture
def fast_scrypt(monkeypatch):
    """Shrink scrypt cost so passphrase tests run in milliseconds."""

    cheap = crypto.ScryptParams(n=1 << 12, r=8, p=1)
    monkeypatch.setattr(crypto, "DEFAULT_SCRYPT", cheap)
    return cheap


@pytest.fixture
def passphrase_credential(fast_scrypt):
    return crypto.PassphraseCredential("correct horse battery staple", fast_scrypt)


@pytest.fixture
def keyfile_credential():
    return crypto.KeyFileCredential(os.urandom(32))


@pytest.fixture
def sample_tree(tmp_path):
    (tmp_path / "notes.txt").write_text("plain notes\n" * 20)
    (tmp_path / "photo.raw").write_bytes(os.urandom(200_000))
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "inner.md").write_text("# inner\n")
    return tmp_path
