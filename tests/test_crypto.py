from __future__ import annotations

import io
import os

import pytest

from memocypher import crypto
from memocypher.errors import (
    IntegrityError,
    UnsupportedFormatError,
    WrongCredentialError,
)

SEGMENT = 256
SIZES = [0, 1, SEGMENT - 1, SEGMENT, SEGMENT + 1, 3 * SEGMENT, 5 * SEGMENT + 7]


def _encrypt(data: bytes, cred, segment=SEGMENT) -> bytes:
    out = io.BytesIO()
    crypto.encrypt_stream(io.BytesIO(data), out, cred, segment_size=segment)
    return out.getvalue()


def _decrypt(blob: bytes, cred) -> bytes:
    out = io.BytesIO()
    crypto.decrypt_stream(io.BytesIO(blob), out, cred)
    return out.getvalue()


@pytest.mark.parametrize("size", SIZES)
def test_roundtrip_passphrase(size, passphrase_credential):
    data = os.urandom(size)
    assert _decrypt(_encrypt(data, passphrase_credential), passphrase_credential) == data


@pytest.mark.parametrize("size", SIZES)
def test_roundtrip_keyfile(size, keyfile_credential):
    data = os.urandom(size)
    assert _decrypt(_encrypt(data, keyfile_credential), keyfile_credential) == data


def test_ciphertext_is_not_plaintext(keyfile_credential):
    data = b"the quick brown fox" * 50
    blob = _encrypt(data, keyfile_credential)
    assert data not in blob
    assert blob.startswith(crypto.MAGIC)


def test_wrong_passphrase_rejected(fast_scrypt):
    good = crypto.PassphraseCredential("open sesame", fast_scrypt)
    bad = crypto.PassphraseCredential("open sasame", fast_scrypt)
    blob = _encrypt(os.urandom(500), good)
    with pytest.raises(WrongCredentialError):
        _decrypt(blob, bad)


def test_wrong_keyfile_rejected():
    blob = _encrypt(os.urandom(500), crypto.KeyFileCredential(os.urandom(32)))
    with pytest.raises(WrongCredentialError):
        _decrypt(blob, crypto.KeyFileCredential(os.urandom(32)))


def test_body_tamper_detected(keyfile_credential):
    blob = bytearray(_encrypt(os.urandom(1000), keyfile_credential))
    blob[-1] ^= 0x01
    with pytest.raises(IntegrityError):
        _decrypt(bytes(blob), keyfile_credential)


def test_header_tamper_detected(keyfile_credential):
    blob = bytearray(_encrypt(os.urandom(1000), keyfile_credential))
    idx = blob.index(b'"nonce_prefix"')
    blob[idx + 20] ^= 0x01
    with pytest.raises((IntegrityError, UnsupportedFormatError)):
        _decrypt(bytes(blob), keyfile_credential)


def test_truncation_of_final_segment_detected(keyfile_credential):
    blob = _encrypt(os.urandom(5 * SEGMENT), keyfile_credential)
    truncated = blob[: -(SEGMENT + 16)]
    with pytest.raises(IntegrityError):
        _decrypt(truncated, keyfile_credential)


def test_segment_reorder_detected(keyfile_credential):
    blob = _encrypt(os.urandom(3 * SEGMENT), keyfile_credential)
    header = crypto.read_header(io.BytesIO(blob))
    body = blob[header.body_offset :]
    ct_seg = SEGMENT + 16
    seg0, seg1 = body[:ct_seg], body[ct_seg : 2 * ct_seg]
    swapped = blob[: header.body_offset] + seg1 + seg0 + body[2 * ct_seg :]
    with pytest.raises(IntegrityError):
        _decrypt(swapped, keyfile_credential)


def test_appended_segment_detected(keyfile_credential):
    blob = _encrypt(os.urandom(2 * SEGMENT), keyfile_credential)
    with pytest.raises(IntegrityError):
        _decrypt(blob + os.urandom(SEGMENT + 16), keyfile_credential)


def test_not_a_container():
    with pytest.raises(UnsupportedFormatError):
        crypto.read_header(io.BytesIO(b"just some bytes, not a container at all"))


def test_key_id_is_stable_and_distinct():
    key = os.urandom(32)
    assert crypto.key_fingerprint(key) == crypto.key_fingerprint(key)
    assert crypto.key_fingerprint(key) != crypto.key_fingerprint(os.urandom(32))
    assert len(crypto.key_fingerprint(key)) == 16


def test_header_reports_credential_type(passphrase_credential, keyfile_credential):
    pp = crypto.read_header(io.BytesIO(_encrypt(b"x", passphrase_credential)))
    kf = crypto.read_header(io.BytesIO(_encrypt(b"x", keyfile_credential)))
    assert pp.is_passphrase and pp.kdf is not None
    assert kf.is_keyfile and kf.kdf is None
    assert kf.key_id == keyfile_credential.key_id


def test_streaming_uses_bounded_memory(keyfile_credential):
    """Encryption must not slurp the whole input; it reads a segment at a time."""

    reads: list[int] = []

    class SpyReader(io.RawIOBase):
        def __init__(self, data):
            self._buf = io.BytesIO(data)

        def readable(self):
            return True

        def read(self, size=-1):
            chunk = self._buf.read(size)
            reads.append(len(chunk))
            return chunk

    data = os.urandom(10 * SEGMENT)
    out = io.BytesIO()
    crypto.encrypt_stream(SpyReader(data), out, keyfile_credential, segment_size=SEGMENT)
    assert max(reads) <= SEGMENT
    assert _decrypt(out.getvalue(), keyfile_credential) == data


def test_file_helpers_are_atomic_on_failure(tmp_path, keyfile_credential):
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(2000))
    enc = tmp_path / "in.bin.mcz"
    crypto.encrypt_file(src, enc, keyfile_credential)

    blob = bytearray(enc.read_bytes())
    blob[-1] ^= 0xFF
    enc.write_bytes(bytes(blob))

    dst = tmp_path / "out.bin"
    with pytest.raises(IntegrityError):
        crypto.decrypt_file(enc, dst, keyfile_credential)
    assert not dst.exists()
    assert not any(p.name.startswith(".out.bin") for p in tmp_path.iterdir())


def test_legacy_fernet_decrypt(tmp_path):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    token = Fernet(key).encrypt(b"legacy memocry payload")
    out = io.BytesIO()
    crypto.decrypt_legacy_stream(io.BytesIO(token), out, key)
    assert out.getvalue() == b"legacy memocry payload"

    with pytest.raises(IntegrityError):
        crypto.decrypt_legacy_stream(io.BytesIO(token), io.BytesIO(), Fernet.generate_key())
