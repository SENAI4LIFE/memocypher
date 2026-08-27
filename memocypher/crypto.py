"""Authenticated streaming encryption for memocypher.

Container layout (``memocypher/1``)::

    magic        8 bytes   b"MCYPHER1"
    header_len   2 bytes   big-endian uint16, length of the JSON header
    header       N bytes   UTF-8 JSON, see ``ContainerHeader``
    body         ...       AES-256-GCM-HKDF-STREAM segments

The body is a STREAM construction (the scheme used by Tink and age): a fresh
256-bit content key is derived per file with HKDF-SHA256, the file is split
into fixed-size segments, and each segment is sealed with AES-256-GCM under a
nonce built from a random per-file prefix, the segment index, and a
"final segment" flag. That flag, combined with the positional segment index,
makes truncation, reordering and extension of the ciphertext detectable:
tampering fails authentication and no plaintext is written.

Two credential types feed the master key:

* :class:`PassphraseCredential` - scrypt(passphrase, per-file salt).
* :class:`KeyFileCredential`   - 32 raw bytes from a ``.mckey`` file.

Nothing in this module touches the filesystem beyond the file objects handed
to it; path handling, collisions and atomic replacement live in
:mod:`memocypher.fsops`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import (
    CancelledError,
    IntegrityError,
    MemocypherError,
    UnsupportedFormatError,
    WrongCredentialError,
)

MAGIC = b"MCYPHER1"
FORMAT_VERSION = 1

# Plaintext bytes per STREAM segment. 1 MiB keeps peak memory to a few MiB
# regardless of file size while adding only 16 bytes of tag per segment.
DEFAULT_SEGMENT_SIZE = 1024 * 1024
_TAG_LEN = 16
_KEY_LEN = 32
_HKDF_SALT_LEN = 16
_NONCE_PREFIX_LEN = 7
_MAX_HEADER_LEN = 8192
_KEY_ID_LEN = 16  # hex characters

ProgressFn = Callable[[int], None]
CancelFn = Callable[[], bool]


# --------------------------------------------------------------------------- #
# Key derivation parameters
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ScryptParams:
    """scrypt cost parameters, stored per file so they can be raised later."""

    n: int = 1 << 17
    r: int = 8
    p: int = 1

    def to_dict(self) -> dict:
        return {"algo": "scrypt", "n": self.n, "r": self.r, "p": self.p}

    @classmethod
    def from_dict(cls, data: dict) -> ScryptParams:
        if data.get("algo") != "scrypt":
            raise UnsupportedFormatError(f"Unknown KDF: {data.get('algo')!r}")
        try:
            return cls(n=int(data["n"]), r=int(data["r"]), p=int(data["p"]))
        except (KeyError, ValueError, TypeError) as exc:
            raise UnsupportedFormatError("Malformed KDF parameters") from exc

    def derive(self, passphrase: str, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=_KEY_LEN, n=self.n, r=self.r, p=self.p).derive(
            passphrase.encode("utf-8")
        )


DEFAULT_SCRYPT = ScryptParams()


def key_fingerprint(key_bytes: bytes) -> str:
    """Stable short identifier for raw key material (``_KEY_ID_LEN`` hex chars)."""

    digest = hashlib.sha256(b"memocypher-key-v1" + key_bytes).hexdigest()
    return digest[:_KEY_ID_LEN]


def format_key_id(key_id: str) -> str:
    """Group a key id into 4-char blocks for display, e.g. ``0123 4567 89ab cdef``."""

    return " ".join(key_id[i : i + 4] for i in range(0, len(key_id), 4))


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #
class Credential:
    """Base class: turns a user secret into a 32-byte master key."""

    cred_type: str = ""

    def master_key_for_encrypt(self) -> tuple[bytes, dict]:
        """Return ``(master_key, cred_header_fields)`` for a new container."""

        raise NotImplementedError

    def master_key_for_decrypt(self, header: ContainerHeader) -> bytes:
        """Re-derive the master key for an existing container."""

        raise NotImplementedError


class PassphraseCredential(Credential):
    cred_type = "passphrase"

    def __init__(self, passphrase: str, params: ScryptParams = DEFAULT_SCRYPT):
        if not passphrase:
            raise ValueError("Passphrase must not be empty.")
        self._passphrase = passphrase
        self._params = params

    def master_key_for_encrypt(self) -> tuple[bytes, dict]:
        salt = os.urandom(_HKDF_SALT_LEN)
        master_key = self._params.derive(self._passphrase, salt)
        fields = {
            "cred": self.cred_type,
            "kdf": {**self._params.to_dict(), "salt": _b64(salt)},
        }
        return master_key, fields

    def master_key_for_decrypt(self, header: ContainerHeader) -> bytes:
        if header.kdf is None:
            raise UnsupportedFormatError("Container has no KDF block but a passphrase was given.")
        params = ScryptParams.from_dict(header.kdf)
        salt = _unb64(header.kdf.get("salt", ""))
        master_key = params.derive(self._passphrase, salt)
        expected = _passphrase_key_id(salt, master_key)
        if not _ct_equal(expected, header.key_id):
            raise WrongCredentialError("Incorrect passphrase.")
        return master_key


class KeyFileCredential(Credential):
    cred_type = "keyfile"

    def __init__(self, key_bytes: bytes, source: Path | None = None):
        if len(key_bytes) != _KEY_LEN:
            raise ValueError(f"Key must be exactly {_KEY_LEN} bytes, got {len(key_bytes)}.")
        self._key = bytes(key_bytes)
        self.source = source

    @property
    def key_id(self) -> str:
        return key_fingerprint(self._key)

    def master_key_for_encrypt(self) -> tuple[bytes, dict]:
        return self._key, {"cred": self.cred_type}

    def master_key_for_decrypt(self, header: ContainerHeader) -> bytes:
        if not _ct_equal(self.key_id, header.key_id):
            raise WrongCredentialError(
                "This key file does not match the container "
                f"(container key id {format_key_id(header.key_id)})."
            )
        return self._key


def _passphrase_key_id(salt: bytes, master_key: bytes) -> str:
    digest = hashlib.sha256(b"memocypher-pp-v1" + salt + master_key).hexdigest()
    return digest[:_KEY_ID_LEN]


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
@dataclass
class ContainerHeader:
    version: int
    cred: str
    key_id: str
    segment_size: int
    hkdf_salt: bytes
    nonce_prefix: bytes
    kdf: dict | None = None
    body_offset: int = 0
    aad: bytes = b""

    @property
    def is_passphrase(self) -> bool:
        return self.cred == "passphrase"

    @property
    def is_keyfile(self) -> bool:
        return self.cred == "keyfile"


def _build_header_bytes(
    *,
    cred_fields: dict,
    key_id: str,
    segment_size: int,
    hkdf_salt: bytes,
    nonce_prefix: bytes,
) -> tuple[bytes, bytes]:
    header = {
        "version": FORMAT_VERSION,
        "cred": cred_fields["cred"],
        "key_id": key_id,
        "stream": {
            "algo": "AES-256-GCM-HKDF-STREAM",
            "segment": segment_size,
            "hkdf_salt": _b64(hkdf_salt),
            "nonce_prefix": _b64(nonce_prefix),
        },
    }
    if "kdf" in cred_fields:
        header["kdf"] = cred_fields["kdf"]
    body = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(body) > _MAX_HEADER_LEN:
        raise MemocypherError("Encryption header unexpectedly large.")
    framed = MAGIC + struct.pack(">H", len(body)) + body
    return framed, framed  # framed doubles as HKDF info / AAD


def parse_header(prefix: bytes) -> ContainerHeader:
    """Parse a container header from the leading bytes of a file."""

    if len(prefix) < len(MAGIC) + 2:
        raise UnsupportedFormatError("File is too short to be a memocypher container.")
    if not prefix.startswith(MAGIC):
        raise UnsupportedFormatError("Not a memocypher container (bad magic).")
    (header_len,) = struct.unpack(">H", prefix[len(MAGIC) : len(MAGIC) + 2])
    if header_len == 0 or header_len > _MAX_HEADER_LEN:
        raise UnsupportedFormatError("Container header length is out of range.")
    start = len(MAGIC) + 2
    end = start + header_len
    if len(prefix) < end:
        raise UnsupportedFormatError("Container header is truncated.")
    raw = prefix[start:end]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UnsupportedFormatError("Container header is not valid JSON.") from exc
    try:
        stream = data["stream"]
        header = ContainerHeader(
            version=int(data["version"]),
            cred=str(data["cred"]),
            key_id=str(data["key_id"]),
            segment_size=int(stream["segment"]),
            hkdf_salt=_unb64(stream["hkdf_salt"]),
            nonce_prefix=_unb64(stream["nonce_prefix"]),
            kdf=data.get("kdf"),
            body_offset=end,
            aad=prefix[:end],
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise UnsupportedFormatError("Container header is missing required fields.") from exc
    if header.version != FORMAT_VERSION:
        raise UnsupportedFormatError(f"Unsupported container version {header.version}.")
    if header.cred not in ("passphrase", "keyfile"):
        raise UnsupportedFormatError(f"Unknown credential type {header.cred!r}.")
    if len(header.hkdf_salt) != _HKDF_SALT_LEN or len(header.nonce_prefix) != _NONCE_PREFIX_LEN:
        raise UnsupportedFormatError("Container stream parameters are malformed.")
    if not (0 < header.segment_size <= 64 * 1024 * 1024):
        raise UnsupportedFormatError("Container segment size is out of range.")
    return header


def read_header(source: os.PathLike | str | BinaryIO) -> ContainerHeader:
    """Read just the header of a container, given a path or a binary file object."""

    if hasattr(source, "read"):
        pos = source.tell()
        try:
            source.seek(0)
            prefix = source.read(len(MAGIC) + 2 + _MAX_HEADER_LEN)
        finally:
            source.seek(pos)
        return parse_header(prefix)
    with open(source, "rb") as fh:
        prefix = fh.read(len(MAGIC) + 2 + _MAX_HEADER_LEN)
    return parse_header(prefix)


def looks_like_container(path: os.PathLike | str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# STREAM core
# --------------------------------------------------------------------------- #
def _derive_content_key(master_key: bytes, hkdf_salt: bytes, aad: bytes) -> bytes:
    return HKDF(algorithm=_SHA256(), length=_KEY_LEN, salt=hkdf_salt, info=aad).derive(master_key)


def _segment_nonce(prefix: bytes, index: int, last: bool) -> bytes:
    return prefix + struct.pack(">I", index) + (b"\x01" if last else b"\x00")


def _read_exact(fh: BinaryIO, size: int) -> bytes:
    """Read exactly ``size`` bytes unless EOF is reached first."""

    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = fh.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _check_cancel(cancel: CancelFn | None) -> None:
    if cancel is not None and cancel():
        raise CancelledError("Operation cancelled.")


def encrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    credential: Credential,
    *,
    segment_size: int = DEFAULT_SEGMENT_SIZE,
    progress: ProgressFn | None = None,
    cancel: CancelFn | None = None,
) -> None:
    """Encrypt ``src`` into ``dst`` (both open binary file objects)."""

    if segment_size <= 0:
        raise ValueError("segment_size must be positive.")
    master_key, cred_fields = credential.master_key_for_encrypt()

    hkdf_salt = os.urandom(_HKDF_SALT_LEN)
    nonce_prefix = os.urandom(_NONCE_PREFIX_LEN)

    if cred_fields["cred"] == "passphrase":
        salt = _unb64(cred_fields["kdf"]["salt"])
        key_id = _passphrase_key_id(salt, master_key)
    else:
        key_id = key_fingerprint(master_key)

    framed_header, aad = _build_header_bytes(
        cred_fields=cred_fields,
        key_id=key_id,
        segment_size=segment_size,
        hkdf_salt=hkdf_salt,
        nonce_prefix=nonce_prefix,
    )
    dst.write(framed_header)

    aesgcm = AESGCM(_derive_content_key(master_key, hkdf_salt, aad))

    processed = 0
    index = 0
    current = _read_exact(src, segment_size)
    while True:
        nxt = _read_exact(src, segment_size)
        last = nxt == b""
        nonce = _segment_nonce(nonce_prefix, index, last)
        dst.write(aesgcm.encrypt(nonce, current, None))
        processed += len(current)
        if progress is not None:
            progress(processed)
        _check_cancel(cancel)
        if last:
            break
        index += 1
        current = nxt
        if index >= 2**32 - 1:  # pragma: no cover - 4 PiB at 1 MiB segments
            raise MemocypherError("Input exceeds the maximum supported size.")


def decrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    credential: Credential,
    *,
    progress: ProgressFn | None = None,
    cancel: CancelFn | None = None,
) -> ContainerHeader:
    """Decrypt ``src`` into ``dst``; returns the parsed header on success."""

    prefix = src.read(len(MAGIC) + 2 + _MAX_HEADER_LEN)
    header = parse_header(prefix)
    src.seek(header.body_offset)

    master_key = credential.master_key_for_decrypt(header)
    aesgcm = AESGCM(_derive_content_key(master_key, header.hkdf_salt, header.aad))

    ct_segment = header.segment_size + _TAG_LEN
    processed = 0
    index = 0
    current = _read_exact(src, ct_segment)
    while True:
        nxt = _read_exact(src, ct_segment)
        last = nxt == b""
        if len(current) < _TAG_LEN:
            raise IntegrityError("Ciphertext is truncated or empty.")
        nonce = _segment_nonce(header.nonce_prefix, index, last)
        try:
            plaintext = aesgcm.decrypt(nonce, current, None)
        except InvalidTag as exc:
            raise IntegrityError(
                "Authentication failed: the file was truncated, reordered or modified."
            ) from exc
        dst.write(plaintext)
        processed += len(plaintext)
        if progress is not None:
            progress(processed)
        _check_cancel(cancel)
        if last:
            break
        index += 1
        current = nxt
    return header


# --------------------------------------------------------------------------- #
# Path-level convenience (atomic, never partial)
# --------------------------------------------------------------------------- #
def encrypt_file(
    src: os.PathLike | str,
    dst: os.PathLike | str,
    credential: Credential,
    *,
    segment_size: int = DEFAULT_SEGMENT_SIZE,
    progress: ProgressFn | None = None,
    cancel: CancelFn | None = None,
) -> None:
    from . import fsops

    src = Path(src)
    with open(src, "rb") as fin, fsops.atomic_writer(Path(dst)) as fout:
        encrypt_stream(
            fin, fout, credential, segment_size=segment_size, progress=progress, cancel=cancel
        )


def decrypt_file(
    src: os.PathLike | str,
    dst: os.PathLike | str,
    credential: Credential,
    *,
    progress: ProgressFn | None = None,
    cancel: CancelFn | None = None,
) -> ContainerHeader:
    from . import fsops

    with open(Path(src), "rb") as fin, fsops.atomic_writer(Path(dst)) as fout:
        return decrypt_stream(fin, fout, credential, progress=progress, cancel=cancel)


def decrypt_legacy_file(
    src: os.PathLike | str, dst: os.PathLike | str, fernet_key: bytes
) -> None:
    from . import fsops

    with open(Path(src), "rb") as fin, fsops.atomic_writer(Path(dst)) as fout:
        decrypt_legacy_stream(fin, fout, fernet_key)


# --------------------------------------------------------------------------- #
# Legacy (memocry) Fernet containers
# --------------------------------------------------------------------------- #
def decrypt_legacy_stream(src: BinaryIO, dst: BinaryIO, fernet_key: bytes) -> None:
    """Decrypt a whole-file Fernet blob produced by the original memocry tool.

    Fernet has no streaming mode, so the entire file is loaded into memory.
    """

    from cryptography.fernet import Fernet, InvalidToken

    try:
        fernet = Fernet(fernet_key.strip())
    except Exception as exc:  # noqa: BLE001 - library raises bare ValueError/binascii
        raise WrongCredentialError("Not a valid legacy Fernet key.") from exc
    data = src.read()
    try:
        plaintext = fernet.decrypt(data)
    except InvalidToken as exc:
        raise IntegrityError(
            "Legacy decryption failed: wrong key or the file is corrupted."
        ) from exc
    dst.write(plaintext)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _ct_equal(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a, b)
