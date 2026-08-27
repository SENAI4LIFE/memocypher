"""Key file format, key generation and key discovery.

A memocypher key file (``.mckey``) is small, UTF-8 and human-inspectable::

    memocypher-key/1
    id: 131c2d63fb4ed5f1
    key: 6Jr0k... (base64url, no padding, decodes to 32 bytes)
    created: 2026-08-26T09:41:00Z
    label: family photos

The ``id`` is a fingerprint of the key bytes. It is written into every
container that key encrypts, so :class:`KeyStore` can point you straight at the
right key file instead of making you guess.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from . import fsops
from .crypto import KeyFileCredential, key_fingerprint
from .errors import KeyFileError

_MAGIC_LINE = "memocypher-key/1"
_KEY_BYTES = 32


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


@dataclass(frozen=True)
class KeyRef:
    path: Path
    key_id: str | None
    label: str = ""
    created: str = ""
    kind: str = "memocypher"
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def display_name(self) -> str:
        return self.label or self.path.name


def generate_key_bytes() -> bytes:
    return os.urandom(_KEY_BYTES)


def write_keyfile(
    path: Path,
    key_bytes: bytes,
    *,
    label: str = "",
    overwrite: bool = False,
) -> KeyRef:
    """Write ``key_bytes`` to ``path`` as a ``.mckey`` file (mode 0600 on POSIX)."""

    if len(key_bytes) != _KEY_BYTES:
        raise KeyFileError(f"Key must be {_KEY_BYTES} bytes, got {len(key_bytes)}.")
    path = Path(path)
    if path.suffix != fsops.KEYFILE_SUFFIX:
        path = path.with_name(path.name + fsops.KEYFILE_SUFFIX)
    created = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    key_id = key_fingerprint(key_bytes)
    lines = [
        _MAGIC_LINE,
        f"id: {key_id}",
        f"key: {_b64u_encode(key_bytes)}",
        f"created: {created}",
    ]
    if label:
        lines.append(f"label: {label}")
    body = ("\n".join(lines) + "\n").encode("utf-8")
    with fsops.atomic_writer(path, mode=0o600, overwrite=overwrite) as fh:
        fh.write(body)
    return KeyRef(path=path, key_id=key_id, label=label, created=created)


def generate_keyfile(path: Path, *, label: str = "", overwrite: bool = False) -> KeyRef:
    return write_keyfile(path, generate_key_bytes(), label=label, overwrite=overwrite)


def _parse_keyfile_text(text: str) -> dict:
    fields: dict[str, str] = {}
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines or not lines[0].startswith("memocypher-key/"):
        raise KeyFileError("Missing 'memocypher-key/1' header line.")
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip().lower()] = value.strip()
    if "key" not in fields:
        raise KeyFileError("No 'key:' line found.")
    return fields


def load_key_bytes(path: Path) -> bytes:
    """Read and validate the 32-byte key from a ``.mckey`` file."""

    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise KeyFileError(f"Cannot read key file: {exc}") from exc
    fields = _parse_keyfile_text(text)
    try:
        key_bytes = _b64u_decode(fields["key"])
    except (ValueError, binascii.Error) as exc:
        raise KeyFileError("The 'key:' value is not valid base64.") from exc
    if len(key_bytes) != _KEY_BYTES:
        raise KeyFileError(f"Key must decode to {_KEY_BYTES} bytes, got {len(key_bytes)}.")
    stated = fields.get("id")
    actual = key_fingerprint(key_bytes)
    if stated and stated.lower() != actual:
        raise KeyFileError(
            f"Key file is inconsistent: states id {stated} but the key fingerprints to {actual}."
        )
    return key_bytes


def load_credential(path: Path) -> KeyFileCredential:
    return KeyFileCredential(load_key_bytes(path), source=Path(path))


def read_key_ref(path: Path) -> KeyRef:
    """Metadata for a key file; never raises, records the problem in ``error``."""

    path = Path(path)
    name = path.name.lower()
    if name.endswith(fsops.KEYFILE_SUFFIX):
        try:
            text = path.read_text(encoding="utf-8")
            fields = _parse_keyfile_text(text)
            key_bytes = _b64u_decode(fields["key"])
            key_id = key_fingerprint(key_bytes)
            if fields.get("id") and fields["id"].lower() != key_id:
                return KeyRef(path, key_id, error="stated id does not match key")
            return KeyRef(
                path,
                key_id,
                label=fields.get("label", ""),
                created=fields.get("created", ""),
            )
        except (OSError, KeyFileError, ValueError) as exc:
            return KeyRef(path, None, error=str(exc))
    try:
        raw = path.read_bytes().strip()
        base64.urlsafe_b64decode(raw)
        return KeyRef(path, None, kind="legacy-fernet")
    except (OSError, ValueError) as exc:
        return KeyRef(path, None, kind="legacy-fernet", error=str(exc))


def load_legacy_fernet_key(path: Path) -> bytes:
    return Path(path).read_bytes().strip()


_PRUNE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".tox"}


class KeyStore:
    """Index of key files found under one or more directories.

    Each root remembers whether it should be walked recursively. Recursion
    prunes well-known heavy directories and stops after ``max_files`` entries
    so pointing it at a large tree cannot wedge the app.
    """

    def __init__(self, roots: Iterable[Path] = (), *, recursive: bool = True):
        self._roots: list[tuple[Path, bool]] = []
        for root in roots:
            self.add_root(root, recursive=recursive)
        self._refs: list[KeyRef] = []

    def add_root(self, root: Path, *, recursive: bool = True) -> None:
        resolved = Path(root).expanduser().resolve()
        if all(existing != resolved for existing, _ in self._roots):
            self._roots.append((resolved, recursive))

    def scan(self, *, recursive: bool | None = None, max_files: int = 50_000) -> list[KeyRef]:
        seen: set[Path] = set()
        refs: list[KeyRef] = []
        budget = max_files
        for root, root_recursive in self._roots:
            if not root.is_dir():
                continue
            walk = root_recursive if recursive is None else recursive
            for candidate in self._iter(root, walk):
                budget -= 1
                if budget <= 0:
                    break
                if not fsops.is_keyfile_name(candidate) or not candidate.is_file():
                    continue
                resolved = candidate.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                refs.append(read_key_ref(candidate))
        refs.sort(key=lambda r: (r.kind != "memocypher", r.display_name.lower()))
        self._refs = refs
        return refs

    @staticmethod
    def _iter(root: Path, recursive: bool):
        if not recursive:
            try:
                yield from root.iterdir()
            except OSError:
                return
            return
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                entries = list(current.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_dir():
                    if entry.name not in _PRUNE_DIRS and not entry.is_symlink():
                        stack.append(entry)
                else:
                    yield entry

    def match(self, key_id: str) -> list[KeyRef]:
        return [r for r in self._refs if r.key_id == key_id]
