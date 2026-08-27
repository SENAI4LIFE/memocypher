"""Scan a working directory into the buckets the UI and CLI care about."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from . import fsops
from .crypto import ContainerHeader, read_header
from .errors import MemocypherError
from .keys import KeyRef, KeyStore

_DEFAULT_MAX_ENTRIES = 20_000


@dataclass(frozen=True)
class FileEntry:
    path: Path
    size: int
    modified: float
    kind: str  # "plaintext" | "encrypted" | "keyfile" | "folder"
    # populated for encrypted entries
    container: ContainerHeader | None = None
    container_error: str = ""
    # populated for folder entries
    child_count: int = 0

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def modified_str(self) -> str:
        return _dt.datetime.fromtimestamp(self.modified).strftime("%Y-%m-%d %H:%M")

    @property
    def cred_type(self) -> str:
        if self.container_error:
            return "unreadable"
        if self.container is None:
            return "legacy"
        return self.container.cred

    @property
    def key_id(self) -> str | None:
        return self.container.key_id if self.container else None


@dataclass
class Workspace:
    root: Path
    plaintext: list[FileEntry] = field(default_factory=list)
    encrypted: list[FileEntry] = field(default_factory=list)
    keyfiles: list[FileEntry] = field(default_factory=list)
    folders: list[FileEntry] = field(default_factory=list)
    key_refs: list[KeyRef] = field(default_factory=list)
    truncated: bool = False

    @property
    def all_entries(self) -> list[FileEntry]:
        return [*self.folders, *self.plaintext, *self.encrypted, *self.keyfiles]

    def key_ref_for(self, entry: FileEntry) -> list[KeyRef]:
        if entry.kind != "encrypted" or not entry.key_id:
            return []
        return [r for r in self.key_refs if r.key_id == entry.key_id]

    def filter(self, query: str) -> Workspace:
        q = query.strip().lower()
        if not q:
            return self

        def keep(entry: FileEntry) -> bool:
            return q in entry.name.lower()

        return Workspace(
            root=self.root,
            plaintext=[e for e in self.plaintext if keep(e)],
            encrypted=[e for e in self.encrypted if keep(e)],
            keyfiles=[e for e in self.keyfiles if keep(e)],
            folders=[e for e in self.folders if keep(e)],
            key_refs=self.key_refs,
            truncated=self.truncated,
        )


def scan(
    root: Path,
    *,
    recursive: bool = True,
    key_search_roots: Iterable[Path] = (),
    max_entries: int = _DEFAULT_MAX_ENTRIES,
) -> Workspace:
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise MemocypherError(f"Not a directory: {root}")

    ws = Workspace(root=root)
    count = 0

    for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if child.is_dir():
            try:
                child_files = sum(1 for _ in child.iterdir())
            except OSError:
                child_files = 0
            ws.folders.append(
                FileEntry(child, 0, _safe_mtime(child), "folder", child_count=child_files)
            )

    walker = root.rglob("*") if recursive else root.iterdir()
    for path in walker:
        if not path.is_file():
            continue
        count += 1
        if count > max_entries:
            ws.truncated = True
            break
        try:
            stat = path.stat()
        except OSError:
            continue
        if fsops.is_keyfile_name(path):
            ws.keyfiles.append(
                FileEntry(path, stat.st_size, stat.st_mtime, "keyfile")
            )
        elif fsops.is_container_name(path):
            header: ContainerHeader | None = None
            err = ""
            try:
                header = read_header(path)
            except MemocypherError as exc:
                err = str(exc)
            ws.encrypted.append(
                FileEntry(
                    path,
                    stat.st_size,
                    stat.st_mtime,
                    "encrypted",
                    container=header,
                    container_error=err,
                )
            )
        else:
            ws.plaintext.append(
                FileEntry(path, stat.st_size, stat.st_mtime, "plaintext")
            )

    store = KeyStore()
    store.add_root(root, recursive=recursive)
    for extra in key_search_roots:
        store.add_root(extra, recursive=False)
    ws.key_refs = store.scan()
    return ws


def _safe_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0
