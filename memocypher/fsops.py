"""Filesystem operations: atomic writes, collision handling, path checks.

The rules here exist so the rest of the program never has to think about
half-written files or accidental overwrites:

* Every write goes to a temporary file in the same directory and is renamed
  into place only after it is fully written and flushed. A crash leaves the
  destination either absent or complete, never truncated.
* Nothing is overwritten unless the caller explicitly asks for it. The
  default :data:`CollisionPolicy.ERROR` refuses; :data:`RENAME` picks the next
  free ``name (2).ext`` style name; ``OVERWRITE`` and ``SKIP`` are opt-in.
"""

from __future__ import annotations

import contextlib
import enum
import os
import sys
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path

from .errors import CollisionError, MemocypherError

CONTAINER_SUFFIX = ".mcz"
KEYFILE_SUFFIX = ".mckey"
LEGACY_CONTAINER_SUFFIXES = (".enc",)
LEGACY_KEYFILE_SUFFIXES = (".key",)


class CollisionPolicy(str, enum.Enum):
    ERROR = "error"
    RENAME = "rename"
    OVERWRITE = "overwrite"
    SKIP = "skip"


# --------------------------------------------------------------------------- #
# Atomic writing
# --------------------------------------------------------------------------- #
@contextlib.contextmanager
def atomic_writer(
    path: Path, *, mode: int | None = None, overwrite: bool = True
) -> Iterator[_AtomicFile]:
    """Context manager yielding a binary file that atomically replaces ``path``.

    On a clean exit the temp file is flushed, fsynced and renamed onto ``path``.
    On any exception the temp file is removed and ``path`` is left untouched.
    """

    path = Path(path)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".part", dir=directory)
    tmp_path = Path(tmp_name)
    handle = _AtomicFile(os.fdopen(fd, "wb"))
    try:
        yield handle
        handle.flush_and_sync()
        handle.close()
        if mode is not None and os.name == "posix":
            os.chmod(tmp_path, mode)
        if not overwrite and path.exists():
            raise CollisionError(path)
        os.replace(tmp_path, path)
        _fsync_dir(directory)
    except BaseException:
        handle.close()
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


class _AtomicFile:
    """Thin wrapper that also fsyncs on request."""

    def __init__(self, fh):
        self._fh = fh

    def write(self, data) -> int:
        return self._fh.write(data)

    def flush_and_sync(self) -> None:
        self._fh.flush()
        with contextlib.suppress(OSError):
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._fh.close()


def _fsync_dir(directory: Path) -> None:
    if os.name != "posix":
        return
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


# --------------------------------------------------------------------------- #
# Collision resolution
# --------------------------------------------------------------------------- #
def resolve_collision(path: Path, policy: CollisionPolicy) -> Path | None:
    """Return the path to write, or ``None`` when the policy says to skip.

    Raises :class:`CollisionError` for :data:`CollisionPolicy.ERROR`.
    """

    path = Path(path)
    if not path.exists():
        return path
    if policy is CollisionPolicy.OVERWRITE:
        return path
    if policy is CollisionPolicy.SKIP:
        return None
    if policy is CollisionPolicy.ERROR:
        raise CollisionError(path)
    if policy is CollisionPolicy.RENAME:
        return first_free_name(path, lambda p: p.exists())
    raise MemocypherError(f"Unknown collision policy: {policy!r}")


def iter_name_candidates(path: Path) -> Iterator[Path]:
    """Yield ``path``, then ``name (2).ext``, ``name (3).ext``, ... forever."""

    path = Path(path)
    yield path
    stem, suffix = _split_compound_suffix(path)
    counter = 2
    while True:
        yield path.with_name(f"{stem} ({counter}){suffix}")
        counter += 1


def first_free_name(path: Path, taken: Callable[[Path], bool], *, limit: int = 10_000) -> Path:
    """Return the first candidate name for which ``taken`` is False."""

    for offset, candidate in enumerate(iter_name_candidates(path)):
        if not taken(candidate):
            return candidate
        if offset > limit:
            break
    raise MemocypherError(f"Could not find a free name near {path}")


def _split_compound_suffix(path: Path) -> tuple[str, str]:
    """Split ``archive.tar.gz`` into ``('archive', '.tar.gz')`` for known pairs."""

    name = path.name
    for suffix in (CONTAINER_SUFFIX, *LEGACY_CONTAINER_SUFFIXES):
        if name.endswith(suffix) and len(name) > len(suffix):
            inner = name[: -len(suffix)]
            base, dot, ext = inner.rpartition(".")
            if dot:
                return base, f".{ext}{suffix}"
            return inner, suffix
    p = Path(name)
    return p.stem, p.suffix


# --------------------------------------------------------------------------- #
# Output naming
# --------------------------------------------------------------------------- #
def encrypted_name(source: Path) -> str:
    return f"{Path(source).name}{CONTAINER_SUFFIX}"


def decrypted_name(container: Path) -> str:
    """Best guess at the original name for a decrypted container."""

    name = Path(container).name
    for suffix in (CONTAINER_SUFFIX, *LEGACY_CONTAINER_SUFFIXES):
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return f"{Path(container).stem or name}.decrypted"


def is_container_name(path: Path) -> bool:
    name = Path(path).name.lower()
    return name.endswith(CONTAINER_SUFFIX) or any(
        name.endswith(s) for s in LEGACY_CONTAINER_SUFFIXES
    )


def is_keyfile_name(path: Path) -> bool:
    name = Path(path).name.lower()
    return name.endswith(KEYFILE_SUFFIX) or any(
        name.endswith(s) for s in LEGACY_KEYFILE_SUFFIXES
    )


# --------------------------------------------------------------------------- #
# Path validation
# --------------------------------------------------------------------------- #
def validate_source_file(path: Path) -> Path:
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        raise MemocypherError(f"File does not exist: {resolved}")
    if not resolved.is_file():
        raise MemocypherError(f"Not a regular file: {resolved}")
    if not os.access(resolved, os.R_OK):
        raise MemocypherError(f"File is not readable: {resolved}")
    return resolved


def validate_target_dir(path: Path) -> Path:
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        raise MemocypherError(f"Directory does not exist: {resolved}")
    if not resolved.is_dir():
        raise MemocypherError(f"Not a directory: {resolved}")
    if not os.access(resolved, os.W_OK):
        raise MemocypherError(f"Directory is not writable: {resolved}")
    return resolved


def is_within(path: Path, root: Path) -> bool:
    """True if ``path`` is ``root`` or lives underneath it (after resolving)."""

    try:
        Path(path).expanduser().resolve().relative_to(Path(root).expanduser().resolve())
        return True
    except ValueError:
        return False


_SYSTEM_PREFIXES: tuple[Path, ...]
if sys.platform.startswith("win"):
    _SYSTEM_PREFIXES = (
        Path(os.environ.get("SystemRoot", r"C:\Windows")),  # noqa: SIM112 - real var name
        Path(r"C:\Program Files"),
        Path(r"C:\Program Files (x86)"),
    )
else:
    _SYSTEM_PREFIXES = tuple(
        Path(p) for p in ("/bin", "/sbin", "/usr", "/etc", "/boot", "/sys", "/proc", "/dev", "/lib", "/lib64")
    )


def looks_like_system_path(path: Path) -> bool:
    """Advisory only: is this path under a well-known OS directory?

    Used to warn before encrypting something that would break the machine. It
    is a courtesy check, not a security boundary.
    """

    try:
        resolved = Path(path).expanduser().resolve()
    except OSError:
        return False
    return any(is_within(resolved, prefix) for prefix in _SYSTEM_PREFIXES)


# --------------------------------------------------------------------------- #
# Deletion
# --------------------------------------------------------------------------- #
def delete_file(path: Path) -> None:
    """Delete a file with a normal unlink.

    memocypher does not offer a "secure wipe": on SSDs, wear levelling and
    over-provisioning, and on journaling or copy-on-write filesystems the
    snapshotting layer, mean overwriting a file's visible blocks does not
    reliably erase the underlying data. Full-disk encryption is the dependable
    way to protect data at rest, so that is what the docs recommend instead.
    """

    p = Path(path)
    if p.is_file() or p.is_symlink():
        p.unlink()
