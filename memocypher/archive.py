"""Package a directory tree into a single ``.zip`` so it can be encrypted as one
container.

Used only by the "encrypt a folder as one archive" workflow. The zip is written
atomically and, in that workflow, lives in a private temporary directory that is
deleted as soon as the container has been written. It is still an unencrypted
copy on disk for that short window, which the docs call out.
"""

from __future__ import annotations

import os
import zipfile
from collections.abc import Callable
from pathlib import Path

from . import fsops
from .errors import CancelledError

CancelFn = Callable[[], bool]
ProgressFn = Callable[[int], None]


def zip_directory(
    folder: Path,
    dest_zip: Path,
    *,
    cancel: CancelFn | None = None,
    progress: ProgressFn | None = None,
) -> int:
    """Write a deflate zip of ``folder``'s contents to ``dest_zip`` atomically.

    Archive names are relative to ``folder`` so the folder name is not baked in.
    Empty directories are kept. Symlinked directories are not followed. Returns
    the number of files written.
    """

    folder = fsops.validate_source_dir(folder)
    entries: list[tuple[Path, str, bool]] = []
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        dirnames.sort()
        here = Path(dirpath)
        rel = here.relative_to(folder)
        if not filenames and not dirnames and rel != Path("."):
            entries.append((here, f"{rel.as_posix()}/", True))
        for name in sorted(filenames):
            path = here / name
            if path.is_file():
                entries.append((path, (rel / name).as_posix(), False))

    files_total = sum(1 for _, _, is_dir in entries if not is_dir) or 1
    written = 0
    with (
        fsops.atomic_writer(Path(dest_zip)) as raw,
        zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_DEFLATED) as zf,
    ):
        for path, arcname, is_dir in entries:
            if cancel is not None and cancel():
                raise CancelledError("Archiving cancelled.")
            if is_dir:
                zf.writestr(arcname, b"")
                continue
            zf.write(path, arcname)
            written += 1
            if progress is not None:
                progress(int(written / files_total * 100))
    return written
