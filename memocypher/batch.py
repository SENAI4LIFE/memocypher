"""Plan and run batches of encrypt / decrypt jobs.

The planner turns a pile of user-selected paths into a concrete list of
:class:`Job` objects with their output paths and collisions already resolved,
plus a list of things that were skipped and why. The runner then executes
jobs one at a time, never aborting the whole batch because one file failed,
and emits events so a GUI can show live progress. :func:`run` is synchronous
(used by the CLI and tests); :class:`BatchRunner` is the threaded wrapper.
"""

from __future__ import annotations

import enum
import queue
import shutil
import tempfile
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from . import archive, crypto, fsops
from .crypto import Credential
from .errors import CancelledError, CollisionError, MemocypherError


class JobKind(str, enum.Enum):
    ENCRYPT = "encrypt"
    ENCRYPT_ARCHIVE = "encrypt-archive"
    DECRYPT = "decrypt"
    DECRYPT_LEGACY = "decrypt-legacy"


class ItemStatus(str, enum.Enum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


@dataclass
class Job:
    kind: JobKind
    src: Path
    dst: Path
    credential: Credential | None = None
    legacy_key: bytes | None = None
    delete_source: bool = False
    total_bytes: int = 0


@dataclass
class ItemResult:
    job: Job
    status: ItemStatus
    message: str = ""
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status is ItemStatus.OK


@dataclass
class Skipped:
    path: Path
    reason: str
    collision: bool = False


@dataclass
class BatchSummary:
    results: list[ItemResult] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    elapsed: float = 0.0
    cancelled: bool = False

    @property
    def ok_count(self) -> int:
        return sum(1 for r in self.results if r.status is ItemStatus.OK)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if r.status is ItemStatus.FAILED)

    @property
    def cancelled_count(self) -> int:
        return sum(1 for r in self.results if r.status is ItemStatus.CANCELLED)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped) + sum(
            1 for r in self.results if r.status is ItemStatus.SKIPPED
        )

    @property
    def success(self) -> bool:
        return self.failed_count == 0 and not self.cancelled


@dataclass
class BatchStarted:
    total: int


@dataclass
class ItemStarted:
    index: int
    job: Job


@dataclass
class ItemProgress:
    index: int
    job: Job
    done_bytes: int
    total_bytes: int


@dataclass
class ItemFinished:
    index: int
    job: Job
    result: ItemResult


@dataclass
class BatchFinished:
    summary: BatchSummary


Event = BatchStarted | ItemStarted | ItemProgress | ItemFinished | BatchFinished
EventFn = Callable[[Event], None]


def plan_encrypt(
    sources: Iterable[Path],
    credential: Credential,
    *,
    out_dir: Path | None = None,
    collision: fsops.CollisionPolicy = fsops.CollisionPolicy.ERROR,
    delete_source: bool = False,
) -> tuple[list[Job], list[Skipped]]:
    """Turn files and directories into encrypt jobs.

    A file becomes ``name.mcz``. A directory becomes a single
    ``name.zip.mcz`` archive job (the CLI's ``-r`` flag expands the directory
    to individual files before it gets here).
    """

    jobs: list[Job] = []
    skipped: list[Skipped] = []
    planned_outputs: set[Path] = set()
    for raw in sources:
        src = Path(raw)
        is_dir = src.is_dir()
        try:
            src = fsops.validate_source_dir(src) if is_dir else fsops.validate_source_file(src)
        except MemocypherError as exc:
            skipped.append(Skipped(src, str(exc)))
            continue

        target_dir = Path(out_dir).expanduser().resolve() if out_dir else src.parent
        if is_dir:
            desired = target_dir / f"{src.name}.zip{fsops.CONTAINER_SUFFIX}"
        else:
            desired = target_dir / fsops.encrypted_name(src)

        final = _resolve(desired, collision, planned_outputs, skipped, src)
        if final is None:
            continue
        planned_outputs.add(final)
        jobs.append(
            Job(
                kind=JobKind.ENCRYPT_ARCHIVE if is_dir else JobKind.ENCRYPT,
                src=src,
                dst=final,
                credential=credential,
                delete_source=delete_source and not is_dir,
                total_bytes=_tree_size(src) if is_dir else src.stat().st_size,
            )
        )
    return jobs, skipped


def _tree_size(folder: Path, *, cap: int = 200_000) -> int:
    total = 0
    for i, path in enumerate(folder.rglob("*")):
        if i >= cap:
            break
        try:
            if path.is_file():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def plan_decrypt(
    sources: Iterable[Path],
    credential: Credential | None,
    *,
    out_dir: Path | None = None,
    collision: fsops.CollisionPolicy = fsops.CollisionPolicy.ERROR,
    delete_source: bool = False,
    legacy_key: bytes | None = None,
) -> tuple[list[Job], list[Skipped]]:
    jobs: list[Job] = []
    skipped: list[Skipped] = []
    planned_outputs: set[Path] = set()
    for raw in sources:
        src = Path(raw)
        try:
            src = fsops.validate_source_file(src)
        except MemocypherError as exc:
            skipped.append(Skipped(src, str(exc)))
            continue

        target_dir = Path(out_dir).expanduser().resolve() if out_dir else src.parent
        desired = target_dir / fsops.decrypted_name(src)

        if crypto.looks_like_container(src):
            if credential is None:
                skipped.append(Skipped(src, "no passphrase or key file supplied"))
                continue
            try:
                header = crypto.read_header(src)
            except MemocypherError as exc:
                skipped.append(Skipped(src, f"unreadable container: {exc}"))
                continue
            if header.cred != credential.cred_type:
                skipped.append(
                    Skipped(src, f"needs a {header.cred} credential, got {credential.cred_type}")
                )
                continue
            final = _resolve(desired, collision, planned_outputs, skipped, src)
            if final is None:
                continue
            planned_outputs.add(final)
            jobs.append(
                Job(
                    kind=JobKind.DECRYPT,
                    src=src,
                    dst=final,
                    credential=credential,
                    delete_source=delete_source,
                    total_bytes=src.stat().st_size,
                )
            )
        else:
            if legacy_key is None:
                skipped.append(
                    Skipped(src, "legacy whole-file .enc container; pass a legacy .key")
                )
                continue
            final = _resolve(desired, collision, planned_outputs, skipped, src)
            if final is None:
                continue
            planned_outputs.add(final)
            jobs.append(
                Job(
                    kind=JobKind.DECRYPT_LEGACY,
                    src=src,
                    dst=final,
                    legacy_key=legacy_key,
                    delete_source=delete_source,
                    total_bytes=src.stat().st_size,
                )
            )
    return jobs, skipped


def _resolve(
    desired: Path,
    policy: fsops.CollisionPolicy,
    planned_outputs: set[Path],
    skipped: list[Skipped],
    src: Path,
) -> Path | None:
    """Resolve a collision against both the disk and earlier jobs in this batch."""

    def taken(path: Path) -> bool:
        return path.exists() or path in planned_outputs

    if desired in planned_outputs and policy is not fsops.CollisionPolicy.RENAME:
        skipped.append(
            Skipped(src, f"another file already targets {desired.name}", collision=True)
        )
        return None

    try:
        resolved = fsops.resolve_collision(desired, policy, taken=taken)
    except MemocypherError as exc:
        collision = isinstance(exc, CollisionError)
        reason = f"output already exists: {desired.name}" if collision else str(exc)
        skipped.append(Skipped(src, reason, collision=collision))
        return None
    if resolved is None:
        skipped.append(Skipped(src, f"skipped, output exists: {desired.name}", collision=True))
    return resolved


def run(
    jobs: list[Job],
    *,
    on_event: EventFn | None = None,
    cancel_check: Callable[[], bool] | None = None,
    skipped: list[Skipped] | None = None,
) -> BatchSummary:
    emit = on_event or (lambda _e: None)
    summary = BatchSummary(skipped=list(skipped or []))
    started = time.perf_counter()
    emit(BatchStarted(total=len(jobs)))

    stop = False
    for index, job in enumerate(jobs):
        if stop or (cancel_check and cancel_check()):
            result = ItemResult(job, ItemStatus.CANCELLED, "cancelled")
            summary.results.append(result)
            summary.cancelled = True
            emit(ItemFinished(index, job, result))
            continue
        emit(ItemStarted(index, job))
        result = _run_one(job, index, emit, cancel_check)
        if result.status is ItemStatus.CANCELLED:
            summary.cancelled = True
            stop = True
        summary.results.append(result)
        emit(ItemFinished(index, job, result))

    summary.elapsed = time.perf_counter() - started
    emit(BatchFinished(summary))
    return summary


def _run_one(job: Job, index: int, emit: EventFn, cancel_check) -> ItemResult:
    started = time.perf_counter()

    def progress(done: int) -> None:
        emit(ItemProgress(index, job, min(done, job.total_bytes or done), job.total_bytes))

    try:
        _execute(job, progress, cancel_check)
    except CancelledError:
        return ItemResult(job, ItemStatus.CANCELLED, "cancelled")
    except MemocypherError as exc:
        return ItemResult(job, ItemStatus.FAILED, str(exc))
    except OSError as exc:
        return ItemResult(job, ItemStatus.FAILED, f"filesystem error: {exc}")
    except Exception as exc:  # noqa: BLE001 - last-resort guard for the batch
        return ItemResult(job, ItemStatus.FAILED, f"unexpected error: {exc!r}")

    elapsed = time.perf_counter() - started
    if job.delete_source:
        try:
            fsops.delete_file(job.src)
        except OSError as exc:
            return ItemResult(
                job, ItemStatus.OK, f"done, but could not delete source: {exc}", elapsed
            )
    return ItemResult(job, ItemStatus.OK, elapsed=elapsed)


def _execute(job: Job, progress, cancel_check) -> None:
    cancel = cancel_check if cancel_check else None
    if job.kind is JobKind.ENCRYPT:
        crypto.encrypt_file(job.src, job.dst, job.credential, progress=progress, cancel=cancel)
    elif job.kind is JobKind.ENCRYPT_ARCHIVE:
        _execute_archive(job, progress, cancel)
    elif job.kind is JobKind.DECRYPT:
        crypto.decrypt_file(job.src, job.dst, job.credential, progress=progress, cancel=cancel)
    elif job.kind is JobKind.DECRYPT_LEGACY:
        crypto.decrypt_legacy_file(job.src, job.dst, job.legacy_key)
    else:  # pragma: no cover
        raise MemocypherError(f"Unknown job kind: {job.kind}")


def _execute_archive(job: Job, progress, cancel) -> None:
    """Zip the folder into a private temp file, encrypt it, then delete the zip."""

    tmp_dir = Path(tempfile.mkdtemp(prefix="memocypher-arc-"))
    try:
        zip_path = tmp_dir / f"{job.src.name}.zip"
        archive.zip_directory(job.src, zip_path, cancel=cancel)
        if cancel is not None and cancel():
            raise CancelledError("Operation cancelled.")
        job.total_bytes = zip_path.stat().st_size
        crypto.encrypt_file(zip_path, job.dst, job.credential, progress=progress, cancel=cancel)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


class BatchRunner:
    """Run a batch on a worker thread, delivering events through a queue."""

    def __init__(self, jobs: list[Job], *, skipped: list[Skipped] | None = None):
        self._jobs = jobs
        self._skipped = skipped or []
        self.events: queue.Queue[Event] = queue.Queue()
        self._cancel = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self.summary: BatchSummary | None = None

    def start(self) -> None:
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def _worker(self) -> None:
        self.summary = run(
            self._jobs,
            on_event=self.events.put,
            cancel_check=self._cancel.is_set,
            skipped=self._skipped,
        )
