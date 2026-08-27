from __future__ import annotations

import os
import zipfile

from memocypher import batch, crypto, fsops
from memocypher.batch import ItemFinished, ItemStatus, JobKind


def _sources(tmp_path, n=3):
    paths = []
    for i in range(n):
        p = tmp_path / f"f{i}.dat"
        p.write_bytes(os.urandom(1000 + i))
        paths.append(p)
    return paths


def test_encrypt_then_decrypt_roundtrip(tmp_path, keyfile_credential):
    sources = _sources(tmp_path)
    originals = {p.name: p.read_bytes() for p in sources}

    jobs, skipped = batch.plan_encrypt(sources, keyfile_credential, out_dir=tmp_path / "enc")
    assert not skipped
    summary = batch.run(jobs)
    assert summary.success and summary.ok_count == 3

    containers = sorted((tmp_path / "enc").glob("*.mcz"))
    djobs, dskipped = batch.plan_decrypt(
        containers, keyfile_credential, out_dir=tmp_path / "dec"
    )
    assert not dskipped
    dsummary = batch.run(djobs)
    assert dsummary.success

    for name, data in originals.items():
        assert (tmp_path / "dec" / name).read_bytes() == data


def test_delete_source_only_on_success(tmp_path, keyfile_credential):
    sources = _sources(tmp_path, 2)
    jobs, _ = batch.plan_encrypt(
        sources, keyfile_credential, out_dir=tmp_path / "enc", delete_source=True
    )
    batch.run(jobs)
    for p in sources:
        assert not p.exists()


def test_one_failure_does_not_abort_batch(tmp_path, keyfile_credential):
    good = tmp_path / "good.mcz"
    crypto.encrypt_file(_sources(tmp_path, 1)[0], good, keyfile_credential)
    bad = tmp_path / "bad.mcz"
    bad.write_bytes(crypto.MAGIC + b"\x00\x04junk")

    jobs, _ = batch.plan_decrypt([good, bad], keyfile_credential, out_dir=tmp_path / "out")
    summary = batch.run(jobs)
    assert summary.ok_count == 1


def test_wrong_credential_fails_that_item_only(tmp_path):
    cred_a = crypto.KeyFileCredential(os.urandom(32))
    cred_b = crypto.KeyFileCredential(os.urandom(32))
    src = _sources(tmp_path, 1)[0]
    enc = tmp_path / "x.mcz"
    crypto.encrypt_file(src, enc, cred_a)

    jobs, _ = batch.plan_decrypt([enc], cred_b, out_dir=tmp_path / "out")
    summary = batch.run(jobs)
    assert summary.failed_count == 1
    assert not (tmp_path / "out" / "x").exists()


def test_collision_error_is_reported_as_skip(tmp_path, keyfile_credential):
    src = _sources(tmp_path, 1)[0]
    (tmp_path / "f0.dat.mcz").write_bytes(b"already here")
    jobs, skipped = batch.plan_encrypt([src], keyfile_credential)
    assert not jobs
    assert skipped and skipped[0].collision
    non_collision = batch.plan_encrypt([tmp_path / "missing.txt"], keyfile_credential)[1]
    assert non_collision and not non_collision[0].collision


def test_collision_rename_in_plan(tmp_path, keyfile_credential):
    src = _sources(tmp_path, 1)[0]
    (tmp_path / "f0.dat.mcz").write_bytes(b"already here")
    jobs, skipped = batch.plan_encrypt(
        [src], keyfile_credential, collision=fsops.CollisionPolicy.RENAME
    )
    assert not skipped
    assert jobs[0].dst.name == "f0 (2).dat.mcz"


def test_two_inputs_same_output_name_do_not_both_win(tmp_path, keyfile_credential):
    a = tmp_path / "a" / "dup.txt"
    b = tmp_path / "b" / "dup.txt"
    a.parent.mkdir()
    b.parent.mkdir()
    a.write_text("A")
    b.write_text("B")
    jobs, skipped = batch.plan_encrypt(
        [a, b], keyfile_credential, out_dir=tmp_path / "out",
        collision=fsops.CollisionPolicy.RENAME,
    )
    dests = {j.dst.name for j in jobs}
    assert dests == {"dup.txt.mcz", "dup (2).txt.mcz"}


def test_cancel_stops_remaining_jobs(tmp_path, keyfile_credential):
    sources = _sources(tmp_path, 5)
    jobs, _ = batch.plan_encrypt(sources, keyfile_credential, out_dir=tmp_path / "enc")

    calls = {"n": 0}

    def cancel_after_two():
        calls["n"] += 1
        return calls["n"] > 2

    finished: list = []
    summary = batch.run(
        jobs,
        cancel_check=cancel_after_two,
        on_event=lambda e: finished.append(e) if isinstance(e, ItemFinished) else None,
    )
    assert summary.cancelled
    assert summary.cancelled_count >= 1
    assert summary.ok_count < 5
    assert len(finished) == len(jobs)
    assert any(f.result.status is ItemStatus.CANCELLED for f in finished)


def test_encrypt_folder_as_archive_roundtrip(tmp_path, keyfile_credential):
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "main.py").write_text("print('hi')\n")
    (project / "README.md").write_text("# project\n")
    (project / "data.bin").write_bytes(os.urandom(5000))

    jobs, skipped = batch.plan_encrypt([project], keyfile_credential, out_dir=tmp_path / "out")
    assert not skipped
    assert jobs[0].kind is JobKind.ENCRYPT_ARCHIVE
    assert jobs[0].dst.name == "project.zip.mcz"

    summary = batch.run(jobs)
    assert summary.success
    container = tmp_path / "out" / "project.zip.mcz"
    assert container.is_file()
    assert not list(tmp_path.rglob("*.zip"))

    djobs, _ = batch.plan_decrypt([container], keyfile_credential, out_dir=tmp_path / "back")
    assert batch.run(djobs).success
    restored_zip = tmp_path / "back" / "project.zip"
    with zipfile.ZipFile(restored_zip) as zf:
        zf.extractall(tmp_path / "unpacked")
    assert (tmp_path / "unpacked" / "src" / "main.py").read_text() == "print('hi')\n"
    assert (tmp_path / "unpacked" / "data.bin").read_bytes() == (project / "data.bin").read_bytes()


def test_archive_job_ignores_delete_source(tmp_path, keyfile_credential):
    folder = tmp_path / "keepme"
    folder.mkdir()
    (folder / "f.txt").write_text("stay")
    jobs, _ = batch.plan_encrypt(
        [folder], keyfile_credential, out_dir=tmp_path / "out", delete_source=True
    )
    assert jobs[0].delete_source is False
    batch.run(jobs)
    assert folder.is_dir() and (folder / "f.txt").exists()


def test_legacy_job_planned_when_legacy_key_supplied(tmp_path):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    blob = Fernet(key).encrypt(b"payload")
    enc = tmp_path / "old.enc"
    enc.write_bytes(blob)
    keyfile = tmp_path / "old.key"
    keyfile.write_bytes(key)

    jobs, skipped = batch.plan_decrypt(
        [enc], None, out_dir=tmp_path / "out", legacy_key=key
    )
    assert jobs and jobs[0].kind is JobKind.DECRYPT_LEGACY
    summary = batch.run(jobs)
    assert summary.success
    assert (tmp_path / "out" / "old").read_bytes() == b"payload"
