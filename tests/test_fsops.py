from __future__ import annotations

import os

import pytest

from memocypher import fsops
from memocypher.errors import CollisionError


def test_atomic_writer_replaces_on_success(tmp_path):
    target = tmp_path / "data.bin"
    target.write_bytes(b"old")
    with fsops.atomic_writer(target) as fh:
        fh.write(b"new content")
    assert target.read_bytes() == b"new content"
    assert list(tmp_path.iterdir()) == [target]


def test_atomic_writer_leaves_original_on_error(tmp_path):
    target = tmp_path / "data.bin"
    target.write_bytes(b"original")
    with pytest.raises(RuntimeError), fsops.atomic_writer(target) as fh:
        fh.write(b"partial")
        raise RuntimeError("boom")
    assert target.read_bytes() == b"original"
    assert list(tmp_path.iterdir()) == [target]


def test_atomic_writer_creates_parent_dirs(tmp_path):
    target = tmp_path / "a" / "b" / "c.txt"
    with fsops.atomic_writer(target) as fh:
        fh.write(b"hi")
    assert target.read_bytes() == b"hi"


def test_resolve_collision_error(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hi")
    with pytest.raises(CollisionError):
        fsops.resolve_collision(p, fsops.CollisionPolicy.ERROR)


def test_resolve_collision_skip(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hi")
    assert fsops.resolve_collision(p, fsops.CollisionPolicy.SKIP) is None


def test_resolve_collision_overwrite(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hi")
    assert fsops.resolve_collision(p, fsops.CollisionPolicy.OVERWRITE) == p


def test_resolve_collision_rename_sequence(tmp_path):
    (tmp_path / "x.txt").write_text("1")
    first = fsops.resolve_collision(tmp_path / "x.txt", fsops.CollisionPolicy.RENAME)
    assert first.name == "x (2).txt"
    first.write_text("2")
    second = fsops.resolve_collision(tmp_path / "x.txt", fsops.CollisionPolicy.RENAME)
    assert second.name == "x (3).txt"


def test_resolve_collision_rename_keeps_container_suffix(tmp_path):
    (tmp_path / "report.pdf.mcz").write_text("1")
    renamed = fsops.resolve_collision(tmp_path / "report.pdf.mcz", fsops.CollisionPolicy.RENAME)
    assert renamed.name == "report (2).pdf.mcz"


def test_name_helpers():
    from pathlib import Path

    assert fsops.encrypted_name(Path("a/b/photo.jpg")) == "photo.jpg.mcz"
    assert fsops.decrypted_name(Path("photo.jpg.mcz")) == "photo.jpg"
    assert fsops.decrypted_name(Path("legacy.enc")) == "legacy"
    assert fsops.decrypted_name(Path("mystery")).endswith(".decrypted")


def test_is_within(tmp_path):
    inside = tmp_path / "sub" / "f.txt"
    assert fsops.is_within(inside, tmp_path)
    assert not fsops.is_within(tmp_path.parent, tmp_path)


def test_delete_file(tmp_path):
    p = tmp_path / "gone.txt"
    p.write_text("bye")
    fsops.delete_file(p)
    assert not p.exists()
    fsops.delete_file(p)  # no error on missing file


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_atomic_writer_sets_mode(tmp_path):
    target = tmp_path / "k.mckey"
    with fsops.atomic_writer(target, mode=0o600) as fh:
        fh.write(b"secret")
    assert (target.stat().st_mode & 0o777) == 0o600
