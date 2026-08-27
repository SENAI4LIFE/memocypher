from __future__ import annotations

import zipfile

import pytest

from memocypher import archive
from memocypher.errors import CancelledError, MemocypherError


def _make_tree(root):
    (root / "a.txt").write_text("alpha")
    (root / "nested").mkdir()
    (root / "nested" / "b.bin").write_bytes(b"\x00\x01\x02\x03")
    (root / "nested" / "deep").mkdir()
    (root / "nested" / "deep" / "c.md").write_text("# c")
    (root / "empty").mkdir()


def test_zip_directory_roundtrip(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _make_tree(src)

    dest = tmp_path / "out.zip"
    written = archive.zip_directory(src, dest)
    assert written == 3

    out = tmp_path / "unpacked"
    with zipfile.ZipFile(dest) as zf:
        zf.extractall(out)

    assert (out / "a.txt").read_text() == "alpha"
    assert (out / "nested" / "b.bin").read_bytes() == b"\x00\x01\x02\x03"
    assert (out / "nested" / "deep" / "c.md").read_text() == "# c"
    assert (out / "empty").is_dir()


def test_zip_directory_is_deterministic(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _make_tree(src)
    first = tmp_path / "1.zip"
    second = tmp_path / "2.zip"
    archive.zip_directory(src, first)
    archive.zip_directory(src, second)
    with zipfile.ZipFile(first) as a, zipfile.ZipFile(second) as b:
        assert a.namelist() == b.namelist()


def test_zip_directory_rejects_non_directory(tmp_path):
    lonely = tmp_path / "file.txt"
    lonely.write_text("x")
    with pytest.raises(MemocypherError):
        archive.zip_directory(lonely, tmp_path / "out.zip")


def test_zip_directory_honours_cancel(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for i in range(20):
        (src / f"f{i}.txt").write_text(str(i))
    dest = tmp_path / "out.zip"
    with pytest.raises(CancelledError):
        archive.zip_directory(src, dest, cancel=lambda: True)
    assert not dest.exists()
