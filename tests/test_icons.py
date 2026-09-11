"""Packaged icon assets and the GUI's resource loading."""

from __future__ import annotations

import struct
from importlib import resources

import pytest

ASSETS = resources.files("memocypher.gui") / "assets"
RGBA = 6


def png_header(data: bytes) -> tuple[int, int, int]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    width, height, _depth, colour_type = struct.unpack(">IIBB", data[16:26])
    return width, height, colour_type


@pytest.mark.parametrize(
    ("name", "size"),
    [
        ("memocypher.png", 1254),
        ("memocypher-256.png", 256),
        ("memocypher-32.png", 32),
        ("memocypher-16.png", 16),
        ("memocypher-glyph-20.png", 20),
        ("memocypher-glyph-24.png", 24),
        ("memocypher-glyph-32.png", 32),
    ],
)
def test_packaged_icons_resolve_regardless_of_cwd(name, size, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    width, height, colour_type = png_header((ASSETS / name).read_bytes())
    assert (width, height) == (size, size)
    assert colour_type == RGBA


tk = pytest.importorskip("tkinter")


@pytest.fixture
def root():
    try:
        root = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"no usable Tk display: {exc}")
    root.withdraw()
    yield root
    root.destroy()


def test_window_icons_load_largest_first(root):
    from memocypher.gui import icons

    photos = icons.window_icons(root)
    assert [p.width() for p in photos] == list(icons.WINDOW_SIZES)
    assert photos[0].transparency_get(0, 0)


def test_glyph_is_transparent_around_the_symbol(root):
    from memocypher.gui import icons

    for size in icons.GLYPH_SIZES:
        photo = icons.load_photo(root, f"memocypher-glyph-{size}.png")
        assert photo is not None
        assert photo.width() == photo.height() == size
        assert photo.transparency_get(0, 0)
        assert photo.transparency_get(size - 1, size - 1)
        assert not photo.transparency_get(size // 2, size // 2)


def test_glyph_size_follows_line_height(root):
    from memocypher.gui import icons

    assert icons.glyph_size(root, ("Helvetica", 8)) == icons.GLYPH_SIZES[0]
    assert icons.glyph_size(root, ("Helvetica", 48)) == icons.GLYPH_SIZES[-1]


def test_missing_asset_degrades_to_none(root):
    from memocypher.gui import icons

    assert icons.load_photo(root, "does-not-exist.png") is None
