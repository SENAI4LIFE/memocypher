"""The application icon and the toolbar brand glyph, read from the packaged assets.

Only the GUI imports this module; the CLI never touches Tk or these images.
Every loader degrades to ``None`` / an empty list, so a missing or unreadable
asset costs the window its icon and nothing else.
"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from importlib import resources

WINDOW_SIZES = (256, 32, 16)
GLYPH_SIZES = (20, 24, 32)


def asset(name: str):
    return resources.files(__package__) / "assets" / name


def load_photo(master: tk.Misc, name: str) -> tk.PhotoImage | None:
    try:
        return tk.PhotoImage(master=master, data=asset(name).read_bytes())
    except (OSError, tk.TclError):
        return None


def window_icons(master: tk.Misc) -> list[tk.PhotoImage]:
    """The full application icon at each shipped size, largest first for ``wm iconphoto``."""

    photos = (load_photo(master, f"memocypher-{size}.png") for size in WINDOW_SIZES)
    return [photo for photo in photos if photo is not None]


def glyph_size(master: tk.Misc, font) -> int:
    """The largest shipped glyph that fits within ``font``'s line height."""

    linespace = tkfont.Font(master, font=font).metrics("linespace")
    fitting = [size for size in GLYPH_SIZES if size <= linespace]
    return fitting[-1] if fitting else GLYPH_SIZES[0]


def brand_glyph(master: tk.Misc, font) -> tk.PhotoImage | None:
    """The transparent symbol-only glyph sized to sit beside text set in ``font``."""

    return load_photo(master, f"memocypher-glyph-{glyph_size(master, font)}.png")
