"""Optional drag-and-drop support via tkinterdnd2.

If the package is not installed the app still works: :func:`make_root` returns a
plain ``tk.Tk`` and :func:`register_drop_target` becomes a no-op, so callers do
not need to branch. :data:`AVAILABLE` tells the UI whether to show the "drop
files here" affordance or a "click to browse" hint instead.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable

try:  # pragma: no cover - depends on an optional package
    from tkinterdnd2 import DND_FILES, TkinterDnD

    AVAILABLE = True
except Exception:  # noqa: BLE001
    DND_FILES = None  # type: ignore[assignment]
    TkinterDnD = None  # type: ignore[assignment]
    AVAILABLE = False


def base_tk_class() -> type:
    """The Tk root class to subclass: TkinterDnD.Tk if available, else tk.Tk."""

    if AVAILABLE:  # pragma: no cover
        return TkinterDnD.Tk
    return tk.Tk


def make_root() -> tk.Tk:
    return base_tk_class()()


def register_drop_target(widget: tk.Misc, on_drop: Callable[[list[str]], None]) -> bool:
    """Wire ``widget`` to call ``on_drop`` with a list of dropped paths.

    Returns True if drop handling was actually attached.
    """

    if not AVAILABLE:  # pragma: no cover - exercised only with the extra installed
        return False

    def _handle(event) -> None:
        on_drop(_split_drop_paths(event.data))

    widget.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
    widget.dnd_bind("<<Drop>>", _handle)  # type: ignore[attr-defined]
    return True


def _split_drop_paths(data: str) -> list[str]:
    """Parse the platform's drop payload into individual paths.

    Tk hands over a Tcl list; paths with spaces are wrapped in braces.
    """

    paths: list[str] = []
    token = ""
    depth = 0
    for char in data:
        if char == "{":
            depth += 1
            if depth == 1:
                continue
        if char == "}":
            depth -= 1
            if depth == 0:
                paths.append(token)
                token = ""
                continue
        if char == " " and depth == 0:
            if token:
                paths.append(token)
                token = ""
            continue
        token += char
    if token:
        paths.append(token)
    return [p for p in paths if p]
