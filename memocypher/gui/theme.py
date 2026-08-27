"""Design tokens and ttk styling for the memocypher GUI.

Everything visual is driven from one place: a spacing scale, a type scale and
two colour palettes (dark and light). Widgets read tokens from the active
:class:`Theme` instead of hard-coding colours, so the whole app restyles by
swapping the palette and calling :meth:`Theme.apply` again.
"""

from __future__ import annotations

import contextlib
import tkinter as tk
import tkinter.font as tkfont
from dataclasses import dataclass
from tkinter import ttk

XS, SM, MD, LG, XL = 4, 8, 12, 16, 24

_FONT_STACK = (
    "Inter",
    "SF Pro Text",
    "Segoe UI",
    "Ubuntu",
    "Cantarell",
    "DejaVu Sans",
    "Helvetica",
    "Arial",
)
_MONO_STACK = ("SF Mono", "Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Menlo", "Courier")


DARK = {
    "bg": "#15151d",
    "surface": "#1d1d28",
    "surface_alt": "#262633",
    "border": "#34343f",
    "text": "#e6e6f0",
    "muted": "#9797ad",
    "accent": "#7c6af7",
    "accent_hover": "#9382ff",
    "accent_text": "#ffffff",
    "success": "#5bd07a",
    "danger": "#f0616b",
    "danger_hover": "#ff7b84",
    "warning": "#e0a33e",
    "plain": "#7bd88f",
    "encrypted": "#b39dff",
    "key": "#e6b455",
    "selection": "#33324a",
    "focus_ring": "#9382ff",
}

LIGHT = {
    "bg": "#f4f4f7",
    "surface": "#ffffff",
    "surface_alt": "#ececf1",
    "border": "#d5d5de",
    "text": "#1b1b23",
    "muted": "#63636f",
    "accent": "#5b46d9",
    "accent_hover": "#4a37c4",
    "accent_text": "#ffffff",
    "success": "#1f9d4f",
    "danger": "#d23b41",
    "danger_hover": "#b92f35",
    "warning": "#a9691a",
    "plain": "#1f8a4c",
    "encrypted": "#6a4bd6",
    "key": "#9a6b1a",
    "selection": "#e4e0fb",
    "focus_ring": "#5b46d9",
}


@dataclass
class Theme:
    mode: str
    colors: dict
    family: str
    mono: str
    base_size: int = 10

    def font(self, *, size: int | None = None, weight: str = "normal") -> tuple:
        return (self.family, size or self.base_size, weight)

    def mono_font(self, *, size: int | None = None) -> tuple:
        return (self.mono, size or self.base_size - 1)

    @property
    def h1(self) -> tuple:
        return self.font(size=self.base_size + 6, weight="bold")

    @property
    def h2(self) -> tuple:
        return self.font(size=self.base_size + 2, weight="bold")

    @property
    def small(self) -> tuple:
        return self.font(size=self.base_size - 1)

    def c(self, name: str) -> str:
        return self.colors[name]

    def apply(self, root: tk.Misc) -> None:
        colors = self.colors
        style = ttk.Style(root)
        with contextlib.suppress(tk.TclError):  # pragma: no cover
            style.theme_use("clam")

        root.configure(bg=colors["bg"])
        base = self.font()
        small = self.small

        style.configure(".", background=colors["bg"], foreground=colors["text"], font=base)
        style.configure("TFrame", background=colors["bg"])
        style.configure("Surface.TFrame", background=colors["surface"])
        style.configure("Card.TFrame", background=colors["surface"], borderwidth=0)
        style.configure("TLabel", background=colors["bg"], foreground=colors["text"], font=base)
        style.configure(
            "Muted.TLabel", background=colors["bg"], foreground=colors["muted"], font=small
        )
        style.configure(
            "CardMuted.TLabel",
            background=colors["surface"],
            foreground=colors["muted"],
            font=small,
        )
        style.configure(
            "CardHead.TLabel",
            background=colors["surface"],
            foreground=colors["text"],
            font=self.font(weight="bold"),
        )
        style.configure("H1.TLabel", background=colors["bg"], foreground=colors["text"], font=self.h1)
        style.configure("H2.TLabel", background=colors["bg"], foreground=colors["text"], font=self.h2)

        style.configure(
            "TButton",
            background=colors["surface_alt"],
            foreground=colors["text"],
            font=base,
            relief="flat",
            borderwidth=0,
            padding=(MD, SM),
        )
        style.map(
            "TButton",
            background=[("active", colors["border"]), ("disabled", colors["surface"])],
            foreground=[("disabled", colors["muted"])],
        )
        style.configure(
            "Accent.TButton",
            background=colors["accent"],
            foreground=colors["accent_text"],
            font=self.font(weight="bold"),
            padding=(MD, SM),
        )
        style.map(
            "Accent.TButton",
            background=[("active", colors["accent_hover"]), ("disabled", colors["surface_alt"])],
            foreground=[("disabled", colors["muted"])],
        )
        style.configure(
            "Danger.TButton",
            background=colors["danger"],
            foreground="#ffffff",
            font=self.font(weight="bold"),
            padding=(MD, SM),
        )
        style.map("Danger.TButton", background=[("active", colors["danger_hover"])])
        style.configure(
            "Ghost.TButton",
            background=colors["surface"],
            foreground=colors["text"],
            padding=(SM, XS),
        )
        style.map("Ghost.TButton", background=[("active", colors["surface_alt"])])

        for name in ("TEntry", "TCombobox"):
            style.configure(
                name,
                fieldbackground=colors["surface_alt"],
                background=colors["surface_alt"],
                foreground=colors["text"],
                insertcolor=colors["text"],
                borderwidth=1,
                relief="flat",
                padding=SM,
            )
            style.map(
                name,
                fieldbackground=[("focus", colors["surface"])],
                bordercolor=[("focus", colors["focus_ring"])],
            )

        style.configure(
            "Treeview",
            background=colors["surface"],
            fieldbackground=colors["surface"],
            foreground=colors["text"],
            rowheight=28,
            borderwidth=0,
            font=base,
        )
        style.configure(
            "Treeview.Heading",
            background=colors["surface_alt"],
            foreground=colors["muted"],
            font=self.font(size=self.base_size - 1, weight="bold"),
            relief="flat",
            padding=(SM, XS),
        )
        style.map(
            "Treeview",
            background=[("selected", colors["selection"])],
            foreground=[("selected", colors["text"])],
        )
        style.map("Treeview.Heading", background=[("active", colors["border"])])

        style.configure(
            "TProgressbar",
            troughcolor=colors["surface_alt"],
            background=colors["accent"],
            borderwidth=0,
            thickness=8,
        )
        style.configure("TSeparator", background=colors["border"])
        style.configure(
            "TCheckbutton",
            background=colors["bg"],
            foreground=colors["text"],
            font=small,
        )
        style.map("TCheckbutton", background=[("active", colors["bg"])])


def _pick(family_candidates, available: set[str], fallback: str) -> str:
    for name in family_candidates:
        if name in available:
            return name
    return fallback


def make_theme(root: tk.Misc, mode: str = "dark") -> Theme:
    available = set(tkfont.families(root))
    family = _pick(_FONT_STACK, available, "TkDefaultFont")
    mono = _pick(_MONO_STACK, available, "TkFixedFont")
    palette = LIGHT if mode == "light" else DARK
    return Theme(mode=mode, colors=dict(palette), family=family, mono=mono)
