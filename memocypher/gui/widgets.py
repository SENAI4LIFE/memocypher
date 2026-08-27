"""Small reusable widgets built on the active :class:`~memocypher.gui.theme.Theme`."""

from __future__ import annotations

import contextlib
import tkinter as tk
from collections.abc import Callable, Sequence
from tkinter import ttk

from .theme import MD, SM, XS, Theme


class Card(ttk.Frame):
    """A padded surface panel with an optional bold header."""

    def __init__(self, parent: tk.Misc, theme: Theme, title: str = "", accent: str | None = None):
        super().__init__(parent, style="Card.TFrame", padding=MD)
        self.theme = theme
        if title:
            head = ttk.Label(self, text=title.upper(), style="CardHead.TLabel")
            if accent:
                head.configure(foreground=accent)
            head.pack(anchor="w")
            sep = tk.Frame(self, bg=theme.c("border"), height=1)
            sep.pack(fill="x", pady=(XS, SM))
        self.body = ttk.Frame(self, style="Card.TFrame")
        self.body.pack(fill="both", expand=True)


class SegmentedControl(ttk.Frame):
    """A horizontal group of mutually exclusive buttons."""

    def __init__(
        self,
        parent: tk.Misc,
        theme: Theme,
        options: Sequence[tuple[str, str]],
        command: Callable[[str], None],
        initial: str | None = None,
    ):
        super().__init__(parent, style="TFrame")
        self.theme = theme
        self._command = command
        self._value = initial or (options[0][0] if options else "")
        self._buttons: dict[str, tk.Button] = {}
        for value, label in options:
            btn = tk.Button(
                self,
                text=label,
                relief="flat",
                bd=0,
                padx=MD,
                pady=XS,
                cursor="hand2",
                font=theme.small,
                command=lambda v=value: self._select(v),
            )
            btn.pack(side="left", padx=(0, XS))
            self._buttons[value] = btn
        self._restyle()

    @property
    def value(self) -> str:
        return self._value

    def set(self, value: str) -> None:
        if value in self._buttons and value != self._value:
            self._value = value
            self._restyle()

    def _select(self, value: str) -> None:
        if value == self._value:
            return
        self._value = value
        self._restyle()
        self._command(value)

    def _restyle(self) -> None:
        c = self.theme.colors
        for value, btn in self._buttons.items():
            active = value == self._value
            btn.configure(
                bg=c["accent"] if active else c["surface_alt"],
                fg=c["accent_text"] if active else c["muted"],
                activebackground=c["accent_hover"] if active else c["border"],
                activeforeground=c["accent_text"] if active else c["text"],
            )


class Toast:
    """A non-blocking status message that fades from the bottom of a window."""

    def __init__(self, parent: tk.Toplevel | tk.Tk, theme: Theme):
        self.parent = parent
        self.theme = theme
        self._label: tk.Label | None = None
        self._after_id: str | None = None

    def show(self, text: str, kind: str = "info", duration: int = 3200) -> None:
        c = self.theme.colors
        colors = {
            "info": (c["surface_alt"], c["text"]),
            "success": (c["success"], "#0d1b10"),
            "error": (c["danger"], "#ffffff"),
            "warning": (c["warning"], "#1b1200"),
        }
        bg, fg = colors.get(kind, colors["info"])
        self._dismiss()
        self._label = tk.Label(
            self.parent,
            text=text,
            bg=bg,
            fg=fg,
            font=self.theme.small,
            padx=MD,
            pady=SM,
            justify="left",
            wraplength=460,
        )
        self._label.place(relx=0.5, rely=1.0, anchor="s", y=-MD)
        self._after_id = self.parent.after(duration, self._dismiss)

    def _dismiss(self) -> None:
        if self._after_id is not None:
            with contextlib.suppress(tk.TclError):
                self.parent.after_cancel(self._after_id)
            self._after_id = None
        if self._label is not None:
            self._label.destroy()
            self._label = None
