"""Modal dialogs: passphrase entry, key generation, collision resolution."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .. import __version__
from ..errors import CollisionError, MemocypherError
from ..fsops import CollisionPolicy
from ..keys import KeyRef, generate_keyfile
from .theme import LG, MD, SM, XS, Theme


class _Modal(tk.Toplevel):
    def __init__(self, parent: tk.Misc, theme: Theme, title: str):
        super().__init__(parent)
        self.theme = theme
        self.title(title)
        self.configure(bg=theme.c("bg"))
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.result = None
        self.bind("<Escape>", lambda _e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    def show(self):
        self.grab_set()
        self.wait_visibility()
        self.focus_set()
        self._center()
        self.wait_window()
        return self.result

    def _center(self) -> None:
        self.update_idletasks()
        parent = self.master.winfo_toplevel()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 3
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")


def ask_passphrase(
    parent: tk.Misc, theme: Theme, *, confirm: bool = False, title: str = "Passphrase"
) -> str | None:
    dlg = _Modal(parent, theme, title)
    frame = ttk.Frame(dlg, padding=LG)
    frame.pack(fill="both", expand=True)

    ttk.Label(
        frame,
        text="Enter a passphrase" if confirm else "Enter the passphrase",
        style="H2.TLabel",
    ).pack(anchor="w")
    ttk.Label(
        frame,
        text=(
            "Used with scrypt to derive the key. There is no recovery if you forget it."
            if confirm
            else "The passphrase used to encrypt these files."
        ),
        style="Muted.TLabel",
        wraplength=380,
    ).pack(anchor="w", pady=(XS, MD))

    var = tk.StringVar()
    confirm_var = tk.StringVar()
    show_var = tk.BooleanVar(value=False)

    entry = ttk.Entry(frame, textvariable=var, show="•", width=40)
    entry.pack(fill="x")
    hint = ttk.Label(frame, text="", style="Muted.TLabel")
    hint.pack(anchor="w", pady=(XS, 0))

    confirm_entry = None
    if confirm:
        ttk.Label(frame, text="Confirm passphrase", style="Muted.TLabel").pack(
            anchor="w", pady=(MD, XS)
        )
        confirm_entry = ttk.Entry(frame, textvariable=confirm_var, show="•", width=40)
        confirm_entry.pack(fill="x")

    def toggle_show() -> None:
        char = "" if show_var.get() else "•"
        entry.configure(show=char)
        if confirm_entry is not None:
            confirm_entry.configure(show=char)

    ttk.Checkbutton(
        frame, text="Show passphrase", variable=show_var, command=toggle_show
    ).pack(anchor="w", pady=(SM, 0))

    def update_hint(*_a) -> None:
        value = var.get()
        if not value:
            hint.configure(text="")
        elif len(value) < 8:
            hint.configure(text="Short - 12+ characters or several words is stronger.")
        elif len(value) < 12:
            hint.configure(text="Acceptable. A passphrase of several words is stronger.")
        else:
            hint.configure(text="Good length.")

    var.trace_add("write", update_hint)

    buttons = ttk.Frame(frame)
    buttons.pack(fill="x", pady=(LG, 0))

    def submit() -> None:
        if not var.get():
            messagebox.showerror("Passphrase", "The passphrase cannot be empty.", parent=dlg)
            return
        if confirm and var.get() != confirm_var.get():
            messagebox.showerror("Passphrase", "The passphrases do not match.", parent=dlg)
            return
        dlg.result = var.get()
        dlg.destroy()

    ttk.Button(buttons, text="Cancel", style="Ghost.TButton", command=dlg._cancel).pack(
        side="right", padx=(SM, 0)
    )
    ttk.Button(buttons, text="OK", style="Accent.TButton", command=submit).pack(side="right")
    dlg.bind("<Return>", lambda _e: submit())
    entry.focus_set()
    return dlg.show()


def generate_key_dialog(
    parent: tk.Misc, theme: Theme, default_dir: Path
) -> KeyRef | None:
    dlg = _Modal(parent, theme, "Generate key file")
    frame = ttk.Frame(dlg, padding=LG)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="Generate a new key file", style="H2.TLabel").pack(anchor="w")
    ttk.Label(
        frame,
        text="Creates a 256-bit key in a .mckey file. Anything encrypted with it "
        "can only be opened with this exact file.",
        style="Muted.TLabel",
        wraplength=400,
    ).pack(anchor="w", pady=(XS, MD))

    ttk.Label(frame, text="Label (optional)", style="Muted.TLabel").pack(anchor="w")
    label_var = tk.StringVar()
    ttk.Entry(frame, textvariable=label_var, width=44).pack(fill="x", pady=(XS, MD))

    ttk.Label(frame, text="File name", style="Muted.TLabel").pack(anchor="w")
    name_var = tk.StringVar(value="memocypher.mckey")
    ttk.Entry(frame, textvariable=name_var, width=44).pack(fill="x", pady=(XS, MD))

    ttk.Label(frame, text="Location", style="Muted.TLabel").pack(anchor="w")
    loc_row = ttk.Frame(frame)
    loc_row.pack(fill="x", pady=(XS, MD))
    loc_var = tk.StringVar(value=str(default_dir))
    ttk.Entry(loc_row, textvariable=loc_var).pack(side="left", fill="x", expand=True)

    def browse() -> None:
        chosen = filedialog.askdirectory(initialdir=loc_var.get(), parent=dlg)
        if chosen:
            loc_var.set(chosen)

    ttk.Button(loc_row, text="Browse", style="Ghost.TButton", command=browse).pack(
        side="right", padx=(SM, 0)
    )

    warn = tk.Frame(frame, bg=theme.c("surface_alt"))
    warn.pack(fill="x")
    tk.Label(
        warn,
        text="Back this file up to a separate, secure location immediately. "
        "If it is lost, the data it protects is unrecoverable.",
        bg=theme.c("surface_alt"),
        fg=theme.c("warning"),
        font=theme.small,
        justify="left",
        wraplength=400,
        padx=MD,
        pady=SM,
    ).pack(fill="x")

    buttons = ttk.Frame(frame)
    buttons.pack(fill="x", pady=(LG, 0))

    def submit() -> None:
        name = name_var.get().strip()
        if not name:
            messagebox.showerror("Key file", "Enter a file name.", parent=dlg)
            return
        location = Path(loc_var.get().strip()).expanduser()
        if not location.is_dir():
            messagebox.showerror("Key file", "That location is not a folder.", parent=dlg)
            return
        target = location / name
        label = label_var.get().strip()
        try:
            dlg.result = generate_keyfile(target, label=label)
        except CollisionError:
            if not messagebox.askyesno(
                "Key file",
                "A key file with that name already exists. Overwrite it?\n\n"
                "Files encrypted with the old key will no longer open.",
                parent=dlg,
            ):
                return
            try:
                dlg.result = generate_keyfile(target, label=label, overwrite=True)
            except MemocypherError as exc:
                messagebox.showerror("Key file", str(exc), parent=dlg)
                return
        except MemocypherError as exc:
            messagebox.showerror("Key file", str(exc), parent=dlg)
            return
        dlg.destroy()

    ttk.Button(buttons, text="Cancel", style="Ghost.TButton", command=dlg._cancel).pack(
        side="right", padx=(SM, 0)
    )
    ttk.Button(buttons, text="Generate", style="Accent.TButton", command=submit).pack(
        side="right"
    )
    return dlg.show()


def ask_collision_policy(
    parent: tk.Misc, theme: Theme, names: list[str]
) -> CollisionPolicy | None:
    dlg = _Modal(parent, theme, "Output already exists")
    frame = ttk.Frame(dlg, padding=LG)
    frame.pack(fill="both", expand=True)

    ttk.Label(
        frame,
        text=f"{len(names)} output file(s) already exist",
        style="H2.TLabel",
    ).pack(anchor="w")
    preview = ", ".join(names[:4]) + (" ..." if len(names) > 4 else "")
    ttk.Label(frame, text=preview, style="Muted.TLabel", wraplength=420).pack(
        anchor="w", pady=(XS, MD)
    )

    def choose(policy: CollisionPolicy) -> None:
        dlg.result = policy
        dlg.destroy()

    for policy, label, desc in (
        (CollisionPolicy.RENAME, "Keep both", "Write the new files under a numbered name"),
        (CollisionPolicy.OVERWRITE, "Replace", "Overwrite the existing files"),
        (CollisionPolicy.SKIP, "Skip", "Leave the existing files, do nothing for those"),
    ):
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=XS)
        ttk.Button(
            row, text=label, style="Accent.TButton" if policy is CollisionPolicy.RENAME else "TButton",
            width=12, command=lambda p=policy: choose(p)
        ).pack(side="left")
        ttk.Label(row, text=desc, style="Muted.TLabel").pack(side="left", padx=(MD, 0))

    ttk.Button(frame, text="Cancel", style="Ghost.TButton", command=dlg._cancel).pack(
        anchor="e", pady=(MD, 0)
    )
    return dlg.show()


def show_about(parent: tk.Misc, theme: Theme) -> None:
    messagebox.showinfo(
        "About memocypher",
        f"memocypher {__version__}\n\n"
        "Authenticated file encryption using AES-256-GCM in a streaming\n"
        "construction, with scrypt passphrases or 256-bit key files.",
        parent=parent,
    )
