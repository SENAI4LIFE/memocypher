"""The memocypher desktop application."""

from __future__ import annotations

import contextlib
import queue
import sys
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .. import batch, crypto, scanner
from ..batch import (
    BatchFinished,
    BatchRunner,
    ItemFinished,
    ItemProgress,
    ItemStarted,
)
from ..crypto import Credential, KeyFileCredential, PassphraseCredential, format_key_id
from ..errors import KeyFileError, MemocypherError
from ..fsops import CollisionPolicy, is_container_name
from ..keys import KeyStore, load_key_bytes, load_legacy_fernet_key, read_key_ref
from ..scanner import FileEntry, Workspace
from . import dialogs, dnd, icons
from .theme import LG, MD, SM, XS, make_theme
from .widgets import Card, SegmentedControl, Toast

_POLL_MS = 80


def launch() -> int:
    try:
        app = MemocypherApp()
    except tk.TclError as exc:  # pragma: no cover - headless environments
        print(f"memocypher: cannot start the GUI ({exc}).", file=sys.stderr)
        print("Use the command line instead: memocypher --help", file=sys.stderr)
        return 1
    app.mainloop()
    return 0


_BaseRoot = dnd.base_tk_class()


class MemocypherApp(_BaseRoot):  # type: ignore[misc,valid-type]
    def __init__(self) -> None:
        super().__init__()
        self.title("memocypher")
        self.minsize(940, 600)
        self.geometry("1180x760")

        self.mode = "dark"
        self.theme = make_theme(self, self.mode)
        self.theme.apply(self)
        self.window_icons = icons.window_icons(self)
        if self.window_icons:
            with contextlib.suppress(tk.TclError):
                self.iconphoto(True, *self.window_icons)

        self.workspace_dir: Path = Path.cwd()
        self.workspace: Workspace | None = None
        self.view_filter = "all"
        self.credential: Credential | None = None
        self.credential_mode = "passphrase"
        self._passphrase_cache: str | None = None
        self.keyfile_path = tk.StringVar()
        self.collision_choice = tk.StringVar(value="ask")
        self.delete_after = tk.BooleanVar(value=False)
        self.staged: list[Path] = []
        self.runner: BatchRunner | None = None
        self._row_meta: dict[str, FileEntry | Path] = {}
        self._sort_state: tuple[str, bool] = ("name", False)
        self._batch_total = 1
        self._batch_done_bytes = 0

        self.toast = Toast(self, self.theme)

        self._build_menu()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()
        self._bind_keys()

        self.after(120, self.refresh)
        self.after(_POLL_MS, self._poll_events)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open workspace...", accelerator="Ctrl+O", command=self.choose_workspace)
        file_menu.add_command(label="Add files...", accelerator="Ctrl+I", command=self.browse_files)
        file_menu.add_command(label="Add folder...", command=self.browse_folder)
        file_menu.add_command(label="Refresh", accelerator="F5", command=self.refresh)
        file_menu.add_separator()
        file_menu.add_command(label="Quit", accelerator="Ctrl+Q", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        keys_menu = tk.Menu(menubar, tearoff=0)
        keys_menu.add_command(label="Generate key file...", accelerator="Ctrl+G", command=self.generate_key)
        keys_menu.add_command(label="Copy key id of selection", command=self.copy_key_id)
        keys_menu.add_command(label="Identify key for selection", command=self.identify_selection)
        menubar.add_cascade(label="Keys", menu=keys_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Toggle light / dark", command=self.toggle_mode)
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Project page", command=lambda: webbrowser.open("https://github.com/SENAI4LIFE/memocypher"))
        help_menu.add_command(label="About", command=lambda: dialogs.show_about(self, self.theme))
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(LG, MD, LG, SM))
        bar.pack(fill="x")
        self.brand_glyph = icons.brand_glyph(self, self.theme.h1)
        if self.brand_glyph is not None:
            ttk.Label(bar, image=self.brand_glyph).pack(side="left", padx=(0, SM))
        ttk.Label(bar, text="memocypher", style="H1.TLabel").pack(side="left")

        right = ttk.Frame(bar)
        right.pack(side="right")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._populate())
        search = ttk.Entry(right, textvariable=self.search_var, width=26)
        search.pack(side="left")
        _placeholder(search, "Search files...")
        self.search_entry = search
        ttk.Button(right, text="Clear", style="Ghost.TButton", command=lambda: self.search_var.set("")).pack(side="left", padx=(XS, 0))

        wsrow = ttk.Frame(self, padding=(LG, 0, LG, SM))
        wsrow.pack(fill="x")
        ttk.Label(wsrow, text="Workspace", style="Muted.TLabel").pack(side="left", padx=(0, SM))
        self.ws_var = tk.StringVar(value=str(self.workspace_dir))
        entry = ttk.Entry(wsrow, textvariable=self.ws_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _e: self._set_workspace_from_entry())
        ttk.Button(wsrow, text="Open", style="Ghost.TButton", command=self.choose_workspace).pack(side="left", padx=(SM, 0))
        ttk.Button(wsrow, text="Refresh", style="Ghost.TButton", command=self.refresh).pack(side="left", padx=(XS, 0))

    def _build_body(self) -> None:
        body = ttk.Frame(self, padding=(LG, 0, LG, 0))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)

        filters = ttk.Frame(body)
        filters.grid(row=0, column=0, sticky="ew", pady=(0, SM))
        self.segments = SegmentedControl(
            filters,
            self.theme,
            [("all", "All"), ("plaintext", "Plaintext"), ("encrypted", "Encrypted"), ("keyfile", "Keys")],
            command=self._on_filter,
        )
        self.segments.pack(side="left")
        self.count_label = ttk.Label(filters, text="", style="Muted.TLabel")
        self.count_label.pack(side="right")

        list_wrap = ttk.Frame(body, style="Card.TFrame")
        list_wrap.grid(row=1, column=0, sticky="nsew")
        list_wrap.rowconfigure(0, weight=1)
        list_wrap.columnconfigure(0, weight=1)

        columns = ("type", "size", "detail", "modified")
        tree = ttk.Treeview(list_wrap, columns=columns, selectmode="extended")
        tree.heading("#0", text="Name", command=lambda: self._sort_by("name"))
        tree.heading("type", text="Type", command=lambda: self._sort_by("type"))
        tree.heading("size", text="Size", command=lambda: self._sort_by("size"))
        tree.heading("detail", text="Status")
        tree.heading("modified", text="Modified", command=lambda: self._sort_by("modified"))
        tree.column("#0", width=260, minwidth=140, stretch=True)
        tree.column("type", width=78, minwidth=64, anchor="center", stretch=False)
        tree.column("size", width=74, minwidth=60, anchor="e", stretch=False)
        tree.column("detail", width=150, minwidth=90, stretch=False)
        tree.column("modified", width=124, minwidth=96, anchor="center", stretch=False)
        vsb = ttk.Scrollbar(list_wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree = tree

        for tag, color in (
            ("plaintext", self.theme.c("plain")),
            ("encrypted", self.theme.c("encrypted")),
            ("keyfile", self.theme.c("key")),
            ("folder", self.theme.c("muted")),
            ("staged", self.theme.c("accent")),
            ("bad", self.theme.c("danger")),
        ):
            tree.tag_configure(tag, foreground=color)

        tree.bind("<Double-1>", self._on_row_activate)
        tree.bind("<Return>", self._on_row_activate)
        tree.bind("<<TreeviewSelect>>", lambda _e: self._sync_action_state())
        tree.bind("<Button-3>", self._show_context_menu)
        if sys.platform == "darwin":
            tree.bind("<Button-2>", self._show_context_menu)
        dnd.register_drop_target(tree, self._on_drop)

        self._build_actions(body)
        self._build_results(body)

    def _build_actions(self, body: ttk.Frame) -> None:
        col = ttk.Frame(body, padding=(LG, 0, 0, 0))
        col.grid(row=1, column=1, rowspan=1, sticky="ns")
        body.columnconfigure(1, weight=0)

        cred = Card(col, self.theme, "Credential", self.theme.c("accent"))
        cred.pack(fill="x", pady=(0, SM))
        self.cred_segments = SegmentedControl(
            cred.body,
            self.theme,
            [("passphrase", "Passphrase"), ("keyfile", "Key file")],
            command=self._on_cred_mode,
        )
        self.cred_segments.pack(anchor="w", pady=(0, SM))

        self.pass_frame = ttk.Frame(cred.body, style="Card.TFrame")
        self.cred_status = ttk.Label(self.pass_frame, text="Not set", style="CardMuted.TLabel")
        self.cred_status.pack(side="left")
        ttk.Button(self.pass_frame, text="Set...", style="Ghost.TButton", command=self.set_passphrase).pack(side="right")

        self.key_frame = ttk.Frame(cred.body, style="Card.TFrame")
        krow = ttk.Frame(self.key_frame, style="Card.TFrame")
        krow.pack(fill="x")
        ttk.Entry(krow, textvariable=self.keyfile_path).pack(side="left", fill="x", expand=True)
        ttk.Button(krow, text="...", style="Ghost.TButton", width=3, command=self.browse_keyfile).pack(side="left", padx=(XS, 0))
        self.key_info = ttk.Label(self.key_frame, text="No key file selected", style="CardMuted.TLabel", wraplength=260)
        self.key_info.pack(anchor="w", pady=(XS, 0))
        ttk.Button(self.key_frame, text="Generate new key file...", style="Ghost.TButton", command=self.generate_key).pack(anchor="w", pady=(XS, 0))
        self.keyfile_path.trace_add("write", lambda *_: self._refresh_key_info())
        self._on_cred_mode("passphrase")

        enc = Card(col, self.theme, "Encrypt", self.theme.c("encrypted"))
        enc.pack(fill="x", pady=(0, SM))
        ttk.Label(enc.body, text="Files become .mcz containers; a folder becomes one .zip.mcz archive.", style="CardMuted.TLabel", wraplength=260).pack(anchor="w", pady=(0, SM))
        self.encrypt_btn = ttk.Button(enc.body, text="Encrypt selection", style="Accent.TButton", command=self.encrypt_selection)
        self.encrypt_btn.pack(fill="x")

        dec = Card(col, self.theme, "Decrypt", self.theme.c("plain"))
        dec.pack(fill="x", pady=(0, SM))
        ttk.Label(dec.body, text="Selected .mcz (or legacy .enc) files are restored.", style="CardMuted.TLabel", wraplength=260).pack(anchor="w", pady=(0, SM))
        self.decrypt_btn = ttk.Button(dec.body, text="Decrypt selection", style="Accent.TButton", command=self.decrypt_selection)
        self.decrypt_btn.pack(fill="x")

        opt = Card(col, self.theme, "Options")
        opt.pack(fill="x")
        ttk.Label(opt.body, text="If the output exists", style="CardMuted.TLabel").pack(anchor="w")
        ttk.Combobox(
            opt.body,
            textvariable=self.collision_choice,
            values=["ask", "rename", "overwrite", "skip", "error"],
            state="readonly",
        ).pack(fill="x", pady=(XS, SM))
        ttk.Checkbutton(
            opt.body,
            text="Delete each source after success",
            variable=self.delete_after,
        ).pack(anchor="w")

    def _build_results(self, body: ttk.Frame) -> None:
        self.results_wrap = ttk.Frame(body, style="Card.TFrame", padding=SM)
        self.results_wrap.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(SM, LG))
        head = ttk.Frame(self.results_wrap, style="Card.TFrame")
        head.pack(fill="x")
        ttk.Label(head, text="RESULTS", style="CardHead.TLabel").pack(side="left")
        ttk.Button(head, text="Hide", style="Ghost.TButton", command=self._toggle_results).pack(side="right")
        cols = ("result", "detail")
        self.results = ttk.Treeview(self.results_wrap, columns=cols, show="tree headings", height=5)
        self.results.heading("#0", text="File")
        self.results.heading("result", text="Result")
        self.results.heading("detail", text="Detail")
        self.results.column("#0", width=320)
        self.results.column("result", width=90, anchor="center", stretch=False)
        self.results.column("detail", width=420)
        self.results.pack(fill="x", pady=(SM, 0))
        for tag, color in (("ok", self.theme.c("success")), ("failed", self.theme.c("danger")), ("skipped", self.theme.c("muted"))):
            self.results.tag_configure(tag, foreground=color)
        self._results_visible = True
        self._toggle_results()

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, padding=(LG, SM))
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.status_var, style="Muted.TLabel").pack(side="left")
        self.cancel_btn = ttk.Button(bar, text="Cancel", style="Danger.TButton", command=self._cancel_batch)
        self.progress = ttk.Progressbar(bar, mode="determinate", length=240)
        self.results_toggle = ttk.Button(bar, text="Results", style="Ghost.TButton", command=self._toggle_results)
        self.results_toggle.pack(side="right")

    def _bind_keys(self) -> None:
        self.bind("<Control-o>", lambda _e: self.choose_workspace())
        self.bind("<Control-i>", lambda _e: self.browse_files())
        self.bind("<Control-q>", lambda _e: self._on_close())
        self.bind("<F5>", lambda _e: self.refresh())
        self.bind("<Control-r>", lambda _e: self.refresh())
        self.bind("<Control-f>", lambda _e: self.search_entry.focus_set())
        self.bind("<Control-e>", lambda _e: self.encrypt_selection())
        self.bind("<Control-d>", lambda _e: self.decrypt_selection())
        self.bind("<Control-g>", lambda _e: self.generate_key())
        self.bind("<Delete>", lambda _e: self._unstage_selection())

    def choose_workspace(self) -> None:
        chosen = filedialog.askdirectory(initialdir=str(self.workspace_dir), parent=self)
        if chosen:
            self.workspace_dir = Path(chosen)
            self.ws_var.set(chosen)
            self.staged.clear()
            self.refresh()

    def _set_workspace_from_entry(self) -> None:
        candidate = Path(self.ws_var.get()).expanduser()
        if candidate.is_dir():
            self.workspace_dir = candidate
            self.refresh()
        else:
            self.toast.show("That path is not a folder.", "error")

    def _key_search_roots(self) -> list[Path]:
        roots = [Path.home()]
        conventional = Path.home() / ".memocypher" / "keys"
        if conventional.is_dir():
            roots.append(conventional)
        return roots

    def refresh(self) -> None:
        try:
            self.workspace = scanner.scan(
                self.workspace_dir, key_search_roots=self._key_search_roots()
            )
        except MemocypherError as exc:
            self.toast.show(str(exc), "error")
            return
        self.ws_var.set(str(self.workspace.root))
        self._populate()
        if self.workspace.truncated:
            self.toast.show("Listing truncated - very large folder.", "warning")

    def _on_filter(self, value: str) -> None:
        self.view_filter = value
        self._populate()

    def _sort_by(self, key: str) -> None:
        col, reverse = self._sort_state
        self._sort_state = (key, not reverse if col == key else False)
        self._populate()

    def _populate(self) -> None:
        if self.workspace is None:
            return
        tree = self.tree
        tree.delete(*tree.get_children())
        self._row_meta.clear()

        query = self.search_var.get().strip().lower()
        if query == "search files...":
            query = ""
        ws = self.workspace.filter(query) if query else self.workspace

        buckets: list[tuple[str, list]] = []
        if self.view_filter in ("all", "plaintext"):
            buckets.append(("folder", ws.folders))
            buckets.append(("plaintext", ws.plaintext))
        if self.view_filter in ("all", "encrypted"):
            buckets.append(("encrypted", ws.encrypted))
        if self.view_filter in ("all", "keyfile"):
            buckets.append(("keyfile", ws.keyfiles))

        for path in self.staged:
            if query and query not in path.name.lower():
                continue
            iid = f"staged::{path}"
            is_dir = path.is_dir()
            tree.insert(
                "", "end", iid=iid, text=f"  {path.name}",
                values=(
                    "staged folder" if is_dir else "staged",
                    "" if is_dir else _human_size(_safe_size(path)),
                    str(path.parent),
                    "",
                ),
                tags=("staged",),
            )
            self._row_meta[iid] = path

        key, reverse = self._sort_state
        for kind, entries in buckets:
            for entry in _sorted_entries(entries, key, reverse):
                iid = f"{kind}::{entry.path}"
                is_folder = kind == "folder"
                tree.insert(
                    "", "end", iid=iid, text=f"  {entry.name}",
                    values=(
                        "folder" if is_folder else kind.replace("keyfile", "key"),
                        "" if is_folder else _human_size(entry.size),
                        self._detail_for(entry, kind),
                        entry.modified_str,
                    ),
                    tags=(("bad",) if entry.container_error else (kind,)),
                )
                self._row_meta[iid] = entry

        shown = len(self._row_meta)
        total = len(ws.plaintext) + len(ws.encrypted) + len(ws.keyfiles) + len(ws.folders)
        self.count_label.configure(text=f"{shown} shown / {total} in workspace")
        self._sync_action_state()

    def _detail_for(self, entry: FileEntry, kind: str) -> str:
        if kind == "folder":
            return f"{entry.child_count} item(s)"
        if kind == "encrypted":
            if entry.container_error:
                return "unreadable"
            if entry.container is None:
                return "legacy"
            if entry.container.is_passphrase:
                return "passphrase"
            matches = self.workspace.key_ref_for(entry) if self.workspace else []
            return "key ready" if matches else "key missing"
        if kind == "keyfile":
            ref = next(
                (r for r in (self.workspace.key_refs if self.workspace else []) if r.path == entry.path),
                None,
            )
            if ref and ref.error:
                return "invalid"
            if ref and ref.key_id:
                short = ref.key_id[:8]
                return f"{ref.label} ({short})" if ref.label else short
            return "legacy key"
        return ""

    def _selection(self) -> list[FileEntry | Path]:
        return [self._row_meta[iid] for iid in self.tree.selection() if iid in self._row_meta]

    def _selected_paths(self, *, kinds: tuple[str, ...] | None = None) -> list[Path]:
        out: list[Path] = []
        for iid in self.tree.selection():
            meta = self._row_meta.get(iid)
            if meta is None:
                continue
            if isinstance(meta, Path):
                out.append(meta)
            elif kinds is None or meta.kind in kinds:
                out.append(meta.path)
        return out

    def _sync_action_state(self) -> None:
        paths = self._selected_paths()
        has_enc = any(is_container_name(p) for p in paths)
        self.encrypt_btn.state(["!disabled"] if paths or self.staged else ["disabled"])
        self.decrypt_btn.state(["!disabled"] if has_enc else ["disabled"])

    def _on_cred_mode(self, mode: str) -> None:
        self.credential_mode = mode
        self.credential = None
        if mode == "passphrase":
            self.key_frame.pack_forget()
            self.pass_frame.pack(fill="x")
        else:
            self.pass_frame.pack_forget()
            self.key_frame.pack(fill="x")

    def set_passphrase(self) -> None:
        value = dialogs.ask_passphrase(self, self.theme, confirm=True, title="Set passphrase")
        if value:
            self._passphrase_cache = value
            self.cred_status.configure(text="Passphrase set", foreground=self.theme.c("success"))

    def browse_keyfile(self) -> None:
        chosen = filedialog.askopenfilename(
            parent=self,
            initialdir=str(self.workspace_dir),
            filetypes=[("memocypher key", "*.mckey"), ("Legacy key", "*.key"), ("All files", "*.*")],
        )
        if chosen:
            self.keyfile_path.set(chosen)

    def _refresh_key_info(self) -> None:
        path = self.keyfile_path.get().strip()
        if not path:
            self.key_info.configure(text="No key file selected", foreground=self.theme.c("muted"))
            return
        ref = read_key_ref(Path(path))
        if ref.error:
            self.key_info.configure(text=f"Invalid: {ref.error}", foreground=self.theme.c("danger"))
        elif ref.key_id:
            text = f"id {format_key_id(ref.key_id)}"
            if ref.label:
                text += f"\n{ref.label}"
            self.key_info.configure(text=text, foreground=self.theme.c("muted"))
        else:
            self.key_info.configure(text="Legacy Fernet key (decrypt only)", foreground=self.theme.c("warning"))

    def _resolve_credential(self, *, for_encrypt: bool) -> Credential | None:
        if self.credential_mode == "keyfile":
            path = self.keyfile_path.get().strip()
            if not path:
                self.toast.show("Choose a key file first.", "error")
                return None
            try:
                return KeyFileCredential(load_key_bytes(Path(path)), source=Path(path))
            except KeyFileError as exc:
                self.toast.show(str(exc), "error")
                return None
        if self._passphrase_cache is None:
            value = dialogs.ask_passphrase(self, self.theme, confirm=for_encrypt)
            if not value:
                return None
            self._passphrase_cache = value
            self.cred_status.configure(text="Passphrase set", foreground=self.theme.c("success"))
        return PassphraseCredential(self._passphrase_cache)

    def _gather_encrypt_targets(self) -> list[Path]:
        targets: list[Path] = list(self.staged)
        for meta in self._selection():
            path = meta if isinstance(meta, Path) else meta.path
            kind = None if isinstance(meta, Path) else meta.kind
            if kind in (None, "plaintext", "folder") and path not in targets:
                targets.append(path)
        return [p for p in targets if not is_container_name(p)]

    def encrypt_selection(self) -> None:
        if self._busy():
            return
        targets = self._gather_encrypt_targets()
        if not targets:
            self.toast.show("Select one or more plaintext files or folders.", "warning")
            return
        folders = [p for p in targets if p.is_dir()]
        if folders and not messagebox.askyesno(
            "Encrypt folders",
            f"{len(folders)} folder(s) will each be packed into a single "
            "'.zip.mcz' archive, then the zip is deleted.\n\nContinue?",
            parent=self,
        ):
            return
        credential = self._resolve_credential(for_encrypt=True)
        if credential is None:
            return

        def planner(policy):
            return batch.plan_encrypt(
                targets, credential, collision=policy, delete_source=self.delete_after.get()
            )

        policy = self._decide_policy(planner)
        if policy is None:
            return
        jobs, skipped = planner(policy)
        self._start_batch(jobs, skipped, verb="Encrypting")

    def decrypt_selection(self) -> None:
        if self._busy():
            return
        targets = [p for p in self._selected_paths() if is_container_name(p)]
        targets += [p for p in self.staged if is_container_name(p)]
        targets = list(dict.fromkeys(targets))
        if not targets:
            self.toast.show("Select one or more encrypted files.", "warning")
            return

        legacy_targets = [p for p in targets if not crypto.looks_like_container(p)]
        v1_targets = [p for p in targets if crypto.looks_like_container(p)]

        credential = None
        if v1_targets:
            credential = self._resolve_credential(for_encrypt=False)
            if credential is None:
                return

        legacy_key = None
        if legacy_targets:
            legacy_key = self._ask_legacy_key(legacy_targets[0])
            if legacy_key is None:
                return

        def planner(p):
            return batch.plan_decrypt(
                targets, credential, collision=p,
                delete_source=self.delete_after.get(), legacy_key=legacy_key,
            )

        policy = self._decide_policy(planner)
        if policy is None:
            return
        jobs, skipped = planner(policy)
        self._start_batch(jobs, skipped, verb="Decrypting")

    def _ask_legacy_key(self, sample: Path) -> bytes | None:
        sibling = sample.with_suffix(".key")
        chosen = filedialog.askopenfilename(
            parent=self, title="Select the legacy .key file",
            initialdir=str(sample.parent),
            initialfile=sibling.name if sibling.exists() else "",
            filetypes=[("Legacy key", "*.key"), ("All files", "*.*")],
        )
        if not chosen:
            return None
        try:
            return load_legacy_fernet_key(Path(chosen))
        except OSError as exc:
            self.toast.show(f"Could not read key: {exc}", "error")
            return None

    def _decide_policy(self, planner) -> CollisionPolicy | None:
        choice = self.collision_choice.get()
        if choice != "ask":
            return CollisionPolicy(choice)
        _, skipped = planner(CollisionPolicy.ERROR)
        clashes = [s.path.name for s in skipped if s.collision]
        if not clashes:
            return CollisionPolicy.ERROR
        return dialogs.ask_collision_policy(self, self.theme, clashes)

    def _busy(self) -> bool:
        if self.runner and self.runner.is_alive():
            self.toast.show("An operation is already running.", "warning")
            return True
        return False

    def _start_batch(self, jobs, skipped, *, verb: str) -> None:
        if not jobs:
            if skipped:
                self._show_results([], skipped)
                self.toast.show(f"Nothing to do - {len(skipped)} skipped.", "warning")
            else:
                self.toast.show("Nothing to do.", "info")
            return
        self._batch_total = max(sum(j.total_bytes for j in jobs), 1)
        self._batch_done_bytes = 0
        self.results.delete(*self.results.get_children())
        self._show_results_panel()
        self.progress.configure(value=0, maximum=100)
        self.progress.pack(side="right", padx=(SM, SM))
        self.cancel_btn.pack(side="right", padx=(SM, 0))
        self.status_var.set(f"{verb} {len(jobs)} file(s)...")
        self.encrypt_btn.state(["disabled"])
        self.decrypt_btn.state(["disabled"])
        self.runner = BatchRunner(jobs, skipped=skipped)
        self.runner.start()

    def _cancel_batch(self) -> None:
        if self.runner:
            self.runner.cancel()
            self.status_var.set("Cancelling...")

    def _poll_events(self) -> None:
        runner = self.runner
        if runner is not None:
            try:
                while True:
                    event = runner.events.get_nowait()
                    self._handle_event(event)
            except queue.Empty:
                pass
        self.after(_POLL_MS, self._poll_events)

    def _handle_event(self, event) -> None:
        if isinstance(event, ItemStarted):
            self.status_var.set(f"Working on {event.job.src.name}")
        elif isinstance(event, ItemProgress):
            done = self._batch_done_bytes + min(event.done_bytes, event.total_bytes or event.done_bytes)
            self.progress.configure(value=min(100.0, done / self._batch_total * 100))
        elif isinstance(event, ItemFinished):
            self._batch_done_bytes += event.job.total_bytes
            r = event.result
            tag = {"ok": "ok", "failed": "failed"}.get(r.status.value, "skipped")
            self.results.insert(
                "", "end", text=f"  {event.job.src.name}  ->  {event.job.dst.name}",
                values=(r.status.value, r.message), tags=(tag,),
            )
        elif isinstance(event, BatchFinished):
            self._finish_batch(event.summary)

    def _finish_batch(self, summary) -> None:
        self.progress.pack_forget()
        self.cancel_btn.pack_forget()
        for skip in summary.skipped:
            self.results.insert("", "end", text=f"  {skip.path.name}", values=("skipped", skip.reason), tags=("skipped",))
        msg = f"{summary.ok_count} done, {summary.failed_count} failed, {summary.skipped_count} skipped"
        self.status_var.set(msg)
        kind = "success" if summary.success and not summary.skipped else ("error" if summary.failed_count else "warning")
        self.toast.show(msg, kind)
        self.staged.clear()
        self.runner = None
        self.refresh()

    def _toggle_results(self) -> None:
        self._results_visible = not getattr(self, "_results_visible", True)
        if self._results_visible:
            self.results_wrap.grid()
        else:
            self.results_wrap.grid_remove()

    def _show_results_panel(self) -> None:
        if not getattr(self, "_results_visible", False):
            self._toggle_results()

    def _show_results(self, results, skipped) -> None:
        self.results.delete(*self.results.get_children())
        self._show_results_panel()
        for skip in skipped:
            self.results.insert("", "end", text=f"  {skip.path.name}", values=("skipped", skip.reason), tags=("skipped",))

    def generate_key(self) -> None:
        ref = dialogs.generate_key_dialog(self, self.theme, self.workspace_dir)
        if ref:
            self.toast.show(f"Key file created - id {format_key_id(ref.key_id or '')}", "success")
            if self.credential_mode == "keyfile":
                self.keyfile_path.set(str(ref.path))
            self.refresh()

    def copy_key_id(self) -> None:
        for meta in self._selection():
            if isinstance(meta, FileEntry) and meta.key_id:
                self.clipboard_clear()
                self.clipboard_append(meta.key_id)
                self.toast.show(f"Copied key id {format_key_id(meta.key_id)}", "success")
                return
        self.toast.show("Select an encrypted file or key with an id.", "warning")

    def identify_selection(self) -> None:
        entries = [m for m in self._selection() if isinstance(m, FileEntry) and m.kind == "encrypted"]
        if not entries:
            self.toast.show("Select an encrypted file.", "warning")
            return
        store = KeyStore()
        store.add_root(self.workspace_dir, recursive=True)
        for extra in self._key_search_roots():
            store.add_root(extra, recursive=False)
        store.scan()
        lines = []
        for entry in entries:
            if entry.container is None:
                lines.append(f"{entry.name}: legacy container, decrypt with its .key")
                continue
            if entry.container.is_passphrase:
                lines.append(f"{entry.name}: needs its passphrase")
                continue
            matches = store.match(entry.key_id or "")
            if matches:
                lines.append(f"{entry.name}: {', '.join(str(m.path) for m in matches)}")
            else:
                lines.append(f"{entry.name}: no key file found for id {format_key_id(entry.key_id)}")
        messagebox.showinfo("Identify key", "\n\n".join(lines), parent=self)

    def browse_files(self) -> None:
        chosen = filedialog.askopenfilenames(parent=self, initialdir=str(self.workspace_dir))
        self._stage_paths(Path(p) for p in chosen)

    def browse_folder(self) -> None:
        chosen = filedialog.askdirectory(parent=self, initialdir=str(self.workspace_dir))
        if chosen:
            self._stage_paths([Path(chosen)])

    def _stage_paths(self, paths) -> None:
        added = 0
        for path in paths:
            if path not in self.staged:
                self.staged.append(path)
                added += 1
        if added:
            self._populate()
            self.toast.show(f"Added {added} item(s) to the working set.", "info")

    def _on_drop(self, paths: list[str]) -> None:
        added = 0
        for raw in paths:
            path = Path(raw)
            if (path.is_file() or path.is_dir()) and path not in self.staged:
                self.staged.append(path)
                added += 1
        if added:
            self._populate()
            self.toast.show(f"Added {added} item(s). Folders encrypt as one archive.", "info")

    def _unstage_selection(self) -> None:
        removed = 0
        for iid in self.tree.selection():
            meta = self._row_meta.get(iid)
            if isinstance(meta, Path) and meta in self.staged:
                self.staged.remove(meta)
                removed += 1
        if removed:
            self._populate()

    def _on_row_activate(self, _event=None) -> None:
        paths = self._selected_paths()
        if paths and all(is_container_name(p) for p in paths):
            self.decrypt_selection()
        elif paths:
            self.encrypt_selection()

    def _show_context_menu(self, event) -> None:
        row = self.tree.identify_row(event.y)
        if row and row not in self.tree.selection():
            self.tree.selection_set(row)
        menu = tk.Menu(self, tearoff=0)
        paths = self._selected_paths()
        if paths and all(is_container_name(p) for p in paths):
            menu.add_command(label="Decrypt", command=self.decrypt_selection)
            menu.add_command(label="Identify key", command=self.identify_selection)
        elif paths:
            menu.add_command(label="Encrypt", command=self.encrypt_selection)
        menu.add_command(label="Copy key id", command=self.copy_key_id)
        menu.add_separator()
        menu.add_command(label="Reveal in file manager", command=self._reveal_selection)
        if any(isinstance(self._row_meta.get(i), Path) for i in self.tree.selection()):
            menu.add_command(label="Remove from working set", command=self._unstage_selection)
        menu.add_command(label="Refresh", command=self.refresh)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _reveal_selection(self) -> None:
        paths = self._selected_paths()
        if not paths:
            return
        target = paths[0].parent
        try:
            if sys.platform.startswith("win"):
                import os
                os.startfile(target)  # noqa: S606
            elif sys.platform == "darwin":
                import subprocess
                subprocess.run(["open", str(target)], check=False)
            else:
                import subprocess
                subprocess.run(["xdg-open", str(target)], check=False)
        except OSError as exc:
            self.toast.show(str(exc), "error")

    def toggle_mode(self) -> None:
        self.mode = "light" if self.mode == "dark" else "dark"
        self.theme = make_theme(self, self.mode)
        self.theme.apply(self)
        for tree, tags in (
            (self.tree, (("plaintext", "plain"), ("encrypted", "encrypted"), ("keyfile", "key"), ("folder", "muted"), ("staged", "accent"), ("bad", "danger"))),
            (self.results, (("ok", "success"), ("failed", "danger"), ("skipped", "muted"))),
        ):
            for tag, color in tags:
                tree.tag_configure(tag, foreground=self.theme.c(color))
        self._populate()

    def _on_close(self) -> None:
        if self.runner and self.runner.is_alive():
            if not messagebox.askyesno("Quit", "An operation is running. Quit anyway?", parent=self):
                return
            self.runner.cancel()
        self.destroy()


def _sorted_entries(entries: list[FileEntry], key: str, reverse: bool) -> list[FileEntry]:
    keyers = {
        "name": lambda e: e.name.lower(),
        "type": lambda e: e.kind,
        "size": lambda e: e.size,
        "modified": lambda e: e.modified,
    }
    return sorted(entries, key=keyers.get(key, keyers["name"]), reverse=reverse)


def _human_size(size: int) -> str:
    step = 1024.0
    if size < step:
        return f"{size} B"
    for unit in ("KB", "MB", "GB", "TB"):
        size /= step
        if size < step:
            return f"{size:.1f} {unit}"
    return f"{size:.1f} PB"


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _placeholder(entry: ttk.Entry, text: str) -> None:
    entry.insert(0, text)

    def clear(_e):
        if entry.get() == text:
            entry.delete(0, "end")

    def restore(_e):
        if not entry.get():
            entry.insert(0, text)

    entry.bind("<FocusIn>", clear)
    entry.bind("<FocusOut>", restore)
