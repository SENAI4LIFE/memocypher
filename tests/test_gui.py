"""Lightweight GUI checks.

These build the real Tk application and drive it without ``mainloop`` by
pumping the event loop by hand. They skip cleanly where no display is
available (headless CI on Linux without Xvfb).
"""

from __future__ import annotations

import contextlib
import os
import time

import pytest

tk = pytest.importorskip("tkinter")

from memocypher import keys  # noqa: E402
from memocypher.gui import theme as theme_mod  # noqa: E402


@pytest.fixture
def app():
    try:
        from memocypher.gui.app import MemocypherApp

        instance = MemocypherApp()
    except tk.TclError as exc:  # pragma: no cover - depends on environment
        pytest.skip(f"no display: {exc}")
    instance.withdraw()
    yield instance
    with contextlib.suppress(tk.TclError):
        instance.destroy()


def _pump(app, predicate, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.update_idletasks()
        app.update()
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_theme_tokens_present():
    for palette in (theme_mod.DARK, theme_mod.LIGHT):
        for token in ("bg", "surface", "text", "accent", "danger", "encrypted"):
            assert palette[token].startswith("#")


def test_app_builds_and_toggles_theme(app):
    assert app.title() == "memocypher"
    app.toggle_mode()
    assert app.mode == "light"
    app.toggle_mode()
    assert app.mode == "dark"


def test_gui_encrypt_then_decrypt_roundtrip(app, tmp_path):
    (tmp_path / "one.txt").write_text("hello gui")
    (tmp_path / "two.bin").write_bytes(os.urandom(9000))
    ref = keys.generate_keyfile(tmp_path / "k")

    app.workspace_dir = tmp_path
    app.collision_choice.set("rename")
    app.cred_segments._select("keyfile")
    app.keyfile_path.set(str(ref.path))
    app.refresh()

    plain_rows = [i for i in app.tree.get_children() if i.startswith("plaintext::")]
    assert len(plain_rows) == 2
    app.tree.selection_set(plain_rows)
    app.encrypt_selection()
    assert _pump(app, lambda: app.runner is None)
    assert sorted(p.name for p in tmp_path.glob("*.mcz")) == ["one.txt.mcz", "two.bin.mcz"]

    app.refresh()
    enc_rows = [i for i in app.tree.get_children() if i.startswith("encrypted::")]
    app.tree.selection_set(enc_rows)
    app.decrypt_selection()
    assert _pump(app, lambda: app.runner is None)

    assert (tmp_path / "one (2).txt").read_text() == "hello gui"
    assert (tmp_path / "two (2).bin").read_bytes() == (tmp_path / "two.bin").read_bytes()


def test_gui_search_and_filter(app, tmp_path):
    (tmp_path / "budget.csv").write_text("a,b")
    (tmp_path / "photo.jpg").write_bytes(b"\xff\xd8\xff")
    app.workspace_dir = tmp_path
    app.refresh()

    app.search_var.set("budget")
    app.update()
    names = {app.tree.item(i, "text").strip() for i in app.tree.get_children()}
    assert names == {"budget.csv"}

    app.search_var.set("")
    app.segments._select("encrypted")
    app.update()
    assert not app.tree.get_children()
