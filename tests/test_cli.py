from __future__ import annotations

import os

import pytest

from memocypher import cli


@pytest.fixture
def passfile(tmp_path):
    p = tmp_path / "pp.txt"
    p.write_text("a decent test passphrase")
    return p


def test_keygen_then_keyinfo(tmp_path, capsys):
    keypath = tmp_path / "k.mckey"
    assert cli.main(["keygen", "-o", str(keypath), "--label", "demo"]) == 0
    out = capsys.readouterr().out
    assert "key id:" in out
    assert keypath.exists()

    assert cli.main(["keyinfo", str(keypath)]) == 0
    assert "demo" in capsys.readouterr().out


def test_encrypt_decrypt_directory_roundtrip_keyfile(tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "one.txt").write_text("hello one")
    (src / "two.bin").write_bytes(os.urandom(4096))
    (src / "nested").mkdir()
    (src / "nested" / "three.md").write_text("# three")

    keypath = tmp_path / "k.mckey"
    cli.main(["keygen", "-o", str(keypath)])
    capsys.readouterr()

    enc = tmp_path / "enc"
    rc = cli.main(["encrypt", str(src), "-r", "--keyfile", str(keypath), "-o", str(enc)])
    assert rc == 0
    assert len(list(enc.glob("*.mcz"))) == 3

    dec = tmp_path / "dec"
    rc = cli.main(["decrypt", str(enc), "-r", "--keyfile", str(keypath), "-o", str(dec)])
    assert rc == 0
    assert (dec / "one.txt").read_text() == "hello one"
    assert (dec / "three.md").read_text() == "# three"
    assert (dec / "two.bin").read_bytes() == (src / "two.bin").read_bytes()


def test_encrypt_directory_without_recursive_makes_one_archive(tmp_path, capsys):
    import zipfile

    src = tmp_path / "album"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("a")
    (src / "sub" / "b.txt").write_text("b")

    keypath = tmp_path / "k.mckey"
    cli.main(["keygen", "-o", str(keypath)])
    capsys.readouterr()

    assert cli.main(["encrypt", str(src), "--keyfile", str(keypath), "-o", str(tmp_path / "e")]) == 0
    container = tmp_path / "e" / "album.zip.mcz"
    assert container.is_file()

    dec = tmp_path / "d"
    assert cli.main(["decrypt", str(container), "--keyfile", str(keypath), "-o", str(dec)]) == 0
    with zipfile.ZipFile(dec / "album.zip") as zf:
        zf.extractall(dec / "x")
    assert (dec / "x" / "a.txt").read_text() == "a"
    assert (dec / "x" / "sub" / "b.txt").read_text() == "b"


def test_passphrase_file_roundtrip(tmp_path, passfile, monkeypatch):
    monkeypatch.setattr(
        "memocypher.crypto.DEFAULT_SCRYPT", cli.crypto.ScryptParams(n=1 << 12)
    )
    data = tmp_path / "secret.txt"
    data.write_text("top secret")

    assert (
        cli.main(
            ["encrypt", str(data), "--passphrase-file", str(passfile), "-o", str(tmp_path / "e")]
        )
        == 0
    )
    container = next((tmp_path / "e").glob("*.mcz"))
    assert (
        cli.main(
            ["decrypt", str(container), "--passphrase-file", str(passfile), "-o", str(tmp_path / "d")]
        )
        == 0
    )
    assert (tmp_path / "d" / "secret.txt").read_text() == "top secret"


def test_collision_default_is_error_exit_1(tmp_path, capsys):
    data = tmp_path / "f.txt"
    data.write_text("x")
    keypath = tmp_path / "k.mckey"
    cli.main(["keygen", "-o", str(keypath)])
    capsys.readouterr()

    assert cli.main(["encrypt", str(data), "--keyfile", str(keypath)]) == 0
    capsys.readouterr()
    rc = cli.main(["encrypt", str(data), "--keyfile", str(keypath)])
    assert rc == 1
    assert "exists" in capsys.readouterr().err


def test_identify_points_at_matching_key(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "doc.txt").write_text("content")
    cli.main(["keygen", "-o", "k.mckey"])
    cli.main(["encrypt", "doc.txt", "--keyfile", "k.mckey"])
    capsys.readouterr()

    assert cli.main(["identify", "doc.txt.mcz"]) == 0
    out = capsys.readouterr().out
    assert "keyfile" in out
    assert "k.mckey" in out


def test_scan_json(tmp_path, capsys, monkeypatch):
    import json

    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.txt").write_text("a")
    cli.main(["keygen", "-o", "k.mckey"])
    cli.main(["encrypt", "a.txt", "--keyfile", "k.mckey"])
    capsys.readouterr()

    assert cli.main(["scan", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["root"] == str(tmp_path)
    assert any(e["path"].endswith("a.txt.mcz") for e in payload["encrypted"])


def test_interactive_passphrase_prompt_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "memocypher.crypto.DEFAULT_SCRYPT", cli.crypto.ScryptParams(n=1 << 12)
    )
    prompts = iter(["prompted secret", "prompted secret", "prompted secret"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _p="": next(prompts))

    class _TTY:
        def isatty(self):
            return True

    monkeypatch.setattr(cli.sys, "stdin", _TTY())

    data = tmp_path / "note.txt"
    data.write_text("via prompt")
    assert cli.main(["encrypt", str(data), "-o", str(tmp_path / "e")]) == 0
    container = next((tmp_path / "e").glob("*.mcz"))
    assert cli.main(["decrypt", str(container), "-o", str(tmp_path / "d")]) == 0
    assert (tmp_path / "d" / "note.txt").read_text() == "via prompt"


def test_pipe_passphrase_when_not_a_tty(tmp_path, monkeypatch):
    import io

    monkeypatch.setattr(
        "memocypher.crypto.DEFAULT_SCRYPT", cli.crypto.ScryptParams(n=1 << 12)
    )
    data = tmp_path / "note.txt"
    data.write_text("via pipe")

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("streamed-pass\n"))
    assert cli.main(["encrypt", str(data), "-o", str(tmp_path / "e")]) == 0
    container = next((tmp_path / "e").glob("*.mcz"))
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("streamed-pass\n"))
    assert cli.main(["decrypt", str(container), "-o", str(tmp_path / "d")]) == 0
    assert (tmp_path / "d" / "note.txt").read_text() == "via pipe"


def test_decrypt_wrong_keyfile_exit_1(tmp_path, capsys):
    monkeypatch_dir = tmp_path
    (monkeypatch_dir / "x.txt").write_text("secret")
    good = tmp_path / "good.mckey"
    bad = tmp_path / "bad.mckey"
    cli.main(["keygen", "-o", str(good)])
    cli.main(["keygen", "-o", str(bad)])
    cli.main(["encrypt", str(tmp_path / "x.txt"), "--keyfile", str(good), "-o", str(tmp_path / "e")])
    capsys.readouterr()

    container = next((tmp_path / "e").glob("*.mcz"))
    rc = cli.main(["decrypt", str(container), "--keyfile", str(bad), "-o", str(tmp_path / "d")])
    assert rc == 1
    assert not (tmp_path / "d" / "x.txt").exists()
