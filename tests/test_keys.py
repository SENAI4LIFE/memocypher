from __future__ import annotations

import io

import pytest

from memocypher import crypto, keys
from memocypher.errors import CollisionError, KeyFileError


def test_generate_load_roundtrip(tmp_path):
    ref = keys.generate_keyfile(tmp_path / "fam", label="family photos")
    assert ref.path.name == "fam.mckey"
    assert ref.label == "family photos"
    cred = keys.load_credential(ref.path)
    assert cred.key_id == ref.key_id
    assert crypto.format_key_id(ref.key_id).count(" ") == 3


def test_keyfile_is_human_readable(tmp_path):
    ref = keys.generate_keyfile(tmp_path / "k")
    text = ref.path.read_text()
    assert text.startswith("memocypher-key/1")
    assert "\nid: " in text
    assert "\nkey: " in text


def test_generate_refuses_silent_overwrite(tmp_path):
    keys.generate_keyfile(tmp_path / "k")
    with pytest.raises(CollisionError):
        keys.generate_keyfile(tmp_path / "k")
    keys.generate_keyfile(tmp_path / "k", overwrite=True)


def test_tampered_key_line_is_rejected(tmp_path):
    ref = keys.generate_keyfile(tmp_path / "k")
    lines = ref.path.read_text().splitlines()
    for i, line in enumerate(lines):
        if line.startswith("key: "):
            lines[i] = "key: " + ("A" * 43)
    ref.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(KeyFileError):
        keys.load_key_bytes(ref.path)


def test_keystore_indexes_and_matches(tmp_path, keyfile_credential):
    a = keys.generate_keyfile(tmp_path / "a", label="alpha")
    keys.generate_keyfile(tmp_path / "nested" / "b", label="bravo")

    blob = io.BytesIO()
    cred = keys.load_credential(a.path)
    crypto.encrypt_stream(io.BytesIO(b"data"), blob, cred)
    header = crypto.read_header(io.BytesIO(blob.getvalue()))

    store = keys.KeyStore([tmp_path])
    refs = store.scan()
    assert {r.display_name for r in refs} == {"alpha", "bravo"}
    matched = store.match(header.key_id)
    assert len(matched) == 1
    assert matched[0].path == a.path


def test_keystore_reports_bad_keyfile_without_crashing(tmp_path):
    (tmp_path / "broken.mckey").write_text("not a real key file")
    store = keys.KeyStore([tmp_path])
    refs = store.scan()
    assert len(refs) == 1
    assert not refs[0].ok
    assert refs[0].error
