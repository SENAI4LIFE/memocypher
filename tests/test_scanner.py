from __future__ import annotations

from memocypher import crypto, keys, scanner


def test_scan_buckets(sample_tree, keyfile_credential):
    crypto.encrypt_file(
        sample_tree / "notes.txt", sample_tree / "notes.txt.mcz", keyfile_credential
    )
    keys.generate_keyfile(sample_tree / "fam")

    ws = scanner.scan(sample_tree)

    def names(entries):
        return {e.name for e in entries}

    assert "notes.txt.mcz" in names(ws.encrypted)
    assert "notes.txt" in names(ws.plaintext)
    assert "fam.mckey" not in names(ws.plaintext)
    assert "fam.mckey" in names(ws.keyfiles)
    assert "sub" in names(ws.folders)
    assert "inner.md" in names(ws.plaintext)  # recursive by default


def test_scan_non_recursive(sample_tree):
    ws = scanner.scan(sample_tree, recursive=False)
    assert "inner.md" not in {e.name for e in ws.plaintext}


def test_encrypted_entry_exposes_key_id(sample_tree, keyfile_credential):
    crypto.encrypt_file(
        sample_tree / "photo.raw", sample_tree / "photo.raw.mcz", keyfile_credential
    )
    ws = scanner.scan(sample_tree)
    entry = next(e for e in ws.encrypted if e.name == "photo.raw.mcz")
    assert entry.cred_type == "keyfile"
    assert entry.key_id == keyfile_credential.key_id


def test_key_ref_for_links_entry_to_keyfile(sample_tree):
    ref = keys.generate_keyfile(sample_tree / "fam")
    cred = keys.load_credential(ref.path)
    crypto.encrypt_file(sample_tree / "notes.txt", sample_tree / "notes.txt.mcz", cred)
    ws = scanner.scan(sample_tree)
    entry = next(e for e in ws.encrypted if e.name == "notes.txt.mcz")
    linked = ws.key_ref_for(entry)
    assert [r.path for r in linked] == [ref.path]


def test_filter(sample_tree):
    ws = scanner.scan(sample_tree)
    filtered = ws.filter("photo")
    assert {e.name for e in filtered.plaintext} == {"photo.raw"}
    assert filtered.plaintext and not filtered.folders


def test_unreadable_container_is_flagged(sample_tree):
    (sample_tree / "bogus.mcz").write_bytes(b"MCYPHER1\x00\x05not json")
    ws = scanner.scan(sample_tree)
    entry = next(e for e in ws.encrypted if e.name == "bogus.mcz")
    assert entry.container_error
    assert entry.cred_type == "unreadable"
