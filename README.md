# memocypher

Authenticated file encryption with a desktop GUI and a command-line interface.

[![CI](https://github.com/SENAI4LIFE/memocypher/actions/workflows/ci.yml/badge.svg)](https://github.com/SENAI4LIFE/memocypher/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776ab.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Lint: Ruff](https://img.shields.io/badge/lint-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#requirements)

memocypher encrypts individual files into self-describing `.mcz` containers.
Each container is sealed with AES-256-GCM in a streaming construction, so files
of any size are processed with constant memory and any truncation, reordering
or modification of the ciphertext is detected before a single byte of
plaintext is written. Credentials are either a passphrase (stretched with
scrypt) or a 256-bit key file that carries a stable key id.

## Requirements

- Python 3.10 or newer
- [`cryptography`](https://cryptography.io/) (installed automatically)
- Tkinter for the GUI. It ships with the official Python installers on Windows
  and macOS. On Debian/Ubuntu: `sudo apt install python3-tk`. The command-line
  interface works without Tkinter.
- Optional: `tkinterdnd2` for drag-and-drop into the window.

## Installation

Install from a checkout with pipx (recommended) or pip:

```
pipx install .
# or
python -m pip install .
```

This provides two entry points: `memocypher` (CLI, and the GUI when run with no
arguments) and `memocypher-gui` (GUI without a console window).

To include drag-and-drop:

```
python -m pip install ".[dnd]"
```

To run from source without installing:

```
python -m pip install cryptography
python -m memocypher            # GUI
python -m memocypher --help     # CLI
```

## Usage

### Graphical interface

```
memocypher
```

1. Set the **workspace** to the folder you want to work in. Its files are
   listed and grouped as plaintext, encrypted or key files.
2. Choose a **credential**: set a passphrase, or select a `.mckey` key file
   (generate one from the Keys card or the Keys menu).
3. Select files in the list, or drag them into the window, and click
   **Encrypt selection** or **Decrypt selection**.
4. Watch progress in the status bar; per-file outcomes appear in the Results
   panel.

Keyboard: `Ctrl+O` open workspace, `Ctrl+I` add files, `F5` refresh,
`Ctrl+F` search, `Ctrl+E` encrypt, `Ctrl+D` decrypt, `Ctrl+G` generate key,
`Delete` remove a dragged-in file from the list, `Enter` acts on the selection.

### Command line

```
memocypher keygen -o family.mckey --label "family photos"
memocypher encrypt ./documents -r --keyfile family.mckey -o ./vault
memocypher decrypt ./vault -r --keyfile family.mckey -o ./restored
memocypher identify ./vault/*.mcz          # which key does each file need?
memocypher keyinfo ./vault/report.pdf.mcz  # credential type and key id
memocypher scan ./vault --json
```

Passphrase mode is the default when `--keyfile` is omitted; the passphrase is
requested interactively. For automation, `--passphrase-file FILE` reads it from
the first line of a file (weaker, because the passphrase touches disk).

Collision handling is explicit. By default an existing output is an error;
pass `--on-collision rename|overwrite|skip` to change that. `--delete-source`
removes each input only after its output is verified written.

Exit codes: `0` success, `1` one or more items failed or were skipped, `2`
usage error.

## Workflows

**Per-file encryption.** Encrypting `report.pdf` produces `report.pdf.mcz`
next to it (or in `--out`). Decrypting restores `report.pdf`; if that name is
taken, `rename` writes `report (2).pdf` rather than overwriting.

**Folders.** In the GUI, selecting a folder and choosing Encrypt offers to
package it into a single `.zip` and encrypt that. On the CLI, `encrypt DIR -r`
encrypts each file in the tree individually, skipping existing `.mcz` and
`.mckey` files.

**Batches.** Any selection is processed as one batch. A failure on one file
does not stop the rest; every outcome is reported.

**Identifying keys.** Key-file containers store the key id in their header.
`memocypher identify` (CLI) and the Identify action (GUI) match containers to
the `.mckey` files found in the workspace and your home directory, so you never
have to guess which key opens which file.

**Opening files from the original tool.** Containers made by the earlier
`memocry` utility used whole-file Fernet. Decrypt them by supplying the old
raw key: `memocypher decrypt secret.txt.enc --legacy-key secret.txt.key`.
There is no legacy re-encryption; re-encrypt with a current credential.

## Architecture

memocypher is a small Python package with a clear boundary between the
cryptographic core and the interfaces.

```
memocypher/
  crypto.py     Container format, AES-256-GCM-HKDF STREAM, scrypt, key ids,
                legacy Fernet reader. No filesystem or UI code.
  keys.py       .mckey format, key generation, KeyStore (discovery + matching).
  fsops.py      Atomic writes, collision policies, output naming, path checks.
  scanner.py    Scans a workspace into plaintext / encrypted / key buckets.
  batch.py      Plans jobs (resolving collisions up front) and runs them with
                progress events and cancellation. Threaded wrapper for the GUI.
  cli.py        argparse command-line interface.
  gui/          Tkinter application: theme tokens, widgets, dialogs, drag-and-drop.
```

### Container format (`memocypher/1`)

```
magic        8 bytes   "MCYPHER1"
header_len   2 bytes   big-endian uint16
header       JSON      version, credential type, scrypt parameters + salt,
                       key id, STREAM segment size, HKDF salt, nonce prefix
body         segments  AES-256-GCM sealed 1 MiB plaintext segments
```

A per-file content key is derived with HKDF-SHA256 over the master key, salted,
and bound to the exact header bytes. Each segment's nonce is a random per-file
prefix plus the segment index plus a "final segment" flag; the flag and the
positional index make truncation, reordering and extension fail authentication.

## Security

What memocypher guarantees:

- **Confidentiality and integrity.** AES-256-GCM authenticates every segment.
  A wrong passphrase or key file, or any change to the header or ciphertext,
  aborts decryption with an error and no plaintext output.
- **Truncation resistance.** Removing, appending or reordering segments is
  detected, not silently accepted.
- **Bounded memory.** Files stream a segment at a time; a multi-gigabyte file
  does not need multi-gigabyte RAM.
- **No partial or clobbered files.** Output is written to a temporary file,
  flushed, then atomically renamed. Existing files are never overwritten unless
  you choose `overwrite`.
- **Passphrase stretching.** scrypt with N = 2^17, r = 8, p = 1; the parameters
  are stored per file so they can be raised in future without breaking old
  containers.

What it deliberately does not claim:

- **No secure erase of plaintext.** On SSDs (wear levelling, over-provisioning)
  and on journaling or copy-on-write filesystems, overwriting a file's visible
  blocks does not reliably destroy the data. memocypher does a normal delete
  and nothing more. Protect data at rest with full-disk encryption.
- **No in-memory key protection.** Python cannot reliably zero secrets in
  memory, so no such guarantee is made.
- **Metadata is not hidden.** Anyone with a container can see its size, that it
  is a memocypher file, whether it uses a passphrase or a key file, and, for
  key-file mode, the key id. File names are not stored in the container.
- **Not transport security.** It protects files at rest, not data in transit.

Key management:

- Losing a key file, or forgetting a passphrase, means the data is
  unrecoverable. There is no backdoor.
- Back up every key file to separate, secure storage the moment you create it.
- A key file is plaintext key material. Keep it away from the data it protects.

## Development

```
python -m pip install -e ".[dev]"
python -m pytest
ruff check .
```

The test suite covers the container format (round trips, tamper and truncation
detection, wrong credentials), key files and matching, atomic writes and
collision policies, workspace scanning, batch planning and execution, the CLI,
and a GUI smoke test that drives a real window without entering the main loop.

## License

MIT. See [LICENSE](LICENSE).
