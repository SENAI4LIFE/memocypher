# memocypher

Authenticated file encryption with a desktop GUI and a command-line interface.

[![CI](https://github.com/SENAI4LIFE/memocypher/actions/workflows/ci.yml/badge.svg)](https://github.com/SENAI4LIFE/memocypher/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776ab.svg)](https://www.python.org/downloads/)
[![Lint: Ruff](https://img.shields.io/badge/lint-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#requirements)

memocypher encrypts a file into a self-describing `.mcz` container, or packs a
whole folder into one `.zip.mcz`. Each container is sealed with AES-256-GCM in a
streaming construction, so files of any size are processed with constant memory
and any truncation, reordering or modification of the ciphertext is detected
before a single byte of plaintext is written. A credential is either a
passphrase (stretched with scrypt) or a 256-bit key file that carries a stable
key id.

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
python -m pip install .
```

This provides two entry points: `memocypher` (the CLI, and the GUI when run
with no arguments) and `memocypher-gui` (the GUI without a console window).

Drag-and-drop is an optional extra:

```
python -m pip install ".[dnd]"
```

To run straight from a checkout without installing:

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

1. Set the **workspace** to the folder you want to work in. Its contents are
   listed and grouped as folders, plaintext, encrypted and key files.
2. Choose a **credential**: set a passphrase, or select a `.mckey` key file
   (generate one from the Keys card or the Keys menu).
3. Select rows in the list, or drag files and folders onto the window, then
   click **Encrypt selection** or **Decrypt selection**.
4. Progress shows in the status bar; per-item outcomes appear in the Results
   panel.

Keyboard: `Ctrl+O` open workspace, `Ctrl+I` add files, `F5` refresh,
`Ctrl+F` search, `Ctrl+E` encrypt, `Ctrl+D` decrypt, `Ctrl+G` generate key,
`Delete` remove an added item from the list, `Enter` acts on the selection.

### Command line

```
memocypher keygen -o family.mckey --label "family photos"
memocypher encrypt ./report.pdf --keyfile family.mckey
memocypher encrypt ./project --keyfile family.mckey          # -> project.zip.mcz
memocypher encrypt ./documents -r --keyfile family.mckey -o ./vault
memocypher decrypt ./vault -r --keyfile family.mckey -o ./restored
memocypher identify ./vault/*.mcz
memocypher keyinfo ./vault/report.pdf.mcz
memocypher scan ./vault --json
```

A passphrase is the default when `--keyfile` is omitted; it is requested
interactively. For automation, `--passphrase-file FILE` reads it from the first
line of a file (weaker, because the passphrase touches disk).

Collision handling is explicit. By default an existing output is an error; pass
`--on-collision rename|overwrite|skip` to change that. `--delete-source`
removes each input only after its output has been written and flushed.

Exit codes: `0` success, `1` one or more items failed or were skipped, `2`
usage error.

## Workflows

**Single file.** Encrypting `report.pdf` produces `report.pdf.mcz` beside it
(or in `--out`). Decrypting restores `report.pdf`; if that name is taken,
`rename` writes `report (2).pdf` instead of overwriting.

**Whole folder as one archive.** Selecting a folder in the GUI, or passing a
directory to `memocypher encrypt` without `-r`, packs the tree into a single
`.zip.mcz`. The intermediate zip is written to a private temporary directory
and deleted as soon as the container exists. Decrypting yields the `.zip`,
which you then extract.

**Every file in a folder separately.** `memocypher encrypt DIR -r` walks the
tree and encrypts each file to its own `.mcz`, skipping existing `.mcz` and
`.mckey` files. `memocypher decrypt DIR -r` restores every container it finds.

**Batches.** Any selection runs as one batch. A failure on one item does not
stop the rest, and every outcome is reported. A long run can be cancelled;
work already completed is kept.

**Identifying keys.** A key-file container records the key id in its header.
`memocypher identify` and the GUI's Identify action match containers to the
`.mckey` files in the workspace and your home directory, so you do not have to
guess which key opens which file.

**Legacy `.enc` files.** Whole-file Fernet containers from the predecessor
tool are read with `memocypher decrypt secret.txt.enc --legacy-key
secret.txt.key`. There is no legacy re-encryption; re-encrypt with a current
credential.

## Architecture

memocypher is a small Python package with a firm boundary between the
cryptographic core and the interfaces.

```
memocypher/
  crypto.py     Container format, AES-256-GCM-HKDF STREAM, scrypt, key ids,
                legacy Fernet reader. No filesystem or UI code.
  archive.py    Deflate a directory tree into one zip for archive encryption.
  keys.py       .mckey format, key generation, KeyStore discovery and matching.
  fsops.py      Atomic writes, collision policies, output naming, path checks.
  scanner.py    Scan a workspace into folder / plaintext / encrypted / key rows.
  batch.py      Plan jobs with collisions resolved up front, then run them with
                progress events and cancellation. Threaded wrapper for the GUI.
  cli.py        argparse command-line interface.
  gui/          Tkinter application: theme tokens, widgets, dialogs, drag-drop.
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
prefix plus the segment index plus a final-segment flag; the flag and the
positional index make truncation, reordering and extension fail authentication.

## Security

What memocypher provides:

- **Confidentiality and integrity.** AES-256-GCM authenticates every segment.
  A wrong passphrase or key file, or any change to the header or ciphertext,
  aborts decryption with an error and no plaintext output.
- **Truncation resistance.** Removing, appending or reordering segments is
  detected, not silently accepted.
- **Bounded memory.** Files stream a segment at a time; a multi-gigabyte file
  does not need multi-gigabyte RAM.
- **No partial or clobbered files.** Output is written to a temporary file,
  flushed and fsynced, then atomically renamed. Existing files are overwritten
  only when you ask for it.
- **Passphrase stretching.** scrypt with N = 2^17, r = 8, p = 1; the parameters
  live in each header so they can be raised later without breaking old files.

What it deliberately does not claim:

- **No secure erase of plaintext.** On SSDs (wear levelling, over-provisioning)
  and on journaling or copy-on-write filesystems, overwriting a file's visible
  blocks does not reliably destroy the data. memocypher does a normal delete
  and nothing more. Protect data at rest with full-disk encryption.
- **No in-memory key protection.** Python cannot reliably zero secrets in
  memory, so no such guarantee is made.
- **Metadata is not hidden.** A container reveals its size, that it is a
  memocypher file, whether it uses a passphrase or a key file, and, in key-file
  mode, the key id. Original file names are not stored in the container. The
  folder workflow leaves an unencrypted zip on disk for the short window
  between packing and sealing.
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

The suite covers the container format (round trips, tamper / truncation /
reorder detection, wrong credentials), archive packing, key files and matching,
atomic writes and collision policies, workspace scanning, batch planning and
execution including cancellation, the CLI, and a GUI check that drives a real
window without entering the main loop.
