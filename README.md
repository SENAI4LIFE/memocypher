# memocry

A self-contained, zero-footprint Python utility for symmetric file-level encryption and decryption. Built on authenticated Fernet cryptography with a modern dark-themed GUI. Two files. No installation. Runs anywhere Python 3.10+ is available.

---

## Requirements

- Python 3.10 or higher
- `cryptography` library

---

## Setup


```bash
sudo apt install python3.12-venv python3-pip
```
### Windows

```cmd
python -m venv venv
venv\Scripts\activate
pip install cryptography
```

### macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography
```

### Linux

```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography
```

---

## Usage

```bash
python memocry.py
```

On first launch memocry opens in your current working directory as the **Family Folder** — the directory it scans and operates on by default.

---

## Core Workflow

### Encrypt

1. Select files in the **Plain Files** panel (Ctrl/Shift+click for multi-select), or click **Browse Files** in the ENCRYPT panel.
2. Select or generate a key. If no key is loaded, memocry will offer to generate one automatically.
3. Click **Encrypt Selected**. Each file becomes `filename.ext.enc`.

### Decrypt

1. Select files in the **Encrypted Files** panel, or click **Browse Files** in the DECRYPT panel.
2. Select a key. If a paired key exists in the same folder, it auto-fills.
3. Click **Decrypt Selected**.

### Keys

Keys are Fernet keys stored as `.key` files. Generate them via **Generate & Save Key** in the KEY MANAGEMENT panel or when prompted during encryption. **Back up every key to a separate secure location immediately.** Loss of a key makes all files encrypted with it permanently and irreversibly unrecoverable.

---

## Features

### File Panels

| Panel | Color | Content |
|---|---|---|
| 📄 Plain Files | Green | Regular files and subfolders in the family folder |
| 🔒 Encrypted Files | Purple | `.enc` files with key-pairing status (Found / Missing) |
| 🗝 Detected Keys | Orange | `.key` files discovered in the family folder |

- **Folders** appear in the Plain Files panel with a 📁 icon and file count, distinct from regular files
- File names display without full path — name only, extension in a dedicated column
- Column widths are fixed; the window never auto-resizes after launch

### Folder Encryption

The **Add Folder** button and the folder right-click menu offer two modes:

- **Encrypt each file individually** — queues every plain file inside the folder for the next encrypt operation
- **Zip folder then Encrypt** — creates a `.zip` archive of the entire folder, encrypts it immediately using the loaded key, then deletes the intermediate zip automatically

### Batch Operations

All encrypt and decrypt actions are batched and run on a background thread. The GUI remains fully responsive during long operations. A progress bar appears during processing and disappears on completion.

### Right-click Context Menus

Context menus are context-aware — files, folders, encrypted files, and keys each have their own set of actions.

**Plain files:** Encrypt Selected, Rename, Move to, Compress (zip), Secure Wipe, Properties, Remove from list, Delete

**Folders:** Encrypt files individually, Zip folder then Encrypt, Compress (zip only), Rename, Move to, Properties

**Encrypted files:** Decrypt Selected, Find Key, Rename, Move to, Compress (zip), Secure Wipe, Properties, Remove from list, Delete

**Keys:** Use for Encryption, Use for Decryption, Rename, Move to, Properties, Delete key

### Key Management

- **Generate & Save Key** — creates a new cryptographically secure Fernet key, lets you name it and choose where to save it
- **Remove Selected Key** — deletes the key currently selected in the Detected Keys panel
- **Delete All Detected Keys** — permanently deletes all `.key` files in the family folder, double-confirmed

### Secure Wipe

Available via right-click on any file. Performs a **3-pass random overwrite** before deletion, making data recovery significantly harder than a standard delete. Useful before disposing of hardware or removing sensitive plaintext after encryption.

### Smart Key Pairing

When you select an encrypted file, memocry checks whether a matching `.key` file exists alongside it and auto-fills the DECRYPT key field. The **Find Key** context menu action searches the family folder and home directory for compatible keys if the paired key is missing.

### Session Toggles

All toggles are volatile — they reset to off on every launch and are never written to disk.

| Toggle | Effect |
|---|---|
| Delete source after encrypt | Deletes original plain files after successful encryption |
| Delete .enc after decrypt | Deletes the `.enc` file after successful decryption |
| Delete key after encrypt | Deletes the key file after encryption completes |
| Delete key after decrypt | Deletes the key file after decryption completes |
| Extra warnings | Adds confirmation dialogs before every operation |
| No warnings | Suppresses all optional confirmations |

Safety-critical warnings — encrypting memocry.py itself, encrypting the active key — always fire regardless of toggle state.

### Session Log

A volatile in-RAM activity log recording every operation, skip, and error. Toggle visibility with **Show / Hide** in the top bar. Never written to disk. Cleared on exit.

---

## Security Model

- **Fernet (AES-128-CBC + HMAC-SHA256)** — authenticated encryption; any tampering or wrong key aborts decryption immediately with no partial output written
- **Atomic writes** — output is written to a `.tmp` file first and renamed on success; partial writes never corrupt the destination
- **Memory hygiene** — key material is explicitly dereferenced after use in every code path
- **System file protection** — known system paths and root-owned files are flagged before encryption proceeds
- **In-use detection** — files open by another process are warned about before modification
- **No persistence** — all preferences, session state, and key material exist only in RAM; nothing is stored between sessions
- **Path sanitization** — all user-provided paths are resolved and validated before any file operation
- **Separation of concerns** — the GUI layer never holds raw key material; the cryptographic engine is fully isolated

---

## Architecture

```
memocry.py
├── CryptographicEngine     — Fernet encrypt/decrypt, key gen/save, zip, secure wipe
├── PathValidator           — input/output/key path sanitization and access checks
├── FamilyFolderScanner     — discovers plain files, encrypted files, keys, subfolders
├── BatchOperationWorker    — background thread for all batch encrypt/decrypt jobs
├── ToggleButton            — session option toggle widget
├── KeySaveDialog           — key generation and save dialog
├── KeySearchDialog         — key search and match dialog
├── ContextMenu             — right-click menus for files, folders, encrypted files, keys
├── KeyInfoLabel            — active key display widget in operation panels
└── MemocryApp              — main application window and orchestration
```

---

