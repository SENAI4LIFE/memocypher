"""Command-line interface for memocypher.

    memocypher encrypt  PATHS...  [--keyfile K | --passphrase] [-o DIR] [-r]
    memocypher decrypt  PATHS...  [--keyfile K | --passphrase] [-o DIR]
    memocypher keygen   [-o FILE] [--label L]
    memocypher keyinfo  FILE
    memocypher identify PATHS...
    memocypher scan     [DIR] [--json]
    memocypher gui

Passphrases are read interactively with :func:`getpass` and never taken from
the argument list. ``--passphrase-file`` exists for automation and is
documented as a security trade-off.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

from . import __version__, crypto, fsops
from .batch import (
    ItemFinished,
    ItemStatus,
    plan_decrypt,
    plan_encrypt,
    run,
)
from .crypto import Credential, KeyFileCredential, PassphraseCredential, format_key_id
from .errors import KeyFileError, MemocypherError
from .keys import KeyStore, generate_keyfile, load_key_bytes, read_key_ref

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memocypher",
        description="Authenticated file encryption (AES-256-GCM streaming).",
    )
    parser.add_argument("--version", action="version", version=f"memocypher {__version__}")
    sub = parser.add_subparsers(dest="command")

    def add_credential_opts(p: argparse.ArgumentParser) -> None:
        g = p.add_argument_group("credential")
        g.add_argument("--keyfile", type=Path, metavar="FILE", help="use a .mckey key file")
        g.add_argument(
            "--passphrase",
            action="store_true",
            help="use a passphrase (prompted; the default if --keyfile is absent)",
        )
        g.add_argument(
            "--passphrase-file",
            type=Path,
            metavar="FILE",
            help="read the passphrase from the first line of FILE (weaker; for automation)",
        )

    def add_common_io(p: argparse.ArgumentParser) -> None:
        p.add_argument("paths", nargs="+", type=Path, help="files or directories")
        p.add_argument("-o", "--out", type=Path, metavar="DIR", help="write outputs to DIR")
        p.add_argument(
            "-r", "--recursive", action="store_true", help="descend into directories"
        )
        p.add_argument(
            "--on-collision",
            choices=[p.value for p in fsops.CollisionPolicy],
            default=fsops.CollisionPolicy.ERROR.value,
            help="what to do when an output already exists (default: error)",
        )
        p.add_argument(
            "--delete-source",
            action="store_true",
            help="delete each input after it is processed successfully",
        )
        p.add_argument("-q", "--quiet", action="store_true", help="only print problems")
        p.add_argument("--json", action="store_true", help="print a JSON summary")

    p_enc = sub.add_parser("encrypt", help="encrypt files")
    add_common_io(p_enc)
    add_credential_opts(p_enc)

    p_dec = sub.add_parser("decrypt", help="decrypt .mcz (or legacy .enc) files")
    add_common_io(p_dec)
    add_credential_opts(p_dec)
    p_dec.add_argument(
        "--legacy-key",
        type=Path,
        metavar="FILE",
        help="raw Fernet .key for decrypting original memocry files",
    )

    p_keygen = sub.add_parser("keygen", help="generate a new .mckey key file")
    p_keygen.add_argument("-o", "--out", type=Path, default=Path("memocypher.mckey"))
    p_keygen.add_argument("--label", default="", help="human label stored in the file")
    p_keygen.add_argument("--force", action="store_true", help="overwrite an existing file")

    p_keyinfo = sub.add_parser("keyinfo", help="show a key file's id and metadata")
    p_keyinfo.add_argument("path", type=Path)

    p_identify = sub.add_parser("identify", help="show which key each container needs")
    p_identify.add_argument("paths", nargs="+", type=Path)
    p_identify.add_argument(
        "--keys",
        type=Path,
        nargs="*",
        default=[],
        metavar="DIR",
        help="extra directories to search for matching key files",
    )
    p_identify.add_argument("--json", action="store_true")

    p_scan = sub.add_parser("scan", help="list a directory's plaintext / encrypted / key files")
    p_scan.add_argument("dir", type=Path, nargs="?", default=Path.cwd())
    p_scan.add_argument("--json", action="store_true")

    sub.add_parser("gui", help="launch the graphical interface")
    return parser


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        # Bare `memocypher` launches the GUI; use a subcommand for the CLI.
        return _cmd_gui(args)
    try:
        handler = _HANDLERS[args.command]
    except KeyError:  # pragma: no cover
        parser.error(f"unknown command {args.command!r}")
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_FAILURE
    except MemocypherError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE


# --------------------------------------------------------------------------- #
# Credential resolution
# --------------------------------------------------------------------------- #
def _resolve_credential(args, *, confirm: bool) -> Credential:
    if getattr(args, "keyfile", None):
        try:
            return KeyFileCredential(load_key_bytes(args.keyfile), source=args.keyfile)
        except KeyFileError as exc:
            raise SystemExitCode(EXIT_USAGE, f"error: {exc}") from exc
    if getattr(args, "passphrase_file", None):
        text = Path(args.passphrase_file).read_text(encoding="utf-8").splitlines()
        if not text or not text[0]:
            raise SystemExitCode(EXIT_USAGE, "error: passphrase file is empty")
        return PassphraseCredential(text[0])
    # default: prompt (or read one line from a pipe when not on a terminal)
    interactive = bool(sys.stdin) and sys.stdin.isatty()
    first = _read_secret("Passphrase: ", interactive)
    if not first:
        raise SystemExitCode(EXIT_USAGE, "error: empty passphrase")
    if confirm and interactive and _read_secret("Confirm passphrase: ", interactive) != first:
        raise SystemExitCode(EXIT_USAGE, "error: passphrases did not match")
    return PassphraseCredential(first)


def _read_secret(prompt: str, interactive: bool) -> str:
    if interactive:
        return getpass.getpass(prompt)
    line = sys.stdin.readline()
    if not line:
        raise SystemExitCode(EXIT_USAGE, "error: no passphrase provided on stdin")
    return line.rstrip("\r\n")


class SystemExitCode(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------- #
# Input expansion
# --------------------------------------------------------------------------- #
def _expand(paths: Iterable[Path], *, recursive: bool, want: str) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    problems: list[str] = []
    for path in paths:
        path = Path(path)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            if not recursive:
                problems.append(f"{path} is a directory (use -r to descend)")
                continue
            for child in sorted(path.rglob("*")):
                if not child.is_file():
                    continue
                if want == "encrypt" and (
                    fsops.is_container_name(child) or fsops.is_keyfile_name(child)
                ):
                    continue
                if want == "decrypt" and not fsops.is_container_name(child):
                    continue
                files.append(child)
        else:
            problems.append(f"{path} does not exist")
    return files, problems


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def _cmd_encrypt(args) -> int:
    return _run_batch(args, want="encrypt")


def _cmd_decrypt(args) -> int:
    return _run_batch(args, want="decrypt")


def _run_batch(args, *, want: str) -> int:
    files, problems = _expand(args.paths, recursive=args.recursive, want=want)
    for problem in problems:
        print(f"skip: {problem}", file=sys.stderr)
    if not files:
        print("error: nothing to do", file=sys.stderr)
        return EXIT_USAGE

    legacy_key: bytes | None = None
    credential: Credential | None = None
    try:
        if want == "decrypt" and getattr(args, "legacy_key", None):
            legacy_key = Path(args.legacy_key).read_bytes().strip()
        if want == "encrypt" or _needs_v1_credential(files):
            credential = _resolve_credential(args, confirm=(want == "encrypt"))
    except SystemExitCode as exc:
        print(exc.message, file=sys.stderr)
        return exc.code

    policy = fsops.CollisionPolicy(args.on_collision)
    if want == "encrypt":
        jobs, skipped = plan_encrypt(
            files,
            credential,
            out_dir=args.out,
            collision=policy,
            delete_source=args.delete_source,
        )
    else:
        jobs, skipped = plan_decrypt(
            files,
            credential,
            out_dir=args.out,
            collision=policy,
            delete_source=args.delete_source,
            legacy_key=legacy_key,
        )

    def on_event(event) -> None:
        if isinstance(event, ItemFinished) and not args.json:
            r = event.result
            mark = {"ok": "OK  ", "failed": "FAIL", "skipped": "SKIP", "cancelled": "----"}[
                r.status.value
            ]
            if r.status is ItemStatus.OK and args.quiet:
                return
            detail = f"  {r.message}" if r.message else ""
            print(f"{mark}  {event.job.src.name} -> {event.job.dst.name}{detail}")

    summary = run(jobs, on_event=on_event, skipped=skipped)

    for skip in summary.skipped:
        print(f"SKIP  {skip.path.name}  {skip.reason}", file=sys.stderr)

    if args.json:
        print(json.dumps(_summary_dict(summary), indent=2))
    elif not args.quiet:
        print(
            f"\n{summary.ok_count} ok, {summary.failed_count} failed, "
            f"{summary.skipped_count} skipped in {summary.elapsed:.2f}s"
        )
    return EXIT_OK if summary.success and not summary.skipped else EXIT_FAILURE


def _needs_v1_credential(files: list[Path]) -> bool:
    return any(crypto.looks_like_container(f) for f in files)


def _summary_dict(summary) -> dict:
    return {
        "ok": summary.ok_count,
        "failed": summary.failed_count,
        "skipped": summary.skipped_count,
        "cancelled": summary.cancelled,
        "elapsed_seconds": round(summary.elapsed, 3),
        "items": [
            {
                "src": str(r.job.src),
                "dst": str(r.job.dst),
                "status": r.status.value,
                "message": r.message,
            }
            for r in summary.results
        ],
        "planning_skipped": [
            {"path": str(s.path), "reason": s.reason} for s in summary.skipped
        ],
    }


def _cmd_keygen(args) -> int:
    try:
        ref = generate_keyfile(args.out, label=args.label, overwrite=args.force)
    except MemocypherError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    print(f"wrote {ref.path}")
    print(f"key id: {format_key_id(ref.key_id or '')}")
    print("Back this file up somewhere safe and separate. Without it, data")
    print("encrypted with this key cannot be recovered.")
    return EXIT_OK


def _cmd_keyinfo(args) -> int:
    path = Path(args.path)
    if fsops.is_container_name(path):
        try:
            header = crypto.read_header(path)
        except MemocypherError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_FAILURE
        print(f"path:    {path}")
        print(f"type:    memocypher container v{header.version}")
        print(f"cred:    {header.cred}")
        print(f"key id:  {format_key_id(header.key_id)}")
        if header.kdf:
            print(f"kdf:     {header.kdf.get('algo')} n={header.kdf.get('n')}")
        return EXIT_OK
    ref = read_key_ref(path)
    print(f"path:    {path}")
    print(f"type:    {ref.kind}")
    if ref.error:
        print(f"error:   {ref.error}")
        return EXIT_FAILURE
    if ref.key_id:
        print(f"key id:  {format_key_id(ref.key_id)}")
    if ref.label:
        print(f"label:   {ref.label}")
    if ref.created:
        print(f"created: {ref.created}")
    return EXIT_OK


def _cmd_identify(args) -> int:
    store = KeyStore([Path.cwd(), *args.keys])
    store.scan()
    report = []
    for raw in args.paths:
        path = Path(raw)
        entry: dict = {"path": str(path)}
        if not path.is_file():
            entry["error"] = "not a file"
        elif not crypto.looks_like_container(path):
            entry["type"] = "legacy-or-unknown"
        else:
            try:
                header = crypto.read_header(path)
                entry["type"] = "memocypher"
                entry["cred"] = header.cred
                entry["key_id"] = header.key_id
                entry["matches"] = [str(r.path) for r in store.match(header.key_id)]
            except MemocypherError as exc:
                entry["error"] = str(exc)
        report.append(entry)

    if args.json:
        print(json.dumps(report, indent=2))
        return EXIT_OK
    for entry in report:
        print(entry["path"])
        if "error" in entry:
            print(f"  error: {entry['error']}")
            continue
        if entry.get("type") != "memocypher":
            print("  not a memocypher v1 container")
            continue
        print(f"  cred:   {entry['cred']}")
        print(f"  key id: {format_key_id(entry['key_id'])}")
        if entry["cred"] == "keyfile":
            if entry["matches"]:
                for match in entry["matches"]:
                    print(f"  key:    {match}")
            else:
                print("  key:    no matching key file found")
    return EXIT_OK


def _cmd_scan(args) -> int:
    from .scanner import scan as scan_ws

    ws = scan_ws(args.dir)
    if args.json:
        print(
            json.dumps(
                {
                    "root": str(ws.root),
                    "plaintext": [str(e.path) for e in ws.plaintext],
                    "encrypted": [
                        {"path": str(e.path), "cred": e.cred_type, "key_id": e.key_id}
                        for e in ws.encrypted
                    ],
                    "keyfiles": [
                        {"path": str(r.path), "key_id": r.key_id, "kind": r.kind}
                        for r in ws.key_refs
                    ],
                    "truncated": ws.truncated,
                },
                indent=2,
            )
        )
        return EXIT_OK
    print(f"{ws.root}")
    print(f"  plaintext:  {len(ws.plaintext)}")
    print(f"  encrypted:  {len(ws.encrypted)}")
    print(f"  key files:  {len(ws.key_refs)}")
    for entry in ws.encrypted:
        kid = format_key_id(entry.key_id) if entry.key_id else "-"
        print(f"    {entry.name}   [{entry.cred_type}]  key {kid}")
    if ws.truncated:
        print("  (listing truncated)")
    return EXIT_OK


def _cmd_gui(_args) -> int:
    from .gui.app import launch

    return launch()


def gui_main() -> int:
    """Entry point for the windowed launcher (no console on Windows)."""

    from .gui.app import launch

    return launch()


_HANDLERS = {
    "encrypt": _cmd_encrypt,
    "decrypt": _cmd_decrypt,
    "keygen": _cmd_keygen,
    "keyinfo": _cmd_keyinfo,
    "identify": _cmd_identify,
    "scan": _cmd_scan,
    "gui": _cmd_gui,
}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
