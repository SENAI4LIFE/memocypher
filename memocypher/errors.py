"""Exception hierarchy shared across memocypher.

Every error raised deliberately by the package derives from
:class:`MemocypherError`, so callers can catch one type and show a message
instead of leaking tracebacks.
"""

from __future__ import annotations


class MemocypherError(Exception):
    """Base class for all errors raised by memocypher."""


class UnsupportedFormatError(MemocypherError):
    """The input is not a container memocypher knows how to read."""


class IntegrityError(MemocypherError):
    """Authentication failed: the data was truncated, reordered or modified.

    Raised only after the credential has been accepted, so it always means the
    ciphertext itself is damaged or tampered with. No plaintext is written.
    """


class WrongCredentialError(MemocypherError):
    """The passphrase or key file does not match the container."""


class CollisionError(MemocypherError):
    """The output path already exists and the collision policy forbids writing.

    Attributes:
        path: the output path that already exists.
    """

    def __init__(self, path):
        self.path = path
        super().__init__(f"Output already exists: {path}")


class KeyFileError(MemocypherError):
    """A key file is missing, malformed or holds invalid key material."""


class CancelledError(MemocypherError):
    """An operation was cancelled by the caller before it finished."""
