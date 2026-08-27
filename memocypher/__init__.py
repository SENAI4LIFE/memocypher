"""memocypher - authenticated file encryption with a GUI and a CLI.

The public surface is intentionally small; import the submodules directly for
anything lower level.
"""

from __future__ import annotations

__version__ = "1.0.0"

from .errors import (
    CollisionError,
    IntegrityError,
    KeyFileError,
    MemocypherError,
    UnsupportedFormatError,
    WrongCredentialError,
)

__all__ = [
    "__version__",
    "MemocypherError",
    "IntegrityError",
    "WrongCredentialError",
    "UnsupportedFormatError",
    "CollisionError",
    "KeyFileError",
]
