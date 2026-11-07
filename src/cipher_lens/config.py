"""Local application paths and configuration."""

from __future__ import annotations

import os
from pathlib import Path


def data_directory() -> Path:
    """Return the local data directory without reading or exposing credentials."""
    configured = os.getenv("CIPHER_LENS_DATA_DIR", "data")
    path = Path(configured).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def database_path() -> Path:
    return data_directory() / "cipher_lens.sqlite3"
