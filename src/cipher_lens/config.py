"""Local application paths and configuration."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel


def data_directory() -> Path:
    """Return the local data directory without reading or exposing credentials."""
    configured = os.getenv("CIPHER_LENS_DATA_DIR", "data")
    path = Path(configured).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def database_path() -> Path:
    return data_directory() / "cipher_lens.sqlite3"


def load_local_environment() -> None:
    """Load the repository-local secret file without overriding real process settings."""
    load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)


class ProviderSlot(BaseModel):
    label: str
    base_url: str
    api_key: str
    model: str


def provider_slots() -> list[ProviderSlot]:
    """Read only complete provider slots; no credential values are logged or returned to UI."""
    load_local_environment()
    slots: list[ProviderSlot] = []
    for number in (1, 2):
        base_url = os.getenv(f"PROVIDER_{number}_BASE_URL", "").strip()
        api_key = os.getenv(f"PROVIDER_{number}_API_KEY", "").strip()
        model = os.getenv(f"PROVIDER_{number}_MODEL", "").strip()
        if base_url and api_key and model:
            slots.append(ProviderSlot(label=f"provider_{number}", base_url=base_url, api_key=api_key, model=model))
    return slots


def zap_base_url() -> str:
    """Return the checked local ZAP default when no daemon URL is configured."""
    load_local_environment()
    return os.getenv("ZAP_BASE_URL", "http://127.0.0.1:8080").rstrip("/")


def nvd_api_key() -> str | None:
    """Return the configured NIST NVD API key, or None if unconfigured."""
    load_local_environment()
    key = os.getenv("NVD_API_KEY", "").strip()
    return key if key else None
