"""Local application paths and configuration."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import dotenv_values, load_dotenv
from pydantic import BaseModel


def data_directory() -> Path:
    """Return the local data directory without reading or exposing credentials."""
    configured = os.getenv("CIPHER_LENS_DATA_DIR", "data")
    path = Path(configured).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def database_path() -> Path:
    return data_directory() / "cipher_lens.sqlite3"


def _read_local_env() -> dict[str, str]:
    """Read key-values directly from the current working directory's .env without modifying os.environ."""
    env_file = Path.cwd() / ".env"
    if not env_file.is_file():
        return {}
    return {k: str(v).strip() for k, v in dotenv_values(dotenv_path=env_file).items() if v is not None}


def load_local_environment() -> None:
    """Load the repository-local secret file without overriding real process settings."""
    env_file = Path.cwd() / ".env"
    if env_file.is_file():
        load_dotenv(dotenv_path=env_file, override=False)


class ProviderSlot(BaseModel):
    label: str
    base_url: str
    api_key: str
    model: str


def provider_slots() -> list[ProviderSlot]:
    """Read only complete provider slots; no credential values are logged or returned to UI."""
    file_env = _read_local_env()
    slots: list[ProviderSlot] = []
    for number in (1, 2):
        base_url = (os.getenv(f"PROVIDER_{number}_BASE_URL") or file_env.get(f"PROVIDER_{number}_BASE_URL") or "").strip()
        api_key = (os.getenv(f"PROVIDER_{number}_API_KEY") or file_env.get(f"PROVIDER_{number}_API_KEY") or "").strip()
        model = (os.getenv(f"PROVIDER_{number}_MODEL") or file_env.get(f"PROVIDER_{number}_MODEL") or "").strip()
        if base_url and api_key and model:
            slots.append(ProviderSlot(label=f"provider_{number}", base_url=base_url, api_key=api_key, model=model))
    return slots


def zap_base_url() -> str:
    """Return the checked local ZAP default when no daemon URL is configured."""
    file_env = _read_local_env()
    val = (os.getenv("ZAP_BASE_URL") or file_env.get("ZAP_BASE_URL") or "http://127.0.0.1:8080").strip()
    return val.rstrip("/")


def nvd_api_key() -> str | None:
    """Return the configured NIST NVD API key, or None if unconfigured."""
    file_env = _read_local_env()
    key = (os.getenv("NVD_API_KEY") or file_env.get("NVD_API_KEY") or "").strip()
    return key if key else None
