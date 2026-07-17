from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Mini Vault"
    app_version: str = "0.1.0"
    mini_vault_db_url: str = "sqlite:///./data/mini_vault.db"
    debug: bool = False

    model_config = SettingsConfigDict(env_file=".env", env_prefix="MINI_VAULT_", extra="ignore")


settings = Settings()

if os.getenv("MINI_VAULT_DB_URL"):
    settings.mini_vault_db_url = os.getenv("MINI_VAULT_DB_URL")

ROOT_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ROOT_DIR / "data" / "mini_vault.db"
