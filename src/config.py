from __future__ import annotations

from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "mini_vault.db"
DEFAULT_DB_URL = f"sqlite:///{DB_PATH.as_posix()}"


def normalize_db_url(url: str) -> str:
    if not url:
        return DEFAULT_DB_URL

    if not url.startswith("sqlite"):
        return url

    parsed = make_url(url)
    if not parsed.database:
        return url

    db_path = Path(parsed.database).expanduser()
    if not db_path.is_absolute():
        db_path = (ROOT_DIR / db_path).resolve()
    else:
        db_path = db_path.resolve()

    return f"sqlite:///{db_path.as_posix()}"


class Settings(BaseSettings):
    app_name: str = "Mini Vault"
    app_version: str = "0.1.0"
    mini_vault_db_url: str = Field(
        default=DEFAULT_DB_URL,
        validation_alias=AliasChoices(
            "MINI_VAULT_DB_URL",
            "MINI_VAULT_MINI_VAULT_DB_URL",
            "mini_vault_db_url",
        ),
    )
    debug: bool = False

    model_config = SettingsConfigDict(
        env_file=ROOT_DIR / ".env",
        env_prefix="MINI_VAULT_",
        extra="ignore",
    )

    def model_post_init(self, __context) -> None:
        self.mini_vault_db_url = normalize_db_url(self.mini_vault_db_url)


settings = Settings()