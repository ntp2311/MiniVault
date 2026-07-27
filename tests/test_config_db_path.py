from __future__ import annotations

from src.config import ROOT_DIR, normalize_db_url


def test_normalize_db_url_converts_relative_sqlite_path_to_absolute() -> None:
    relative_url = "sqlite:///./data/mini_vault.db"

    normalized = normalize_db_url(relative_url)

    expected = f"sqlite:///{(ROOT_DIR / 'data' / 'mini_vault.db').resolve().as_posix()}"
    assert normalized == expected
