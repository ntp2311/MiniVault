from __future__ import annotations

from typing import Generator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch) -> Generator[TestClient, None, None]:
    db_path = tmp_path / "mini_vault.db"
    monkeypatch.setenv("MINI_VAULT_DB_URL", f"sqlite:///{db_path}")
    import importlib
    import main

    importlib.reload(main)
    app = main.create_app()
    with TestClient(app) as test_client:
        yield test_client
