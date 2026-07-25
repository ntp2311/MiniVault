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


@pytest.fixture()
def unlocked_and_registered_user(client: TestClient) -> tuple[TestClient, dict]:
    client.post(
        "/api/v1/vault/init",
        json={
            "master_passphrase": "MiniVault@Secure2026",
            "confirm_master_passphrase": "MiniVault@Secure2026",
        },
    )
    client.post(
        "/api/v1/vault/unlock",
        json={"master_passphrase": "MiniVault@Secure2026"},
    )
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "passphrase": "Alice@Secure2026"},
    )
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    return client, headers
