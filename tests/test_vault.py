from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


def test_init_success(client: TestClient) -> None:
    response = client.post(
        "/api/v1/vault/init",
        json={
            "master_passphrase": "MiniVault@Secure2026",
            "confirm_master_passphrase": "MiniVault@Secure2026",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "locked"
    assert body["initialized"] is True


def test_init_twice_rejected(client: TestClient) -> None:
    client.post(
        "/api/v1/vault/init",
        json={
            "master_passphrase": "MiniVault@Secure2026",
            "confirm_master_passphrase": "MiniVault@Secure2026",
        },
    )
    second = client.post(
        "/api/v1/vault/init",
        json={
            "master_passphrase": "MiniVault@Secure2026",
            "confirm_master_passphrase": "MiniVault@Secure2026",
        },
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "VAULT_ALREADY_INITIALIZED"


def test_weak_master_passphrase(client: TestClient) -> None:
    response = client.post(
        "/api/v1/vault/init",
        json={"master_passphrase": "123456", "confirm_master_passphrase": "123456"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "WEAK_MASTER_PASSPHRASE"


def test_confirmation_mismatch(client: TestClient) -> None:
    response = client.post(
        "/api/v1/vault/init",
        json={"master_passphrase": "MiniVault@Secure2026", "confirm_master_passphrase": "Different123!"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "PASSPHRASE_CONFIRMATION_MISMATCH"


def test_unlock_success(client: TestClient) -> None:
    client.post(
        "/api/v1/vault/init",
        json={
            "master_passphrase": "MiniVault@Secure2026",
            "confirm_master_passphrase": "MiniVault@Secure2026",
        },
    )
    response = client.post(
        "/api/v1/vault/unlock",
        json={"master_passphrase": "MiniVault@Secure2026"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "unlocked"


def test_unlock_failure(client: TestClient) -> None:
    client.post(
        "/api/v1/vault/init",
        json={
            "master_passphrase": "MiniVault@Secure2026",
            "confirm_master_passphrase": "MiniVault@Secure2026",
        },
    )
    response = client.post(
        "/api/v1/vault/unlock",
        json={"master_passphrase": "WrongPass123!"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNLOCK_FAILED"


def test_lock_vault(client: TestClient) -> None:
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
    response = client.post("/api/v1/vault/lock")
    assert response.status_code == 200
    assert response.json()["status"] == "locked"


def test_restart_simulation(client: TestClient) -> None:
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

    from src.core.vault_state import vault_state

    vault_state.clear_dek()
    response = client.get("/api/v1/vault/status")
    assert response.status_code == 200
    assert response.json()["status"] == "locked"


def test_require_vault_unlocked_dependency(client: TestClient) -> None:
    response = client.get("/api/v1/vault/status")
    assert response.status_code == 200
    assert response.json()["status"] == "not_initialized"

    protected = client.get("/api/v1/auth/me")
    assert protected.status_code == 401
    assert protected.json()["error"]["code"] == "UNAUTHENTICATED"
