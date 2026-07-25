from __future__ import annotations

import base64

from fastapi.testclient import TestClient


def test_create_key_success(client: TestClient, unlocked_and_registered_user: tuple[TestClient, dict]):
    client, headers = unlocked_and_registered_user
    response = client.post("/api/v1/transit/keys", json={"key_name": "my-key"}, headers=headers)
    assert response.status_code == 201
    body = response.json()
    assert body["key_name"] == "my-key"
    assert body["key_usage"] == "ENCRYPT_DECRYPT"


def test_list_keys(client: TestClient, unlocked_and_registered_user: tuple[TestClient, dict]):
    client, headers = unlocked_and_registered_user
    client.post("/api/v1/transit/keys", json={"key_name": "my-key-1"}, headers=headers)
    client.post("/api/v1/transit/keys", json={"key_name": "my-key-2"}, headers=headers)

    response = client.get("/api/v1/transit/keys", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert len(body["keys"]) == 2
    assert body["keys"][0]["key_name"] == "my-key-1"
    assert body["keys"][1]["key_name"] == "my-key-2"


def test_revoke_key(client: TestClient, unlocked_and_registered_user: tuple[TestClient, dict]):
    client, headers = unlocked_and_registered_user
    client.post("/api/v1/transit/keys", json={"key_name": "my-key"}, headers=headers)

    response = client.delete("/api/v1/transit/keys/my-key", headers=headers)
    assert response.status_code == 204

    response = client.get("/api/v1/transit/keys", headers=headers)
    assert len(response.json()["keys"]) == 0


def test_encrypt_decrypt_roundtrip(client: TestClient, unlocked_and_registered_user: tuple[TestClient, dict]):
    client, headers = unlocked_and_registered_user
    client.post("/api/v1/transit/keys", json={"key_name": "my-key"}, headers=headers)

    plaintext = base64.b64encode(b"hello world").decode("ascii")
    response = client.post(
        "/api/v1/transit/encrypt/my-key",
        json={"plaintext": plaintext},
        headers=headers,
    )
    assert response.status_code == 200
    ciphertext = response.json()["ciphertext"]

    response = client.post(
        "/api/v1/transit/decrypt",
        json={"ciphertext": ciphertext},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["plaintext"] == plaintext


def test_sign_verify_roundtrip(client: TestClient, unlocked_and_registered_user: tuple[TestClient, dict]):
    client, headers = unlocked_and_registered_user
    client.post(
        "/api/v1/transit/keys/sign",
        json={"key_name": "my-signing-key", "signing_algorithm": "ED25519"},
        headers=headers,
    )

    message = base64.b64encode(b"hello world").decode("ascii")
    response = client.post(
        "/api/v1/transit/sign/my-signing-key",
        json={"message": message, "message_type": "RAW"},
        headers=headers,
    )
    assert response.status_code == 200
    signature = response.json()["signature"]

    response = client.post(
        "/api/v1/transit/verify/my-signing-key",
        json={"message": message, "message_type": "RAW", "signature": signature},
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["signature_valid"] is True
    assert body["key_name"] == "my-signing-key"
    assert body["signing_algorithm"] == "ED25519"
