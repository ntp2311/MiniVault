from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


def test_register_success(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"


def test_duplicate_email(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    second = client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "EMAIL_ALREADY_EXISTS"


def test_weak_user_passphrase(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "bob@example.com", "passphrase": "weak", "confirm_passphrase": "weak"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "WEAK_PASSPHRASE"


def test_login_success(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "passphrase": "Alice@Secure2026"},
    )
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["expires_in"] == 1800


def test_login_wrong_under_lockout_limit(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    for _ in range(4):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "passphrase": "WrongPass!1"},
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_login_fifth_attempt_lockout(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    for _ in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "passphrase": "WrongPass!1"},
        )
    assert response.status_code == 423
    assert response.json()["error"]["code"] == "ACCOUNT_TEMPORARILY_LOCKED"


def test_correct_password_during_lockout(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    for _ in range(5):
        client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "passphrase": "WrongPass!1"},
        )
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "passphrase": "Alice@Secure2026"},
    )
    assert response.status_code == 423
    assert response.json()["error"]["code"] == "ACCOUNT_TEMPORARILY_LOCKED"


def test_login_after_lockout_expires(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    for _ in range(5):
        client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "passphrase": "WrongPass!1"},
        )

    from src.auth.session_service import session_service

    user = session_service.get_user_by_email("alice@example.com")
    assert user is not None
    user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=6)
    session_service.db.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "passphrase": "Alice@Secure2026"},
    )
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"


def test_missing_token(client: TestClient) -> None:
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_invalid_token(client: TestClient) -> None:
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_expired_token(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "passphrase": "Alice@Secure2026"},
    )
    token = login.json()["access_token"]

    from src.auth.session_service import session_service

    session = session_service.db.query(session_service.session_model).filter_by(token_hash=session_service.hash_token(token)).first()
    session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    session_service.db.commit()

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "SESSION_EXPIRED"


def test_logout_invalidates_token(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "Alice@Secure2026",
            "confirm_passphrase": "Alice@Secure2026",
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "passphrase": "Alice@Secure2026"},
    )
    token = login.json()["access_token"]

    logout = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout.status_code == 200

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
