from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pyotp
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


def test_setup_mfa_requires_authenticated_user(client: TestClient) -> None:
    response = client.post("/api/v1/auth/mfa/setup")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_setup_mfa_requires_unlocked_vault(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "mfa@example.com",
            "passphrase": "Mfa@Secure2026",
            "confirm_passphrase": "Mfa@Secure2026",
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa@example.com", "passphrase": "Mfa@Secure2026"},
    )
    response = client.post(
        "/api/v1/auth/mfa/setup",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert response.status_code == 423
    assert response.json()["error"]["code"] == "VAULT_LOCKED"


def test_setup_mfa_returns_provisioning_uri_and_secret(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "mfa2@example.com",
            "passphrase": "Mfa@Secure2026",
            "confirm_passphrase": "Mfa@Secure2026",
        },
    )
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
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa2@example.com", "passphrase": "Mfa@Secure2026"},
    )
    response = client.post(
        "/api/v1/auth/mfa/setup",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert response.status_code == 200
    assert response.json()["provisioning_uri"].startswith("otpauth://")
    assert response.json()["manual_entry_secret"]
    assert response.json()["expires_in"] == 600


def test_confirm_mfa_enables_mfa_and_stores_encrypted_secret(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "mfa3@example.com",
            "passphrase": "Mfa@Secure2026",
            "confirm_passphrase": "Mfa@Secure2026",
        },
    )
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
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa3@example.com", "passphrase": "Mfa@Secure2026"},
    )
    setup = client.post(
        "/api/v1/auth/mfa/setup",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    secret = setup.json()["manual_entry_secret"]
    otp_code = pyotp.TOTP(secret).now()

    confirm = client.post(
        "/api/v1/auth/mfa/confirm",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        json={"otp_code": otp_code},
    )
    assert confirm.status_code == 200

    from src.auth.session_service import session_service

    user = session_service.get_user_by_email("mfa3@example.com")
    assert user is not None
    assert user.mfa_enabled is True
    assert user.mfa_secret_encrypted_b64 is not None
    assert user.mfa_secret_encrypted_b64 != secret


def test_login_with_mfa_returns_challenge_token(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "mfa4@example.com",
            "passphrase": "Mfa@Secure2026",
            "confirm_passphrase": "Mfa@Secure2026",
        },
    )
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
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa4@example.com", "passphrase": "Mfa@Secure2026"},
    )
    setup = client.post(
        "/api/v1/auth/mfa/setup",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    otp_code = pyotp.TOTP(setup.json()["manual_entry_secret"]).now()
    client.post(
        "/api/v1/auth/mfa/confirm",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        json={"otp_code": otp_code},
    )

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa4@example.com", "passphrase": "Mfa@Secure2026"},
    )
    assert login_response.status_code == 200
    assert login_response.json()["mfa_required"] is True
    assert "mfa_challenge_token" in login_response.json()
    assert login_response.json()["expires_in"] == 300


def test_challenge_token_is_not_accepted_for_protected_routes(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "mfa5@example.com",
            "passphrase": "Mfa@Secure2026",
            "confirm_passphrase": "Mfa@Secure2026",
        },
    )
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
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa5@example.com", "passphrase": "Mfa@Secure2026"},
    )
    setup = client.post(
        "/api/v1/auth/mfa/setup",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    otp_code = pyotp.TOTP(setup.json()["manual_entry_secret"]).now()
    client.post(
        "/api/v1/auth/mfa/confirm",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        json={"otp_code": otp_code},
    )

    challenge_login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa5@example.com", "passphrase": "Mfa@Secure2026"},
    )
    challenge_token = challenge_login.json()["mfa_challenge_token"]

    protected = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {challenge_token}"},
    )
    assert protected.status_code == 401
    assert protected.json()["error"]["code"] == "UNAUTHENTICATED"


def test_correct_mfa_otp_returns_full_session_token(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "mfa6@example.com",
            "passphrase": "Mfa@Secure2026",
            "confirm_passphrase": "Mfa@Secure2026",
        },
    )
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
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa6@example.com", "passphrase": "Mfa@Secure2026"},
    )
    setup = client.post(
        "/api/v1/auth/mfa/setup",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    otp_code = pyotp.TOTP(setup.json()["manual_entry_secret"]).now()
    client.post(
        "/api/v1/auth/mfa/confirm",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        json={"otp_code": otp_code},
    )

    challenge_login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa6@example.com", "passphrase": "Mfa@Secure2026"},
    )
    response = client.post(
        "/api/v1/auth/login/mfa",
        json={
            "mfa_challenge_token": challenge_login.json()["mfa_challenge_token"],
            "otp_code": otp_code,
        },
    )
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["expires_in"] == 1800


def test_wrong_mfa_otp_does_not_issue_session_token(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "mfa7@example.com",
            "passphrase": "Mfa@Secure2026",
            "confirm_passphrase": "Mfa@Secure2026",
        },
    )
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
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa7@example.com", "passphrase": "Mfa@Secure2026"},
    )
    setup = client.post(
        "/api/v1/auth/mfa/setup",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    otp_code = pyotp.TOTP(setup.json()["manual_entry_secret"]).now()
    client.post(
        "/api/v1/auth/mfa/confirm",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        json={"otp_code": otp_code},
    )

    challenge_login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa7@example.com", "passphrase": "Mfa@Secure2026"},
    )
    response = client.post(
        "/api/v1/auth/login/mfa",
        json={
            "mfa_challenge_token": challenge_login.json()["mfa_challenge_token"],
            "otp_code": "000000",
        },
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_OTP"


def test_replay_otp_is_rejected(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "mfa8@example.com",
            "passphrase": "Mfa@Secure2026",
            "confirm_passphrase": "Mfa@Secure2026",
        },
    )
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
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa8@example.com", "passphrase": "Mfa@Secure2026"},
    )
    setup = client.post(
        "/api/v1/auth/mfa/setup",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    otp_code = pyotp.TOTP(setup.json()["manual_entry_secret"]).now()
    client.post(
        "/api/v1/auth/mfa/confirm",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        json={"otp_code": otp_code},
    )

    challenge_login = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa8@example.com", "passphrase": "Mfa@Secure2026"},
    )
    first = client.post(
        "/api/v1/auth/login/mfa",
        json={
            "mfa_challenge_token": challenge_login.json()["mfa_challenge_token"],
            "otp_code": otp_code,
        },
    )
    second = client.post(
        "/api/v1/auth/login/mfa",
        json={
            "mfa_challenge_token": challenge_login.json()["mfa_challenge_token"],
            "otp_code": otp_code,
        },
    )
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "OTP_REPLAYED"
