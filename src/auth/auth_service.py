from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from src.auth.password_service import hash_password, normalize_email, verify_password, validate_password_strength
from src.auth.session_service import SessionService
from src.exceptions import MiniVaultError
from src.models.user import User


class AuthService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.session_service = SessionService(db)

    def register(self, email: str, passphrase: str, confirm_passphrase: str) -> dict[str, Any]:
        normalized_email = normalize_email(email)
        if not normalized_email or "@" not in normalized_email:
            raise MiniVaultError(400, "INVALID_EMAIL", "Invalid email address.")
        if self.db.query(User).filter(User.email == normalized_email).first() is not None:
            raise MiniVaultError(409, "EMAIL_ALREADY_EXISTS", "Email already exists.")
        if passphrase != confirm_passphrase:
            raise MiniVaultError(400, "PASSPHRASE_CONFIRMATION_MISMATCH", "Passphrase confirmation mismatch.")
        if not validate_password_strength(passphrase, email=normalized_email, min_length=10):
            raise MiniVaultError(400, "WEAK_PASSPHRASE", "User passphrase does not satisfy the security policy.")

        user = User(
            email=normalized_email,
            password_hash=hash_password(passphrase),
            failed_attempts=0,
            locked_until=None,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return {"message": "User registered successfully", "email": normalized_email}

    def login(self, email: str, passphrase: str) -> dict[str, Any]:
        normalized_email = normalize_email(email)
        user = self.db.query(User).filter(User.email == normalized_email).first()
        if user is None:
            raise MiniVaultError(401, "INVALID_CREDENTIALS", "Invalid email or passphrase.")

        now = datetime.now(timezone.utc)
        locked_until = user.locked_until
        if locked_until is not None and locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until is not None and locked_until > now:
            raise MiniVaultError(423, "ACCOUNT_TEMPORARILY_LOCKED", "Account is temporarily locked.", {"locked_until": locked_until.isoformat()})

        if locked_until is not None and locked_until <= now:
            user.locked_until = None
            user.failed_attempts = 0

        if not verify_password(user.password_hash, passphrase):
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = now + timedelta(minutes=5)
                self.db.commit()
                raise MiniVaultError(423, "ACCOUNT_TEMPORARILY_LOCKED", "Account is temporarily locked.", {"locked_until": user.locked_until.isoformat()})
            self.db.commit()
            raise MiniVaultError(401, "INVALID_CREDENTIALS", "Invalid email or passphrase.")

        user.failed_attempts = 0
        user.locked_until = None
        self.db.commit()
        token, _ = self.session_service.create_session(user)
        return {"access_token": token, "token_type": "bearer", "expires_in": 1800}
