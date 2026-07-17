from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Generator

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from src.auth.session_service import SessionService
from src.core.vault_state import vault_state
from src.database import SessionLocal
from src.exceptions import MiniVaultError
from src.models.user import User
from src.models.vault_metadata import VaultMetadata


# Swagger/FastAPI sẽ dùng security scheme này để tạo nút Authorize.
bearer_scheme = HTTPBearer(
    scheme_name="BearerAuth",
    description="Nhập access_token nhận được từ API /api/v1/auth/login.",
    auto_error=False,
)


def get_db() -> Generator[Session, None, None]:
    """
    Tạo một database session cho mỗi request
    và tự động đóng session sau khi request kết thúc.
    """
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def require_vault_unlocked(
    db: Annotated[Session, Depends(get_db)],
) -> None:
    """
    Chặn request nếu Vault chưa được khởi tạo hoặc đang bị khóa.
    """

    vault_metadata = db.query(VaultMetadata).first()

    if vault_metadata is None:
        raise MiniVaultError(
            404,
            "VAULT_NOT_INITIALIZED",
            "Vault has not been initialized.",
        )

    if vault_state.get_dek() is None:
        raise MiniVaultError(
            423,
            "VAULT_LOCKED",
            "Vault is locked.",
        )


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """
    Đọc Bearer token từ Authorization header,
    kiểm tra session rồi trả về người dùng hiện tại.
    """

    if credentials is None:
        raise MiniVaultError(
            401,
            "UNAUTHENTICATED",
            "Authentication required.",
        )

    if credentials.scheme.lower() != "bearer":
        raise MiniVaultError(
            401,
            "UNAUTHENTICATED",
            "Bearer authentication is required.",
        )

    token = credentials.credentials.strip()

    if not token:
        raise MiniVaultError(
            401,
            "UNAUTHENTICATED",
            "Authentication required.",
        )

    session_service = SessionService(db)
    session, user = session_service.get_session_from_token(token)

    if session is None or user is None:
        raise MiniVaultError(
            401,
            "UNAUTHENTICATED",
            "Invalid session token.",
        )

    if session.revoked:
        raise MiniVaultError(
            401,
            "UNAUTHENTICATED",
            "Session has been revoked.",
        )

    expires_at = session.expires_at

    # SQLite thường trả datetime không có timezone.
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        raise MiniVaultError(
            401,
            "SESSION_EXPIRED",
            "Session has expired.",
        )

    return user


def require_authenticated_unlocked_user(
    _: Annotated[None, Depends(require_vault_unlocked)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """
    Dependency kết hợp:
    1. Vault phải được mở khóa.
    2. Session token phải hợp lệ.

    Trả về người dùng hiện tại để Feature 1 và Feature 2 sử dụng.
    """
    return current_user