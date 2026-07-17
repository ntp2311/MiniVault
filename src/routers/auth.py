from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from src.auth.auth_service import AuthService
from src.auth.dependencies import get_current_user, get_db
from src.exceptions import MiniVaultError, error_response
from src.models.user import User
from src.schemas.auth import AuthResponse, LoginRequest, MeResponse, RegisterRequest

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=dict)
def register(payload: RegisterRequest, db: Annotated[Session, Depends(get_db)]) -> dict:
    try:
        auth_service = AuthService(db)
        return auth_service.register(payload.email, payload.passphrase, payload.confirm_passphrase)
    except MiniVaultError as exc:
        raise exc


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest, db: Annotated[Session, Depends(get_db)]) -> AuthResponse:
    try:
        auth_service = AuthService(db)
        result = auth_service.login(payload.email, payload.passphrase)
        return AuthResponse(**result)
    except MiniVaultError as exc:
        raise exc


@router.get("/me", response_model=MeResponse)
def me(current_user: Annotated[User, Depends(get_current_user)]) -> MeResponse:
    return MeResponse(id=current_user.id, email=current_user.email)


@router.post("/logout")
def logout(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    try:
        from src.auth.session_service import SessionService

        authorization = request.headers.get("authorization", "")
        token = authorization.split(" ", 1)[1].strip() if authorization.startswith("Bearer ") else ""
        session_service = SessionService(db)
        session, _ = session_service.get_session_from_token(token)
        if session is not None:
            session_service.revoke_session(session)
        return {"message": "Logged out successfully"}
    except MiniVaultError as exc:
        raise exc
