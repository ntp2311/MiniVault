from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.auth.password_service import normalize_email
from src.database import SessionLocal
from src.exceptions import MiniVaultError
from src.models.session import Session as SessionModel
from src.models.user import User


class SessionService:
    def __init__(self, db: Session | None = None) -> None:
        self.db = db or SessionLocal()
        self.session_model = SessionModel
        self.user_model = User

    def get_user_by_email(self, email: str) -> User | None:
        return self.db.query(User).filter(User.email == normalize_email(email)).first()

    def create_session(self, user: User) -> tuple[str, SessionModel]:
        token = secrets.token_urlsafe(32)
        token_hash = self.hash_token(token)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
        session = SessionModel(user_id=user.id, token_hash=token_hash, expires_at=expires_at)
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return token, session

    def hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def get_session_from_token(self, token: str) -> tuple[SessionModel | None, User | None]:
        token_hash = self.hash_token(token)
        session = self.db.query(SessionModel).filter(SessionModel.token_hash == token_hash).first()
        if session is None:
            return None, None
        user = self.db.query(User).filter(User.id == session.user_id).first()
        return session, user

    def revoke_session(self, session: SessionModel) -> None:
        session.revoked = True
        self.db.commit()

    def close(self) -> None:
        self.db.close()


session_service = SessionService()
