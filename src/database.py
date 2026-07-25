from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from src.config import settings


class Base(DeclarativeBase):
    pass


def get_engine():
    return create_engine(
        settings.mini_vault_db_url,
        connect_args={"check_same_thread": False} if settings.mini_vault_db_url.startswith("sqlite") else {},
        future=True,
    )


engine = get_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from src.models import session, user, vault_metadata  # noqa: F401

    Base.metadata.create_all(bind=engine)
