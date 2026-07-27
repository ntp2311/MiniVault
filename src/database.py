from __future__ import annotations

import os

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from src.config import DB_PATH, settings


class Base(DeclarativeBase):
    pass


def get_engine():
    url = settings.mini_vault_db_url

    print("CWD =", os.getcwd())
    print("DATABASE_URL =", url)
    print("EXPECTED_DB_PATH =", DB_PATH.resolve())
    print("EXPECTED_DB_EXISTS =", DB_PATH.exists())

    return create_engine(
        url,
        connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
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
    from src.models import vault_metadata, user, session  # noqa: F401

    Base.metadata.create_all(bind=engine)


def debug_database_state() -> None:
    from src.models import VaultMetadata

    with SessionLocal() as db:
        count = db.scalar(select(func.count()).select_from(VaultMetadata))
        record = db.scalar(
            select(VaultMetadata)
            .order_by(VaultMetadata.id.asc())
            .limit(1)
        )

        print("VAULT_COUNT =", count)
        if record is not None:
            print("VAULT_ID =", record.id)
            print("VAULT_INITIALIZED =", record.initialized)
