from __future__ import annotations

import os

from sqlalchemy import create_engine, func, select, text
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


def init_db(engine_instance: object | None = None) -> None:
    from src.models import mfa_setup_challenge, session, user, vault_metadata  # noqa: F401

    target_engine = engine_instance or engine
    Base.metadata.create_all(bind=target_engine)
    migrate_existing_database(target_engine)


def migrate_existing_database(engine_instance: object | None = None) -> None:
    target_engine = engine_instance or engine
    if not str(target_engine.url).startswith("sqlite"):
        return

    with target_engine.begin() as connection:
        try:
            result = connection.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='users'"))
            if result.fetchone() is None:
                return
        except Exception:
            return

        columns = {row[1] for row in connection.execute(text("PRAGMA table_info(users)"))}
        if "mfa_enabled" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0"))
        if "mfa_secret_encrypted_b64" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN mfa_secret_encrypted_b64 VARCHAR(2048)"))
        if "last_totp_timecode" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN last_totp_timecode INTEGER"))

        challenges_columns = {row[1] for row in connection.execute(text("PRAGMA table_info(mfa_setup_challenges)"))}
        if "mfa_setup_challenges" not in {row[0] for row in connection.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}:
            connection.execute(text("CREATE TABLE mfa_setup_challenges (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, encrypted_secret_b64 VARCHAR(2048) NOT NULL, expires_at DATETIME NOT NULL, created_at DATETIME NOT NULL, FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE)"))
        elif "user_id" not in challenges_columns:
            connection.execute(text("ALTER TABLE mfa_setup_challenges ADD COLUMN user_id INTEGER"))
        elif "encrypted_secret_b64" not in challenges_columns:
            connection.execute(text("ALTER TABLE mfa_setup_challenges ADD COLUMN encrypted_secret_b64 VARCHAR(2048)"))


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
