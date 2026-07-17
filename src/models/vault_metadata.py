from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from src.database import Base


class VaultMetadata(Base):
    __tablename__ = "vault_metadata"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    initialized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    kdf_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    kdf_salt_b64: Mapped[str] = mapped_column(String(255), nullable=False)
    kdf_parameters_json: Mapped[str] = mapped_column(String(1024), nullable=False)
    nonce_b64: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_dek_b64: Mapped[str] = mapped_column(String(1024), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
