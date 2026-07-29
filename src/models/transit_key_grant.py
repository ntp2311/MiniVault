from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base
from src.models.transit_key import TransitKey


class TransitKeyGrant(Base):
    __tablename__ = "transit_key_grants"
    __table_args__ = (
        UniqueConstraint(
            "transit_key_id",
            "grantee_email",
            "permission",
            name="uq_transit_key_grant",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transit_key_id: Mapped[int] = mapped_column(
        ForeignKey("transit_keys.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    grantee_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    permission: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    transit_key: Mapped[TransitKey] = relationship(backref="grants")
