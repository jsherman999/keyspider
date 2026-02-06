"""SSH Key model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keyspider.db.session import Base


class SSHKey(Base):
    __tablename__ = "ssh_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    fingerprint_md5: Mapped[str | None] = mapped_column(String(60))
    key_type: Mapped[str] = mapped_column(String(20), nullable=False)
    key_bits: Mapped[int | None] = mapped_column(Integer)
    public_key_data: Mapped[str | None] = mapped_column(Text)
    comment: Mapped[str | None] = mapped_column(String(500))
    is_host_key: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    file_mtime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    estimated_age_days: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    locations: Mapped[list["KeyLocation"]] = relationship(back_populates="ssh_key", cascade="all, delete-orphan")
    access_events: Mapped[list["AccessEvent"]] = relationship(back_populates="ssh_key")
    access_paths: Mapped[list["AccessPath"]] = relationship(back_populates="ssh_key")

    __table_args__ = (
        Index("idx_ssh_keys_fingerprint", "fingerprint_sha256"),
        Index("idx_ssh_keys_md5", "fingerprint_md5"),
    )
