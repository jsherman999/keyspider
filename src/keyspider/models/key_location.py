"""Key Location model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keyspider.db.session import Base


class KeyLocation(Base):
    __tablename__ = "key_locations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ssh_key_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ssh_keys.id", ondelete="CASCADE"), nullable=False
    )
    server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False
    )
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_type: Mapped[str] = mapped_column(String(30), nullable=False)
    unix_owner: Mapped[str | None] = mapped_column(String(100))
    unix_permissions: Mapped[str | None] = mapped_column(String(10))
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    ssh_key: Mapped["SSHKey"] = relationship(back_populates="locations")
    server: Mapped["Server"] = relationship(back_populates="key_locations")

    __table_args__ = (
        UniqueConstraint("ssh_key_id", "server_id", "file_path"),
        Index("idx_key_locations_server", "server_id"),
        Index("idx_key_locations_key", "ssh_key_id"),
    )
