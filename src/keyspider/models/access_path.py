"""Access Path model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keyspider.db.session import Base


class AccessPath(Base):
    __tablename__ = "access_paths"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_server_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("servers.id"))
    target_server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id"), nullable=False
    )
    ssh_key_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("ssh_keys.id"))
    username: Mapped[str | None] = mapped_column(String(100))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    source_server: Mapped["Server | None"] = relationship(foreign_keys=[source_server_id])
    target_server: Mapped["Server"] = relationship(foreign_keys=[target_server_id])
    ssh_key: Mapped["SSHKey | None"] = relationship(back_populates="access_paths")

    __table_args__ = (
        UniqueConstraint("source_server_id", "target_server_id", "ssh_key_id", "username"),
        Index("idx_access_paths_source", "source_server_id"),
        Index("idx_access_paths_target", "target_server_id"),
    )
