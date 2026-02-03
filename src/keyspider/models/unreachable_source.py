"""Unreachable Source model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keyspider.db.session import Base


class UnreachableSource(Base):
    __tablename__ = "unreachable_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)
    reverse_dns: Mapped[str | None] = mapped_column(String(255))
    fingerprint: Mapped[str | None] = mapped_column(String(100))
    ssh_key_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("ssh_keys.id"))
    target_server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id"), nullable=False
    )
    username: Mapped[str | None] = mapped_column(String(100))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="high")
    notes: Mapped[str | None] = mapped_column(Text)
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    acknowledged_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    target_server: Mapped["Server"] = relationship()
    ssh_key: Mapped["SSHKey | None"] = relationship()
    acknowledged_user: Mapped["User | None"] = relationship()

    __table_args__ = (
        Index("idx_unreachable_source_ip", "source_ip"),
        Index("idx_unreachable_severity", "severity", "acknowledged"),
    )
