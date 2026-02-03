"""Access Event model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keyspider.db.session import Base


class AccessEvent(Base):
    __tablename__ = "access_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id"), nullable=False
    )
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)
    source_server_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("servers.id")
    )
    ssh_key_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("ssh_keys.id"))
    fingerprint: Mapped[str | None] = mapped_column(String(100))
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    auth_method: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(30), nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    raw_log_line: Mapped[str | None] = mapped_column(Text)
    log_source: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    target_server: Mapped["Server"] = relationship(
        back_populates="target_events", foreign_keys=[target_server_id]
    )
    source_server: Mapped["Server | None"] = relationship(
        back_populates="source_events", foreign_keys=[source_server_id]
    )
    ssh_key: Mapped["SSHKey | None"] = relationship(back_populates="access_events")

    __table_args__ = (
        Index("idx_access_events_target", "target_server_id", "event_time"),
        Index("idx_access_events_source_ip", "source_ip"),
        Index("idx_access_events_fingerprint", "fingerprint"),
        Index("idx_access_events_time", "event_time"),
        Index("idx_access_events_key", "ssh_key_id"),
    )
