"""Sudo Event model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keyspider.db.session import Base


class SudoEvent(Base):
    __tablename__ = "sudo_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False
    )
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    command: Mapped[str | None] = mapped_column(Text)
    target_user: Mapped[str | None] = mapped_column(String(100))
    working_dir: Mapped[str | None] = mapped_column(String(1024))
    tty: Mapped[str | None] = mapped_column(String(50))
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    raw_log_line: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    server: Mapped["Server"] = relationship()

    __table_args__ = (
        Index("idx_sudo_events_server_time", "server_id", "event_time"),
        Index("idx_sudo_events_username", "username"),
    )
