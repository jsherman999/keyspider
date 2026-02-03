"""Watch Session model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keyspider.db.session import Base


class WatchSession(Base):
    __tablename__ = "watch_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    ssh_pid: Mapped[int | None] = mapped_column(Integer)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    events_captured: Mapped[int] = mapped_column(Integer, default=0)
    auto_spider: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    spider_depth: Mapped[int] = mapped_column(Integer, default=3)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    server: Mapped["Server"] = relationship(back_populates="watch_sessions")
