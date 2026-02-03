"""Scan Job model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from keyspider.db.session import Base


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_type: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    initiated_by: Mapped[str] = mapped_column(String(30), nullable=False)
    seed_server_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("servers.id"))
    max_depth: Mapped[int | None] = mapped_column(Integer, default=10)
    config: Mapped[dict | None] = mapped_column(JSONB)
    servers_scanned: Mapped[int] = mapped_column(Integer, default=0)
    keys_found: Mapped[int] = mapped_column(Integer, default=0)
    events_parsed: Mapped[int] = mapped_column(Integer, default=0)
    unreachable_found: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
