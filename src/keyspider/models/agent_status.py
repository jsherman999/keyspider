"""Agent Status model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keyspider.db.session import Base


class AgentStatus(Base):
    __tablename__ = "agent_status"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    agent_version: Mapped[str | None] = mapped_column(String(50))
    deployment_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="not_deployed"
    )  # not_deployed | deploying | active | inactive | error
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    agent_token_hash: Mapped[str | None] = mapped_column(String(128))
    config: Mapped[dict | None] = mapped_column(JSONB)
    installed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    server: Mapped["Server"] = relationship(back_populates="agent_status")

    __table_args__ = (
        Index("idx_agent_status_server", "server_id"),
        Index("idx_agent_status_deployment", "deployment_status"),
    )
