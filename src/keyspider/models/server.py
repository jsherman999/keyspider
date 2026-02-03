"""Server model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keyspider.db.session import Base


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    os_type: Mapped[str] = mapped_column(String(20), nullable=False, default="linux")
    os_version: Mapped[str | None] = mapped_column(String(100))
    ssh_port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    is_reachable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    discovered_via: Mapped[str | None] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    key_locations: Mapped[list["KeyLocation"]] = relationship(back_populates="server", cascade="all, delete-orphan")
    target_events: Mapped[list["AccessEvent"]] = relationship(
        back_populates="target_server", foreign_keys="AccessEvent.target_server_id"
    )
    source_events: Mapped[list["AccessEvent"]] = relationship(
        back_populates="source_server", foreign_keys="AccessEvent.source_server_id"
    )
    watch_sessions: Mapped[list["WatchSession"]] = relationship(back_populates="server")

    __table_args__ = (
        UniqueConstraint("ip_address", "ssh_port"),
        Index("idx_servers_ip", "ip_address"),
        Index("idx_servers_hostname", "hostname"),
    )
