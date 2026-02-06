"""Application configuration via pydantic-settings."""

from __future__ import annotations

import json
from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "", "case_sensitive": False}

    # Database
    database_url: str = "postgresql+asyncpg://keyspider:keyspider_secret@localhost:5432/keyspider"
    database_sync_url: str = "postgresql://keyspider:keyspider_secret@localhost:5432/keyspider"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # SSH
    ssh_key_path: str = "/root/.ssh/id_rsa"
    ssh_known_hosts: str | None = None
    ssh_connect_timeout: int = 10
    ssh_command_timeout: int = 30
    ssh_max_connections: int = 50
    ssh_per_server_limit: int = 3

    # Auth
    secret_key: str = "change-me-in-production"
    access_token_expire_minutes: int = 60
    algorithm: str = "HS256"

    # CORS
    cors_origins: list[str] = ["http://localhost:3000"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return json.loads(v)
        return v

    # Spider
    spider_default_depth: int = 10
    spider_max_depth: int = 50

    # Log scanning
    log_max_lines_initial: int = 50000
    log_max_lines_incremental: int = 50000

    # Watcher
    watcher_reconnect_delay: int = 5
    watcher_max_reconnect_delay: int = 300


settings = Settings()
