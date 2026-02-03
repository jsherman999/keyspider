"""Recursive graph-building spider crawler."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from keyspider.core.key_scanner import DiscoveredKey, scan_server_keys
from keyspider.core.log_parser import AuthEvent, detect_log_paths, parse_log
from keyspider.core.ssh_connector import SSHConnectionPool
from keyspider.core.unreachable_detector import UnreachableDetector
from keyspider.db.queries import get_or_create
from keyspider.models.access_event import AccessEvent
from keyspider.models.access_path import AccessPath
from keyspider.models.key_location import KeyLocation
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey
from keyspider.models.unreachable_source import UnreachableSource

logger = logging.getLogger(__name__)


@dataclass
class SpiderProgress:
    """Tracks spider crawl progress."""

    servers_scanned: int = 0
    keys_found: int = 0
    events_parsed: int = 0
    unreachable_found: int = 0
    current_depth: int = 0
    current_server: str = ""
    visited: set[str] = field(default_factory=set)
    queue: list[tuple[str, int, int]] = field(default_factory=list)  # (hostname, port, depth)


class SpiderEngine:
    """Recursive SSH access graph crawler."""

    def __init__(
        self,
        pool: SSHConnectionPool,
        session: AsyncSession,
        max_depth: int = 10,
        progress_callback=None,
    ):
        self.pool = pool
        self.session = session
        self.max_depth = max_depth
        self.progress = SpiderProgress()
        self._progress_callback = progress_callback
        self._unreachable_detector = UnreachableDetector(pool)
        self._cancelled = False

    def cancel(self):
        """Cancel the crawl."""
        self._cancelled = True

    async def crawl(self, seed_hostname: str, seed_port: int = 22) -> SpiderProgress:
        """Start a spider crawl from a seed server."""
        self.progress.queue.append((seed_hostname, seed_port, 0))

        while self.progress.queue and not self._cancelled:
            hostname, port, depth = self.progress.queue.pop(0)

            server_key = f"{hostname}:{port}"
            if server_key in self.progress.visited:
                continue
            if depth > self.max_depth:
                continue

            self.progress.visited.add(server_key)
            self.progress.current_depth = depth
            self.progress.current_server = hostname

            await self._notify_progress()

            try:
                await self._process_server(hostname, port, depth)
            except Exception as e:
                logger.error("Error processing %s:%d: %s", hostname, port, e)
                continue

        return self.progress

    async def _process_server(self, hostname: str, port: int, depth: int) -> None:
        """Process a single server: parse logs, scan keys, follow chains."""
        # Ensure server exists in DB
        server, _ = await get_or_create(
            self.session,
            Server,
            defaults={
                "hostname": hostname,
                "ip_address": hostname,
                "ssh_port": port,
                "discovered_via": "scan" if depth > 0 else "manual",
                "is_reachable": True,
            },
            ip_address=hostname,
            ssh_port=port,
        )

        # 1. Parse auth logs
        events = await self._parse_server_logs(server)
        self.progress.events_parsed += len(events)

        # 2. Scan for key files
        keys = await self._scan_server_keys(server)
        self.progress.keys_found += len(keys)

        # 3. Store keys and events in DB
        await self._store_keys(server, keys)
        key_map = await self._store_events(server, events)

        # 4. Process source IPs and follow chains
        source_ips = {e.source_ip for e in events if e.source_ip}
        for source_ip in source_ips:
            await self._process_source_ip(source_ip, server, depth)

        # 5. Update server record
        server.last_scanned_at = datetime.now(timezone.utc)
        server.is_reachable = True
        self.progress.servers_scanned += 1

        await self.session.commit()

    async def _parse_server_logs(self, server: Server) -> list[AuthEvent]:
        """Parse auth logs on a server."""
        all_events: list[AuthEvent] = []
        log_paths = detect_log_paths(server.os_type)

        for log_path in log_paths:
            try:
                result = await self.pool.run_command(
                    server.ip_address, f"cat {log_path}", port=server.ssh_port
                )
                if result.exit_status == 0 and result.stdout:
                    events = parse_log(result.stdout, server.os_type)
                    all_events.extend(events)
                    break  # Found a working log path
            except Exception as e:
                logger.debug("Could not read %s on %s: %s", log_path, server.hostname, e)

        return all_events

    async def _scan_server_keys(self, server: Server) -> list[DiscoveredKey]:
        """Scan server for SSH key material."""
        try:
            return await scan_server_keys(
                self.pool, server.ip_address, server.ssh_port, server.os_type
            )
        except Exception as e:
            logger.warning("Key scan failed for %s: %s", server.hostname, e)
            return []

    async def _store_keys(self, server: Server, keys: list[DiscoveredKey]) -> None:
        """Store discovered keys in the database."""
        for dk in keys:
            if not dk.fingerprint_sha256:
                continue

            ssh_key, created = await get_or_create(
                self.session,
                SSHKey,
                defaults={
                    "fingerprint_md5": dk.fingerprint_md5,
                    "key_type": dk.key_type or "unknown",
                    "public_key_data": dk.public_key_data,
                    "comment": dk.comment,
                    "is_host_key": dk.is_host_key,
                },
                fingerprint_sha256=dk.fingerprint_sha256,
            )

            # Record location
            await get_or_create(
                self.session,
                KeyLocation,
                defaults={
                    "file_type": dk.file_type,
                    "unix_owner": dk.unix_owner,
                    "unix_permissions": dk.unix_permissions,
                    "last_verified_at": datetime.now(timezone.utc),
                },
                ssh_key_id=ssh_key.id,
                server_id=server.id,
                file_path=dk.file_path,
            )

    async def _store_events(self, server: Server, events: list[AuthEvent]) -> dict[str, int]:
        """Store auth events in the database and return fingerprint-to-key-id map."""
        key_map: dict[str, int] = {}

        for event in events:
            # Try to match fingerprint to known key
            ssh_key_id = None
            if event.fingerprint:
                if event.fingerprint not in key_map:
                    result = await self.session.execute(
                        select(SSHKey).where(
                            SSHKey.fingerprint_sha256 == event.fingerprint
                        )
                    )
                    key = result.scalar_one_or_none()
                    if key:
                        key_map[event.fingerprint] = key.id
                ssh_key_id = key_map.get(event.fingerprint)

            # Try to match source IP to known server
            source_server_id = None
            result = await self.session.execute(
                select(Server).where(Server.ip_address == event.source_ip)
            )
            source_server = result.scalar_one_or_none()
            if source_server:
                source_server_id = source_server.id

            access_event = AccessEvent(
                target_server_id=server.id,
                source_ip=event.source_ip,
                source_server_id=source_server_id,
                ssh_key_id=ssh_key_id,
                fingerprint=event.fingerprint,
                username=event.username,
                auth_method=event.auth_method,
                event_type=event.event_type,
                event_time=event.timestamp,
                raw_log_line=event.raw_line,
            )
            self.session.add(access_event)

            # Update or create access path
            if event.event_type == "accepted":
                now = datetime.now(timezone.utc)
                path, created = await get_or_create(
                    self.session,
                    AccessPath,
                    defaults={
                        "first_seen_at": event.timestamp,
                        "last_seen_at": event.timestamp,
                    },
                    source_server_id=source_server_id,
                    target_server_id=server.id,
                    ssh_key_id=ssh_key_id,
                    username=event.username,
                )
                if not created:
                    path.last_seen_at = event.timestamp
                    path.event_count += 1

        return key_map

    async def _process_source_ip(
        self, source_ip: str, target_server: Server, current_depth: int
    ) -> None:
        """Process a source IP: check reachability and queue for crawling."""
        # Check if already known
        result = await self.session.execute(
            select(Server).where(Server.ip_address == source_ip)
        )
        existing = result.scalar_one_or_none()

        if existing:
            server_key = f"{existing.ip_address}:{existing.ssh_port}"
            if server_key not in self.progress.visited:
                self.progress.queue.append(
                    (existing.ip_address, existing.ssh_port, current_depth + 1)
                )
            return

        # Check reachability from jump server
        is_reachable = await self.pool.check_reachable(source_ip)

        if is_reachable:
            # Add as new server and queue for crawling
            new_server, _ = await get_or_create(
                self.session,
                Server,
                defaults={
                    "hostname": source_ip,
                    "ssh_port": 22,
                    "discovered_via": "scan",
                    "is_reachable": True,
                },
                ip_address=source_ip,
            )
            self.progress.queue.append((source_ip, 22, current_depth + 1))
        else:
            # Flag as unreachable source
            severity = await self._unreachable_detector.classify_severity(
                source_ip, target_server
            )
            reverse_dns = await self._unreachable_detector.reverse_lookup(source_ip)

            await get_or_create(
                self.session,
                UnreachableSource,
                defaults={
                    "reverse_dns": reverse_dns,
                    "target_server_id": target_server.id,
                    "first_seen_at": datetime.now(timezone.utc),
                    "last_seen_at": datetime.now(timezone.utc),
                    "severity": severity,
                },
                source_ip=source_ip,
                fingerprint=None,
                target_server_id=target_server.id,
            )
            self.progress.unreachable_found += 1

    async def _notify_progress(self) -> None:
        """Notify progress callback if set."""
        if self._progress_callback:
            await self._progress_callback(self.progress)
