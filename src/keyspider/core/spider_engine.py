"""Recursive graph-building spider crawler."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from keyspider.config import settings
from keyspider.core.key_scanner import DiscoveredKey, scan_server_keys
from keyspider.core.log_parser import (
    AuthEvent,
    detect_log_paths,
    parse_log,
    parse_journalctl_output,
)
from keyspider.core.sftp_reader import SFTPReader
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

        # Check if agent is active for this server
        if server.prefer_agent:
            from keyspider.models.agent_status import AgentStatus
            result = await self.session.execute(
                select(AgentStatus).where(
                    AgentStatus.server_id == server.id,
                    AgentStatus.deployment_status == "active",
                )
            )
            agent = result.scalar_one_or_none()
            if agent and agent.last_heartbeat_at:
                age = (datetime.now(timezone.utc) - agent.last_heartbeat_at).total_seconds()
                if age < 300:  # 5 minutes
                    # Agent is active, skip SSH scanning
                    server.last_scanned_at = datetime.now(timezone.utc)
                    self.progress.servers_scanned += 1
                    await self.session.commit()
                    return

        # Get SSH connection for this server
        wrapper = await self.pool.get_connection(hostname, port)
        try:
            conn = wrapper.conn

            # 1. Parse auth logs
            events = await self._parse_server_logs(server, conn)
            self.progress.events_parsed += len(events)

            # 2. Scan for key files
            keys = await self._scan_server_keys(server, conn)
            self.progress.keys_found += len(keys)

            # 3. Store keys and events in DB (batch operations)
            await self._store_keys(server, keys)
            await self._store_events(server, events)

            # 4. Cross-reference graph layers
            await self._cross_reference_layers(server)

            # 5. Process source IPs and follow chains
            source_ips = {e.source_ip for e in events if e.source_ip}
            for source_ip in source_ips:
                await self._process_source_ip(source_ip, server, depth)

            # 6. Update server record
            server.last_scanned_at = datetime.now(timezone.utc)
            server.is_reachable = True
            self.progress.servers_scanned += 1

            await self.session.commit()
        finally:
            await self.pool.release_connection(wrapper.wrapper_id)

    async def _parse_server_logs(
        self, server: Server, conn
    ) -> list[AuthEvent]:
        """Parse auth logs on a server using journalctl or SFTP."""
        all_events: list[AuthEvent] = []

        max_lines = settings.log_max_lines_initial
        if server.scan_watermark:
            max_lines = settings.log_max_lines_incremental

        # Try journalctl first (structured output with real timestamps)
        try:
            cmd = f"journalctl -u sshd --output=json -n {max_lines}"
            if server.scan_watermark:
                cmd += f' --since="{server.scan_watermark}"'
            result = await asyncio.wait_for(
                conn.run(cmd, check=False), timeout=30
            )
            if result.exit_status == 0 and result.stdout:
                events = parse_journalctl_output(result.stdout)
                if events:
                    # Filter by watermark
                    if server.scan_watermark:
                        try:
                            wm = datetime.fromisoformat(server.scan_watermark)
                            events = [e for e in events if e.timestamp > wm]
                        except ValueError:
                            pass
                    # Update watermark
                    if events:
                        latest = max(e.timestamp for e in events)
                        server.scan_watermark = latest.isoformat()
                    return events
        except Exception:
            pass  # journalctl not available, fall back to file

        # Fall back to SFTP file reading
        log_paths = detect_log_paths(server.os_type)
        for log_path in log_paths:
            try:
                # Get file info for rotation detection
                file_info = await SFTPReader.stat_file(conn, log_path)
                if file_info is None:
                    continue

                current_size = file_info.size
                reference_time = file_info.mtime

                # Detect log rotation
                if (
                    server.last_log_size is not None
                    and current_size < server.last_log_size
                ):
                    # File shrank - rotation happened, re-read from start
                    max_lines = settings.log_max_lines_initial

                content = await SFTPReader.read_file_tail(
                    conn, log_path, max_lines=max_lines
                )
                if content:
                    events = parse_log(content, server.os_type, reference_time)

                    # Filter by watermark for incremental scanning
                    if server.scan_watermark and events:
                        try:
                            wm = datetime.fromisoformat(server.scan_watermark)
                            events = [e for e in events if e.timestamp > wm]
                        except ValueError:
                            pass

                    # Update watermark and log size
                    if events:
                        latest = max(e.timestamp for e in events)
                        server.scan_watermark = latest.isoformat()
                    server.last_log_size = current_size

                    all_events.extend(events)
                    break  # Found a working log path
            except Exception as e:
                logger.debug("Could not read %s on %s: %s", log_path, server.hostname, e)

        return all_events

    async def _scan_server_keys(
        self, server: Server, conn
    ) -> list[DiscoveredKey]:
        """Scan server for SSH key material."""
        try:
            return await scan_server_keys(
                conn, server.ip_address, server.ssh_port, server.os_type
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

            # Update file_mtime on SSHKey (keep oldest)
            if dk.file_mtime:
                if ssh_key.file_mtime is None or dk.file_mtime < ssh_key.file_mtime:
                    ssh_key.file_mtime = dk.file_mtime
                if ssh_key.file_mtime:
                    ssh_key.estimated_age_days = (
                        datetime.now(timezone.utc) - ssh_key.file_mtime
                    ).days

            # Determine graph layer
            graph_layer = "authorization" if dk.file_type == "authorized_keys" else "authorization"

            # Record location
            kl, kl_created = await get_or_create(
                self.session,
                KeyLocation,
                defaults={
                    "file_type": dk.file_type,
                    "unix_owner": dk.unix_owner,
                    "unix_permissions": dk.unix_permissions,
                    "graph_layer": graph_layer,
                    "file_mtime": dk.file_mtime,
                    "file_size": dk.file_size,
                    "last_verified_at": datetime.now(timezone.utc),
                },
                ssh_key_id=ssh_key.id,
                server_id=server.id,
                file_path=dk.file_path,
            )
            if not kl_created:
                kl.last_verified_at = datetime.now(timezone.utc)
                kl.file_mtime = dk.file_mtime
                kl.file_size = dk.file_size
                kl.unix_permissions = dk.unix_permissions

    async def _store_events(self, server: Server, events: list[AuthEvent]) -> dict[str, int]:
        """Store auth events in the database and return fingerprint-to-key-id map."""
        if not events:
            return {}

        # Batch pre-fetch: fingerprint -> key_id
        fingerprints = {e.fingerprint for e in events if e.fingerprint}
        key_map: dict[str, int] = {}
        if fingerprints:
            result = await self.session.execute(
                select(SSHKey.fingerprint_sha256, SSHKey.id).where(
                    SSHKey.fingerprint_sha256.in_(fingerprints)
                )
            )
            for fp, kid in result.all():
                key_map[fp] = kid

        # Batch pre-fetch: source_ip -> server_id
        source_ips = {e.source_ip for e in events if e.source_ip}
        ip_map: dict[str, int] = {}
        if source_ips:
            result = await self.session.execute(
                select(Server.ip_address, Server.id).where(
                    Server.ip_address.in_(source_ips)
                )
            )
            for ip, sid in result.all():
                ip_map[ip] = sid

        # Bulk create access events
        access_events = []
        for event in events:
            ssh_key_id = key_map.get(event.fingerprint) if event.fingerprint else None
            source_server_id = ip_map.get(event.source_ip)

            access_events.append(AccessEvent(
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
            ))

        self.session.add_all(access_events)

        # Batch update/create access paths for accepted events
        for event in events:
            if event.event_type != "accepted":
                continue

            ssh_key_id = key_map.get(event.fingerprint) if event.fingerprint else None
            source_server_id = ip_map.get(event.source_ip)

            path, created = await get_or_create(
                self.session,
                AccessPath,
                defaults={
                    "first_seen_at": event.timestamp,
                    "last_seen_at": event.timestamp,
                    "is_used": True,
                },
                source_server_id=source_server_id,
                target_server_id=server.id,
                ssh_key_id=ssh_key_id,
                username=event.username,
            )
            if not created:
                path.last_seen_at = event.timestamp
                path.event_count += 1
                path.is_used = True

        return key_map

    async def _cross_reference_layers(self, server: Server) -> None:
        """After storing keys and events, reconcile graph layers.

        - Keys in authorized_keys that are also seen in logs -> "both"
        - Keys seen in logs but not in authorized_keys -> create "usage" location
        - Update access_path is_authorized flags
        """
        # Get all authorized key fingerprints on this server
        result = await self.session.execute(
            select(KeyLocation.ssh_key_id).where(
                KeyLocation.server_id == server.id,
                KeyLocation.file_type == "authorized_keys",
            )
        )
        authorized_key_ids = {row[0] for row in result.all()}

        # Get all key IDs seen in accepted events on this server
        result = await self.session.execute(
            select(AccessEvent.ssh_key_id).where(
                AccessEvent.target_server_id == server.id,
                AccessEvent.event_type == "accepted",
                AccessEvent.ssh_key_id.isnot(None),
            ).distinct()
        )
        used_key_ids = {row[0] for row in result.all()}

        # Keys that are both authorized and used
        both_ids = authorized_key_ids & used_key_ids
        if both_ids:
            result = await self.session.execute(
                select(KeyLocation).where(
                    KeyLocation.server_id == server.id,
                    KeyLocation.ssh_key_id.in_(both_ids),
                    KeyLocation.file_type == "authorized_keys",
                )
            )
            for kl in result.scalars().all():
                kl.graph_layer = "both"

        # Update access paths with is_authorized flag
        result = await self.session.execute(
            select(AccessPath).where(
                AccessPath.target_server_id == server.id,
                AccessPath.ssh_key_id.isnot(None),
            )
        )
        for path in result.scalars().all():
            path.is_authorized = path.ssh_key_id in authorized_key_ids
            path.is_used = path.ssh_key_id in used_key_ids

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
