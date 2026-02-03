"""Unreachable source identification and classification."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from functools import lru_cache

from keyspider.core.ssh_connector import SSHConnectionPool
from keyspider.models.server import Server

logger = logging.getLogger(__name__)

# RFC1918 private address ranges
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 ULA
]


class UnreachableDetector:
    """Detects and classifies unreachable SSH sources."""

    def __init__(self, pool: SSHConnectionPool):
        self.pool = pool
        self._reachability_cache: dict[str, tuple[bool, float]] = {}
        self._cache_ttl = 3600  # 1 hour

    async def check_reachable(self, ip: str, port: int = 22) -> bool:
        """Check if an IP is reachable via SSH, with caching."""
        import time

        cache_key = f"{ip}:{port}"
        if cache_key in self._reachability_cache:
            is_reachable, cached_at = self._reachability_cache[cache_key]
            if time.time() - cached_at < self._cache_ttl:
                return is_reachable

        is_reachable = await self.pool.check_reachable(ip, port)
        self._reachability_cache[cache_key] = (is_reachable, time.time())
        return is_reachable

    async def reverse_lookup(self, ip: str) -> str | None:
        """Attempt reverse DNS lookup for an IP."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: socket.gethostbyaddr(ip)
            )
            return result[0]
        except (socket.herror, socket.gaierror, OSError):
            return None

    def is_private_ip(self, ip: str) -> bool:
        """Check if an IP is in a private (RFC1918/ULA) range."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in _PRIVATE_RANGES)
        except ValueError:
            return False

    async def classify_severity(
        self,
        source_ip: str,
        target_server: Server,
        username: str | None = None,
        fingerprint: str | None = None,
    ) -> str:
        """Classify the severity of an unreachable source.

        Severity levels:
        - critical: Root key fingerprint used from unreachable source
        - high: Any key used from unreachable, non-RFC1918 source
        - medium: Key from unreachable RFC1918 (internal) source
        - low: Failed auth attempts from unreachable source
        """
        is_private = self.is_private_ip(source_ip)

        if username == "root" and fingerprint:
            return "critical"

        if fingerprint and not is_private:
            return "high"

        if fingerprint and is_private:
            return "medium"

        return "low"

    async def scan_unreachable_sources(
        self,
        source_ips: list[str],
        target_server: Server,
    ) -> list[dict]:
        """Scan a list of source IPs for unreachable ones.

        Returns list of dicts with IP, reachability, severity info.
        """
        results = []
        tasks = [self.check_reachable(ip) for ip in source_ips]
        reachability = await asyncio.gather(*tasks, return_exceptions=True)

        for ip, is_reachable in zip(source_ips, reachability):
            if isinstance(is_reachable, Exception):
                is_reachable = False

            if not is_reachable:
                reverse_dns = await self.reverse_lookup(ip)
                severity = await self.classify_severity(ip, target_server)
                results.append({
                    "source_ip": ip,
                    "reverse_dns": reverse_dns,
                    "severity": severity,
                    "is_private": self.is_private_ip(ip),
                })

        return results
