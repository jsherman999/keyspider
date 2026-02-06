#!/usr/bin/env python3
"""Keyspider Agent - lightweight data collector deployed to monitored servers.

Single-file agent with zero external dependencies (stdlib only).
Deployed via SSH, runs as a systemd service.

Features:
- Heartbeat: POST /api/agent/heartbeat every 60s
- SSH event collection: tail auth logs incrementally (byte offset tracking)
- Sudo event collection: parse sudo lines from same logs
- Key inventory: scan ~/.ssh dirs and /etc/ssh host keys on demand
- Auth: Bearer token (unique per server, generated at deploy)
- Daemonization: runs as systemd service
- Graceful shutdown: signal handlers for SIGTERM/SIGINT
- Rotation detection: if file shrinks, re-read from 0
"""

import hashlib
import http.client
import json
import logging
import os
import re
import signal
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# ─── CONFIG (injected at deploy time) ───
CONFIG = {
    "api_url": "https://keyspider.example.com",
    "agent_token": "PLACEHOLDER_TOKEN",
    "server_id": 0,
    "heartbeat_interval": 60,
    "collect_interval": 30,
    "log_paths": ["/var/log/auth.log", "/var/log/secure"],
    "agent_version": "1.0.0",
}
# ─── END CONFIG ───

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [keyspider-agent] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("keyspider-agent")

# Regex patterns for SSH auth log parsing
_ACCEPTED_RE = re.compile(
    r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted\s+(publickey|password|keyboard-interactive)\s+"
    r"for\s+(\S+)\s+from\s+([\d.]+|[0-9a-fA-F:]+)\s+port\s+(\d+)"
    r"(?:\s+ssh2:\s+\S+\s+(\S+))?"
)

_FAILED_RE = re.compile(
    r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed\s+(publickey|password|keyboard-interactive)\s+"
    r"for\s+(?:invalid user\s+)?(\S+)\s+from\s+([\d.]+|[0-9a-fA-F:]+)\s+port\s+(\d+)"
    r"(?:\s+ssh2:\s+\S+\s+(\S+))?"
)

_SUDO_RE = re.compile(
    r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sudo(?:\[\d+\])?:\s+"
    r"(\S+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.*)"
)


class KeyspiderAgent:
    """Main agent class."""

    def __init__(self, config: dict):
        self.config = config
        self.api_url = config["api_url"]
        self.token = config["agent_token"]
        self.server_id = config["server_id"]
        self.heartbeat_interval = config.get("heartbeat_interval", 60)
        self.collect_interval = config.get("collect_interval", 30)
        self.log_paths = config.get("log_paths", ["/var/log/auth.log", "/var/log/secure"])
        self.running = True

        # Tracking state
        self._log_offsets: dict[str, int] = {}  # path -> byte offset
        self._last_heartbeat = 0.0
        self._last_collect = 0.0

        # Parse API URL
        parsed = urlparse(self.api_url)
        self.api_host = parsed.hostname
        self.api_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.api_scheme = parsed.scheme
        self.api_path_prefix = parsed.path.rstrip("/")

    def _make_request(self, method: str, path: str, body: dict | None = None) -> dict | None:
        """Make an HTTP request to the Keyspider API."""
        full_path = f"{self.api_path_prefix}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        try:
            if self.api_scheme == "https":
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(self.api_host, self.api_port, context=ctx, timeout=30)
            else:
                conn = http.client.HTTPConnection(self.api_host, self.api_port, timeout=30)

            payload = json.dumps(body).encode() if body else None
            conn.request(method, full_path, body=payload, headers=headers)
            response = conn.getresponse()
            data = response.read().decode()
            conn.close()

            if response.status >= 400:
                logger.warning("API %s %s returned %d: %s", method, full_path, response.status, data[:200])
                return None

            return json.loads(data) if data else {}
        except Exception as e:
            logger.error("API request failed: %s %s: %s", method, full_path, e)
            return None

    def send_heartbeat(self):
        """Send a heartbeat to the API."""
        self._make_request("POST", "/api/agent/heartbeat", {
            "server_id": self.server_id,
            "agent_version": self.config.get("agent_version", "1.0.0"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._last_heartbeat = time.time()

    def collect_log_events(self):
        """Read new log entries incrementally and send them to the API."""
        ssh_events = []
        sudo_events = []

        for log_path in self.log_paths:
            if not os.path.exists(log_path):
                continue

            try:
                file_size = os.path.getsize(log_path)
                prev_offset = self._log_offsets.get(log_path, 0)

                # Rotation detection: file shrank
                if file_size < prev_offset:
                    logger.info("Log rotation detected for %s, re-reading from start", log_path)
                    prev_offset = 0

                if file_size == prev_offset:
                    continue  # No new data

                with open(log_path, "r", errors="replace") as f:
                    f.seek(prev_offset)
                    new_content = f.read()
                    self._log_offsets[log_path] = f.tell()

                for line in new_content.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    # Parse SSH events
                    ssh_event = self._parse_ssh_line(line)
                    if ssh_event:
                        ssh_events.append(ssh_event)

                    # Parse sudo events
                    sudo_event = self._parse_sudo_line(line)
                    if sudo_event:
                        sudo_events.append(sudo_event)

            except PermissionError:
                logger.warning("Permission denied reading %s", log_path)
            except Exception as e:
                logger.error("Error reading %s: %s", log_path, e)

        # Send events in batches
        if ssh_events:
            self._make_request("POST", "/api/agent/events", {
                "server_id": self.server_id,
                "events": ssh_events,
            })
            logger.info("Sent %d SSH events", len(ssh_events))

        if sudo_events:
            self._make_request("POST", "/api/agent/sudo-events", {
                "server_id": self.server_id,
                "events": sudo_events,
            })
            logger.info("Sent %d sudo events", len(sudo_events))

        self._last_collect = time.time()

    def _parse_ssh_line(self, line: str) -> dict | None:
        """Parse an SSH auth log line into a dict."""
        if "sshd[" not in line:
            return None

        for regex, event_type in [(_ACCEPTED_RE, "accepted"), (_FAILED_RE, "failed")]:
            m = regex.match(line)
            if m:
                groups = m.groups()
                return {
                    "timestamp": self._parse_timestamp(groups[0]),
                    "auth_method": groups[1],
                    "username": groups[2],
                    "source_ip": groups[3],
                    "port": int(groups[4]),
                    "fingerprint": groups[5] if len(groups) > 5 else None,
                    "event_type": event_type,
                    "raw_line": line,
                }
        return None

    def _parse_sudo_line(self, line: str) -> dict | None:
        """Parse a sudo log line into a dict."""
        m = _SUDO_RE.match(line)
        if m:
            groups = m.groups()
            return {
                "timestamp": self._parse_timestamp(groups[0]),
                "username": groups[1],
                "tty": groups[2],
                "working_dir": groups[3],
                "target_user": groups[4],
                "command": groups[5].strip(),
                "success": True,
                "raw_line": line,
            }
        return None

    def _parse_timestamp(self, ts_str: str) -> str:
        """Parse a syslog timestamp and return ISO format."""
        ts_str = re.sub(r"\s+", " ", ts_str.strip())
        year = datetime.now().year
        try:
            dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            return datetime.now(timezone.utc).isoformat()

    def scan_keys(self):
        """Scan for SSH keys and send inventory to API."""
        keys = []

        # Scan /etc/ssh host keys
        ssh_dir = Path("/etc/ssh")
        if ssh_dir.exists():
            for pub_file in ssh_dir.glob("ssh_host_*_key.pub"):
                try:
                    content = pub_file.read_text().strip()
                    if content:
                        stat = pub_file.stat()
                        keys.append({
                            "public_key_data": content,
                            "file_path": str(pub_file),
                            "file_type": "host_key",
                            "unix_owner": "root",
                            "unix_permissions": oct(stat.st_mode & 0o7777)[2:],
                            "file_mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                            "file_size": stat.st_size,
                            "is_host_key": True,
                        })
                except Exception as e:
                    logger.debug("Error reading %s: %s", pub_file, e)

        # Scan user home directories
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) < 7:
                        continue
                    username, home, shell = parts[0], parts[5], parts[6]
                    if shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false"):
                        continue
                    ssh_user_dir = Path(home) / ".ssh"
                    if ssh_user_dir.exists():
                        self._scan_user_keys(ssh_user_dir, username, keys)
        except Exception as e:
            logger.debug("Error reading /etc/passwd: %s", e)

        if keys:
            self._make_request("POST", "/api/agent/keys", {
                "server_id": self.server_id,
                "keys": keys,
            })
            logger.info("Sent %d key inventory items", len(keys))

    def _scan_user_keys(self, ssh_dir: Path, username: str, keys: list):
        """Scan a user's .ssh directory for keys."""
        for name in ["authorized_keys", "authorized_keys2"]:
            ak = ssh_dir / name
            if ak.exists():
                try:
                    content = ak.read_text()
                    stat = ak.stat()
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # Extract key data
                        for kt in ("ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-nistp"):
                            idx = line.find(kt)
                            if idx >= 0:
                                key_data = line[idx:]
                                keys.append({
                                    "public_key_data": key_data,
                                    "file_path": str(ak),
                                    "file_type": "authorized_keys",
                                    "unix_owner": username,
                                    "unix_permissions": oct(stat.st_mode & 0o7777)[2:],
                                    "file_mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                                    "file_size": stat.st_size,
                                    "is_host_key": False,
                                })
                                break
                except Exception as e:
                    logger.debug("Error reading %s: %s", ak, e)

        # Public key files
        for pattern in ["id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub", "id_dsa.pub"]:
            pub = ssh_dir / pattern
            if pub.exists():
                try:
                    content = pub.read_text().strip()
                    stat = pub.stat()
                    if content:
                        keys.append({
                            "public_key_data": content,
                            "file_path": str(pub),
                            "file_type": "public_key",
                            "unix_owner": username,
                            "unix_permissions": oct(stat.st_mode & 0o7777)[2:],
                            "file_mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                            "file_size": stat.st_size,
                            "is_host_key": False,
                        })
                except Exception as e:
                    logger.debug("Error reading %s: %s", pub, e)

    def run(self):
        """Main agent loop."""
        logger.info(
            "Keyspider agent starting for server_id=%d, api=%s",
            self.server_id, self.api_url,
        )

        # Initial actions
        self.send_heartbeat()
        self.collect_log_events()
        self.scan_keys()

        while self.running:
            now = time.time()

            if now - self._last_heartbeat >= self.heartbeat_interval:
                self.send_heartbeat()

            if now - self._last_collect >= self.collect_interval:
                self.collect_log_events()

            time.sleep(1)

        logger.info("Keyspider agent stopped")

    def stop(self, signum=None, frame=None):
        """Graceful shutdown handler."""
        logger.info("Received signal %s, shutting down...", signum)
        self.running = False


def main():
    agent = KeyspiderAgent(CONFIG)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)

    agent.run()


if __name__ == "__main__":
    main()
