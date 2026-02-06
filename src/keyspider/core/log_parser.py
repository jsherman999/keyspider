"""Auth log parsing for Linux distros and AIX."""

from __future__ import annotations

import json
import re
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class AuthEvent:
    """Parsed SSH authentication event."""

    timestamp: datetime
    source_ip: str
    username: str
    auth_method: str | None  # publickey | password | keyboard-interactive
    event_type: str  # accepted | failed | disconnected | invalid_user
    fingerprint: str | None  # SHA256:xxx or MD5:xx:xx:...
    port: int | None
    pid: int | None
    raw_line: str

    @property
    def fingerprint_normalized(self) -> str | None:
        """Return fingerprint in SHA256:xxx format if possible."""
        if not self.fingerprint:
            return None
        return self.fingerprint


# Debian/Ubuntu: /var/log/auth.log
# RHEL/CentOS: /var/log/secure
# Format: Mon DD HH:MM:SS hostname sshd[PID]: message

# Accepted publickey for root from 10.0.0.1 port 52222 ssh2: RSA SHA256:abcd1234
_ACCEPTED_KEY_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"Accepted\s+(?P<method>publickey|password|keyboard-interactive)\s+"
    r"for\s+(?P<username>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+|[0-9a-fA-F:]+)\s+"
    r"port\s+(?P<port>\d+)\s+"
    r"(?:ssh2:\s+\S+\s+(?P<fingerprint>\S+))?"
)

# Failed password for root from 10.0.0.1 port 52222 ssh2
# Failed publickey for root from 10.0.0.1 port 52222 ssh2: RSA SHA256:abcd1234
_FAILED_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"Failed\s+(?P<method>publickey|password|keyboard-interactive)\s+"
    r"for\s+(?:invalid user\s+)?(?P<username>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+|[0-9a-fA-F:]+)\s+"
    r"port\s+(?P<port>\d+)\s+"
    r"(?:ssh2:\s+\S+\s+(?P<fingerprint>\S+))?"
)

# Invalid user admin from 10.0.0.1 port 52222
_INVALID_USER_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"Invalid user\s+(?P<username>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+|[0-9a-fA-F:]+)\s+"
    r"port\s+(?P<port>\d+)"
)

# Disconnected from 10.0.0.1 port 52222
_DISCONNECT_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"Disconnected from\s+(?:authenticating\s+)?(?:user\s+(?P<username>\S+)\s+)?"
    r"(?P<ip>[\d.]+|[0-9a-fA-F:]+)\s+"
    r"port\s+(?P<port>\d+)"
)

# AIX syslog format
# timestamp hostname auth|security:info sshd[PID]: message
_AIX_ACCEPTED_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+(?:auth|security)[|:]\S*\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"Accepted\s+(?P<method>publickey|password|keyboard-interactive)\s+"
    r"for\s+(?P<username>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+|[0-9a-fA-F:]+)\s+"
    r"port\s+(?P<port>\d+)"
    r"(?:\s+ssh2:\s+\S+\s+(?P<fingerprint>\S+))?"
)

_AIX_FAILED_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+(?:auth|security)[|:]\S*\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"Failed\s+(?P<method>publickey|password|keyboard-interactive)\s+"
    r"for\s+(?:invalid user\s+)?(?P<username>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+|[0-9a-fA-F:]+)\s+"
    r"port\s+(?P<port>\d+)"
    r"(?:\s+ssh2:\s+\S+\s+(?P<fingerprint>\S+))?"
)

# Sudo log regex
_SUDO_RE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"sudo(?:\[\d+\])?:\s+"
    r"(?P<username>\S+)\s+:\s+"
    r"TTY=(?P<tty>\S+)\s+;\s+"
    r"PWD=(?P<pwd>\S+)\s+;\s+"
    r"USER=(?P<target_user>\S+)\s+;\s+"
    r"COMMAND=(?P<command>.+)"
)


def _parse_syslog_timestamp(
    ts_str: str,
    reference_time: datetime | None = None,
    last_timestamp: datetime | None = None,
) -> datetime:
    """Parse a syslog timestamp (e.g., 'Jan  5 14:23:01') into a datetime.

    Syslog timestamps lack a year, so we use the reference time year or current year.
    If a parsed timestamp jumps backwards >300 days compared to last_timestamp,
    we decrement the year (log spans year boundary).
    """
    year = datetime.now(timezone.utc).year
    if reference_time:
        year = reference_time.year

    # Normalize whitespace (syslog uses double space for single-digit days)
    ts_str = re.sub(r"\s+", " ", ts_str.strip())
    try:
        dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)

        # Year rollover detection
        if last_timestamp and (last_timestamp - dt).days > 300:
            year -= 1
            dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc)

        return dt
    except ValueError:
        return datetime.now(timezone.utc)


def parse_line(
    line: str,
    os_type: str = "linux",
    reference_time: datetime | None = None,
    last_timestamp: datetime | None = None,
) -> AuthEvent | None:
    """Parse a single log line into an AuthEvent, or None if not an SSH event."""
    line = line.strip()
    if not line or "sshd[" not in line:
        return None

    patterns: list[tuple[re.Pattern, str]]
    if os_type == "aix":
        patterns = [
            (_AIX_ACCEPTED_RE, "accepted"),
            (_AIX_FAILED_RE, "failed"),
        ]
    else:
        patterns = [
            (_ACCEPTED_KEY_RE, "accepted"),
            (_FAILED_RE, "failed"),
            (_INVALID_USER_RE, "invalid_user"),
            (_DISCONNECT_RE, "disconnected"),
        ]

    for pattern, event_type in patterns:
        m = pattern.match(line)
        if m:
            groups = m.groupdict()
            return AuthEvent(
                timestamp=_parse_syslog_timestamp(
                    groups["timestamp"], reference_time, last_timestamp
                ),
                source_ip=groups["ip"],
                username=groups.get("username", "unknown"),
                auth_method=groups.get("method"),
                event_type=event_type,
                fingerprint=groups.get("fingerprint"),
                port=int(groups["port"]) if groups.get("port") else None,
                pid=int(groups["pid"]) if groups.get("pid") else None,
                raw_line=line,
            )

    return None


def parse_log(
    content: str,
    os_type: str = "linux",
    reference_time: datetime | None = None,
) -> list[AuthEvent]:
    """Parse an entire log file content into a list of AuthEvents."""
    events = []
    last_ts: datetime | None = None
    for line in content.splitlines():
        event = parse_line(line, os_type, reference_time, last_ts)
        if event:
            last_ts = event.timestamp
            events.append(event)
    return events


@dataclass
class SudoLogEvent:
    """Parsed sudo event from syslog."""

    timestamp: datetime
    username: str
    tty: str
    working_dir: str
    target_user: str
    command: str
    raw_line: str
    success: bool = True


def parse_sudo_line(
    line: str,
    reference_time: datetime | None = None,
    last_timestamp: datetime | None = None,
) -> SudoLogEvent | None:
    """Parse a single sudo log line."""
    line = line.strip()
    if not line or "sudo" not in line:
        return None

    m = _SUDO_RE.match(line)
    if m:
        groups = m.groupdict()
        return SudoLogEvent(
            timestamp=_parse_syslog_timestamp(
                groups["timestamp"], reference_time, last_timestamp
            ),
            username=groups["username"],
            tty=groups["tty"],
            working_dir=groups["pwd"],
            target_user=groups["target_user"],
            command=groups["command"].strip(),
            raw_line=line,
        )
    return None


def parse_journalctl_json(json_line: str) -> AuthEvent | None:
    """Parse a single journalctl JSON line into an AuthEvent."""
    try:
        data = json.loads(json_line)
    except (json.JSONDecodeError, ValueError):
        return None

    message = data.get("MESSAGE", "")
    if not message or "sshd" not in data.get("SYSLOG_IDENTIFIER", ""):
        return None

    # Get timestamp from __REALTIME_TIMESTAMP (microseconds since epoch)
    ts_usec = data.get("__REALTIME_TIMESTAMP")
    if ts_usec:
        try:
            ts = datetime.fromtimestamp(int(ts_usec) / 1_000_000, tz=timezone.utc)
        except (ValueError, OSError):
            ts = datetime.now(timezone.utc)
    else:
        ts = datetime.now(timezone.utc)

    pid = data.get("_PID")

    # Try matching the message portion against our patterns
    # We construct a fake syslog line for the regex
    fake_line = f"Jan  1 00:00:00 host sshd[{pid or 0}]: {message}"
    event = parse_line(fake_line)
    if event:
        # Replace timestamp with the real one from journald
        event.timestamp = ts
        event.pid = int(pid) if pid else event.pid
        event.raw_line = json_line
        return event

    return None


def parse_journalctl_output(content: str) -> list[AuthEvent]:
    """Parse multi-line journalctl JSON output into AuthEvents."""
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        event = parse_journalctl_json(line)
        if event:
            events.append(event)
    return events


def detect_log_paths(os_type: str) -> list[str]:
    """Return the log file paths to check for a given OS type."""
    if os_type == "aix":
        return ["/var/adm/syslog", "/var/log/syslog"]
    # Linux - try both Debian and RHEL paths
    return ["/var/log/auth.log", "/var/log/secure"]
