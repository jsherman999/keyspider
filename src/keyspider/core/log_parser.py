"""Auth log parsing for Linux distros and AIX."""

from __future__ import annotations

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


def _parse_syslog_timestamp(ts_str: str, reference_year: int | None = None) -> datetime:
    """Parse a syslog timestamp (e.g., 'Jan  5 14:23:01') into a datetime.

    Syslog timestamps lack a year, so we use the reference year or current year.
    """
    year = reference_year or datetime.now(timezone.utc).year
    # Normalize whitespace (syslog uses double space for single-digit days)
    ts_str = re.sub(r"\s+", " ", ts_str.strip())
    try:
        dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def parse_line(line: str, os_type: str = "linux", reference_year: int | None = None) -> AuthEvent | None:
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
                timestamp=_parse_syslog_timestamp(groups["timestamp"], reference_year),
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


def parse_log(content: str, os_type: str = "linux", reference_year: int | None = None) -> list[AuthEvent]:
    """Parse an entire log file content into a list of AuthEvents."""
    events = []
    for line in content.splitlines():
        event = parse_line(line, os_type, reference_year)
        if event:
            events.append(event)
    return events


def detect_log_paths(os_type: str) -> list[str]:
    """Return the log file paths to check for a given OS type."""
    if os_type == "aix":
        return ["/var/adm/syslog", "/var/log/syslog"]
    # Linux - try both Debian and RHEL paths
    return ["/var/log/auth.log", "/var/log/secure"]
