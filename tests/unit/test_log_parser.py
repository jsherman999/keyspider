"""Tests for the SSH auth log parser."""

import json
import pytest
from datetime import datetime, timezone

from keyspider.core.log_parser import (
    parse_line,
    parse_log,
    parse_sudo_line,
    parse_journalctl_json,
    parse_journalctl_output,
    detect_log_paths,
)


class TestParseLineLinux:
    def test_accepted_publickey(self):
        line = "Jan  5 14:23:01 webserver01 sshd[12345]: Accepted publickey for root from 10.0.1.50 port 52222 ssh2: RSA SHA256:abc123def456"
        event = parse_line(line)
        assert event is not None
        assert event.event_type == "accepted"
        assert event.auth_method == "publickey"
        assert event.username == "root"
        assert event.source_ip == "10.0.1.50"
        assert event.port == 52222
        assert event.pid == 12345
        assert event.fingerprint == "SHA256:abc123def456"

    def test_accepted_password(self):
        line = "Jan  5 14:23:45 webserver01 sshd[12346]: Accepted password for admin from 10.0.1.51 port 48392 ssh2"
        event = parse_line(line)
        assert event is not None
        assert event.event_type == "accepted"
        assert event.auth_method == "password"
        assert event.username == "admin"
        assert event.fingerprint is None

    def test_failed_password(self):
        line = "Jan  5 14:24:10 webserver01 sshd[12347]: Failed password for root from 192.168.1.100 port 39281 ssh2"
        event = parse_line(line)
        assert event is not None
        assert event.event_type == "failed"
        assert event.auth_method == "password"
        assert event.username == "root"
        assert event.source_ip == "192.168.1.100"

    def test_failed_publickey(self):
        line = "Jan  5 14:25:00 webserver01 sshd[12348]: Failed publickey for deploy from 10.0.2.10 port 41234 ssh2: ED25519 SHA256:xyz789abc456"
        event = parse_line(line)
        assert event is not None
        assert event.event_type == "failed"
        assert event.auth_method == "publickey"
        assert event.fingerprint == "SHA256:xyz789abc456"

    def test_invalid_user(self):
        line = "Jan  5 14:26:30 webserver01 sshd[12349]: Invalid user admin from 203.0.113.42 port 55123"
        event = parse_line(line)
        assert event is not None
        assert event.event_type == "invalid_user"
        assert event.username == "admin"
        assert event.source_ip == "203.0.113.42"

    def test_disconnect(self):
        line = "Jan  5 14:28:15 webserver01 sshd[12351]: Disconnected from user root 10.0.1.50 port 52222"
        event = parse_line(line)
        assert event is not None
        assert event.event_type == "disconnected"
        assert event.source_ip == "10.0.1.50"

    def test_non_ssh_line(self):
        line = "Jan  5 14:35:00 webserver01 cron[9999]: pam_unix(cron:session): session opened"
        event = parse_line(line)
        assert event is None

    def test_empty_line(self):
        assert parse_line("") is None
        assert parse_line("   ") is None


class TestParseLineAIX:
    def test_aix_accepted(self):
        line = "Jan  5 08:00:01 aixserver01 auth|security:info sshd[1001]: Accepted publickey for root from 10.20.0.5 port 45001 ssh2: RSA SHA256:aix_key_fp"
        event = parse_line(line, os_type="aix")
        assert event is not None
        assert event.event_type == "accepted"
        assert event.username == "root"
        assert event.source_ip == "10.20.0.5"

    def test_aix_failed(self):
        line = "Jan  5 08:01:30 aixserver01 auth|security:info sshd[1002]: Failed password for admin from 10.20.0.10 port 38201 ssh2"
        event = parse_line(line, os_type="aix")
        assert event is not None
        assert event.event_type == "failed"
        assert event.auth_method == "password"


class TestParseLineWithReferenceTime:
    def test_uses_reference_time_year(self):
        ref = datetime(2023, 6, 15, tzinfo=timezone.utc)
        line = "Jan  5 14:23:01 webserver01 sshd[12345]: Accepted publickey for root from 10.0.1.50 port 52222 ssh2: RSA SHA256:abc123"
        event = parse_line(line, reference_time=ref)
        assert event is not None
        assert event.timestamp.year == 2023

    def test_year_rollover_detection(self):
        # Simulate reading a log where we see a Dec entry after having seen a much
        # later timestamp. The rollover logic triggers when (last_timestamp - dt) > 300 days,
        # meaning the current entry appears to be from an earlier time in the year.
        # last_timestamp = Dec 2024, current line = Jan 2024 -> (Dec - Jan) > 300 days
        # -> the implementation decrements the year to 2023
        ref = datetime(2024, 6, 15, tzinfo=timezone.utc)
        last_ts = datetime(2024, 12, 28, tzinfo=timezone.utc)
        line = "Jan  2 10:00:00 host sshd[999]: Accepted password for root from 10.0.0.1 port 22 ssh2"
        event = parse_line(line, reference_time=ref, last_timestamp=last_ts)
        assert event is not None
        assert event.timestamp.year == 2023


class TestParseLog:
    def test_parse_full_debian_log(self, sample_auth_log_debian):
        events = parse_log(sample_auth_log_debian)
        # Should parse SSH events, skip non-SSH lines (cron)
        assert len(events) > 0
        accepted = [e for e in events if e.event_type == "accepted"]
        failed = [e for e in events if e.event_type == "failed"]
        assert len(accepted) >= 3
        assert len(failed) >= 2

    def test_parse_full_rhel_log(self, sample_auth_log_rhel):
        events = parse_log(sample_auth_log_rhel)
        assert len(events) > 0

    def test_parse_full_aix_log(self, sample_syslog_aix):
        events = parse_log(sample_syslog_aix, os_type="aix")
        assert len(events) > 0

    def test_parse_log_with_reference_time(self):
        ref = datetime(2023, 6, 1, tzinfo=timezone.utc)
        content = (
            "Jun  1 10:00:00 host sshd[1]: Accepted password for root from 10.0.0.1 port 22 ssh2\n"
            "Jun  1 10:01:00 host sshd[2]: Failed password for admin from 10.0.0.2 port 22 ssh2\n"
        )
        events = parse_log(content, reference_time=ref)
        assert len(events) == 2
        for e in events:
            assert e.timestamp.year == 2023

    def test_parse_log_tracks_last_timestamp(self):
        """Ensure parse_log passes last_timestamp through to sequential lines."""
        content = (
            "Jun  1 10:00:00 host sshd[1]: Accepted password for root from 10.0.0.1 port 22 ssh2\n"
            "Jun  1 10:01:00 host sshd[2]: Accepted password for root from 10.0.0.2 port 22 ssh2\n"
        )
        events = parse_log(content)
        assert len(events) == 2
        # Second event should come after first
        assert events[1].timestamp >= events[0].timestamp


class TestDetectLogPaths:
    def test_linux_paths(self):
        paths = detect_log_paths("linux")
        assert "/var/log/auth.log" in paths
        assert "/var/log/secure" in paths

    def test_aix_paths(self):
        paths = detect_log_paths("aix")
        assert "/var/adm/syslog" in paths


class TestParseSudoLine:
    def test_basic_sudo(self):
        line = "Jan  5 14:30:00 host sudo[1234]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update"
        event = parse_sudo_line(line)
        assert event is not None
        assert event.username == "admin"
        assert event.tty == "pts/0"
        assert event.working_dir == "/home/admin"
        assert event.target_user == "root"
        assert event.command == "/usr/bin/apt update"
        assert event.success is True

    def test_sudo_with_complex_command(self):
        line = "Jan  5 15:00:00 host sudo[5678]: deploy : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/systemctl restart nginx"
        event = parse_sudo_line(line)
        assert event is not None
        assert event.username == "deploy"
        assert event.command == "/bin/systemctl restart nginx"

    def test_non_sudo_line(self):
        line = "Jan  5 14:30:00 host sshd[1234]: Accepted password for root from 10.0.0.1 port 22 ssh2"
        event = parse_sudo_line(line)
        assert event is None

    def test_empty_line(self):
        assert parse_sudo_line("") is None
        assert parse_sudo_line("   ") is None

    def test_sudo_with_reference_time(self):
        ref = datetime(2023, 3, 1, tzinfo=timezone.utc)
        line = "Mar  1 10:00:00 host sudo[1]: user1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
        event = parse_sudo_line(line, reference_time=ref)
        assert event is not None
        assert event.timestamp.year == 2023


class TestParseJournalctlJson:
    def test_basic_accepted(self):
        data = {
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Accepted publickey for root from 10.0.0.1 port 22 ssh2: RSA SHA256:abcdef",
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "_PID": "1234",
        }
        event = parse_journalctl_json(json.dumps(data))
        assert event is not None
        assert event.event_type == "accepted"
        assert event.username == "root"
        assert event.source_ip == "10.0.0.1"
        assert event.fingerprint == "SHA256:abcdef"
        assert event.pid == 1234
        # Real timestamp should be used, not the fake syslog one
        assert event.timestamp.year >= 2023

    def test_non_sshd_message(self):
        data = {
            "SYSLOG_IDENTIFIER": "cron",
            "MESSAGE": "pam_unix session opened",
            "__REALTIME_TIMESTAMP": "1700000000000000",
        }
        event = parse_journalctl_json(json.dumps(data))
        assert event is None

    def test_invalid_json(self):
        event = parse_journalctl_json("not json at all")
        assert event is None

    def test_empty_message(self):
        data = {
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "",
            "__REALTIME_TIMESTAMP": "1700000000000000",
        }
        event = parse_journalctl_json(json.dumps(data))
        assert event is None

    def test_failed_password(self):
        data = {
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for admin from 192.168.1.1 port 22 ssh2",
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "_PID": "5678",
        }
        event = parse_journalctl_json(json.dumps(data))
        assert event is not None
        assert event.event_type == "failed"
        assert event.auth_method == "password"


class TestParseJournalctlOutput:
    def test_multi_line(self):
        lines = []
        for i, msg in enumerate([
            "Accepted publickey for root from 10.0.0.1 port 22 ssh2: RSA SHA256:abc",
            "Failed password for admin from 10.0.0.2 port 22 ssh2",
        ]):
            lines.append(json.dumps({
                "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": msg,
                "__REALTIME_TIMESTAMP": str(1700000000000000 + i * 1000000),
                "_PID": str(1000 + i),
            }))
        content = "\n".join(lines)
        events = parse_journalctl_output(content)
        assert len(events) == 2
        assert events[0].event_type == "accepted"
        assert events[1].event_type == "failed"

    def test_empty_content(self):
        events = parse_journalctl_output("")
        assert events == []

    def test_mixed_with_non_ssh(self):
        lines = [
            json.dumps({"SYSLOG_IDENTIFIER": "cron", "MESSAGE": "cron stuff", "__REALTIME_TIMESTAMP": "1700000000000000"}),
            json.dumps({"SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "Accepted password for root from 10.0.0.1 port 22 ssh2", "__REALTIME_TIMESTAMP": "1700000001000000", "_PID": "1"}),
        ]
        events = parse_journalctl_output("\n".join(lines))
        assert len(events) == 1
        assert events[0].event_type == "accepted"
