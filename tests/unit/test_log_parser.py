"""Tests for the SSH auth log parser."""

import pytest

from keyspider.core.log_parser import parse_line, parse_log, detect_log_paths


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


class TestDetectLogPaths:
    def test_linux_paths(self):
        paths = detect_log_paths("linux")
        assert "/var/log/auth.log" in paths
        assert "/var/log/secure" in paths

    def test_aix_paths(self):
        paths = detect_log_paths("aix")
        assert "/var/adm/syslog" in paths
