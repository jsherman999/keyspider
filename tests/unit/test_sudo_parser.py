"""Tests for sudo log line parsing."""

import pytest
from datetime import datetime, timezone

from keyspider.core.log_parser import parse_sudo_line


class TestSudoParserBasic:
    def test_standard_sudo_line(self):
        line = "Feb  3 09:15:22 prod-web01 sudo[4321]: alice : TTY=pts/2 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart httpd"
        event = parse_sudo_line(line)
        assert event is not None
        assert event.username == "alice"
        assert event.tty == "pts/2"
        assert event.working_dir == "/home/alice"
        assert event.target_user == "root"
        assert event.command == "/usr/bin/systemctl restart httpd"
        assert event.success is True

    def test_sudo_different_target_user(self):
        line = "Jan 10 12:00:00 host sudo[100]: bob : TTY=tty1 ; PWD=/tmp ; USER=postgres ; COMMAND=/usr/bin/psql"
        event = parse_sudo_line(line)
        assert event is not None
        assert event.username == "bob"
        assert event.target_user == "postgres"
        assert event.command == "/usr/bin/psql"

    def test_sudo_with_args(self):
        line = "Mar 15 08:30:00 host sudo[200]: deploy : TTY=pts/0 ; PWD=/var/www/app ; USER=root ; COMMAND=/bin/rm -rf /tmp/cache/*"
        event = parse_sudo_line(line)
        assert event is not None
        assert event.command == "/bin/rm -rf /tmp/cache/*"

    def test_not_sudo_line(self):
        line = "Jan  5 14:23:01 host sshd[12345]: Accepted publickey for root from 10.0.1.50 port 52222 ssh2"
        assert parse_sudo_line(line) is None

    def test_empty_line(self):
        assert parse_sudo_line("") is None

    def test_whitespace_line(self):
        assert parse_sudo_line("   \t  ") is None


class TestSudoParserTimestamp:
    def test_with_reference_time(self):
        ref = datetime(2024, 6, 15, tzinfo=timezone.utc)
        line = "Jun  5 10:00:00 host sudo[1]: user1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id"
        event = parse_sudo_line(line, reference_time=ref)
        assert event is not None
        assert event.timestamp.year == 2024

    def test_with_year_rollover(self):
        # When (last_timestamp - parsed_dt) > 300 days, year decrements
        ref = datetime(2024, 6, 15, tzinfo=timezone.utc)
        last_ts = datetime(2024, 12, 28, tzinfo=timezone.utc)
        line = "Jan  2 10:00:00 host sudo[1]: user1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
        event = parse_sudo_line(line, reference_time=ref, last_timestamp=last_ts)
        assert event is not None
        assert event.timestamp.year == 2023


class TestSudoParserEdgeCases:
    def test_sudo_with_no_bracket_pid(self):
        """sudo without [PID] should still match if regex allows it."""
        line = "Jan  5 10:00:00 host sudo: user1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
        event = parse_sudo_line(line)
        # The regex has (?:\[\d+\])? so this should match
        assert event is not None
        assert event.username == "user1"

    def test_raw_line_preserved(self):
        line = "Jan  5 10:00:00 host sudo[1]: user1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
        event = parse_sudo_line(line)
        assert event is not None
        assert event.raw_line == line
