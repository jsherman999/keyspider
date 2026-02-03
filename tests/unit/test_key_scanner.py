"""Tests for the key scanner module."""

import pytest

from keyspider.core.key_scanner import _strip_authorized_keys_options


class TestStripAuthorizedKeysOptions:
    def test_plain_key(self):
        line = "ssh-rsa AAAA... user@host"
        result = _strip_authorized_keys_options(line)
        assert result == "ssh-rsa AAAA... user@host"

    def test_with_options(self):
        line = 'command="/usr/bin/git-shell",no-pty ssh-rsa AAAA... deploy@ci'
        result = _strip_authorized_keys_options(line)
        assert result == "ssh-rsa AAAA... deploy@ci"

    def test_with_from_option(self):
        line = 'from="10.0.0.0/8" ssh-ed25519 AAAA... admin'
        result = _strip_authorized_keys_options(line)
        assert result == "ssh-ed25519 AAAA... admin"

    def test_no_key_type(self):
        line = "some random text without a key"
        result = _strip_authorized_keys_options(line)
        assert result is None

    def test_ecdsa_key(self):
        line = "ecdsa-sha2-nistp256 AAAA... user@host"
        result = _strip_authorized_keys_options(line)
        assert result == "ecdsa-sha2-nistp256 AAAA... user@host"
