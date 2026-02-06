"""Tests for the key scanner module."""

import pytest

from keyspider.core.key_scanner import _strip_authorized_keys_options, DiscoveredKey


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


class TestDiscoveredKeyDataclass:
    def test_default_values(self):
        key = DiscoveredKey(
            fingerprint_sha256="SHA256:abc123",
            fingerprint_md5="MD5:aa:bb",
            key_type="rsa",
            public_key_data="ssh-rsa AAAA... user@host",
            comment="user@host",
            file_path="/root/.ssh/authorized_keys",
            file_type="authorized_keys",
            unix_owner=None,
            unix_permissions=None,
        )
        assert key.file_path == "/root/.ssh/authorized_keys"
        assert key.file_mtime is None
        assert key.file_size is None
        assert key.unix_owner is None
        assert key.unix_permissions is None

    def test_with_file_metadata(self):
        from datetime import datetime, timezone
        mtime = datetime(2023, 6, 15, tzinfo=timezone.utc)
        key = DiscoveredKey(
            fingerprint_sha256="SHA256:xyz789",
            fingerprint_md5=None,
            key_type="ed25519",
            public_key_data="ssh-ed25519 AAAA... admin",
            comment="admin",
            file_path="/root/.ssh/id_rsa.pub",
            file_type="public_key",
            unix_owner="root",
            unix_permissions="0644",
            file_mtime=mtime,
            file_size=512,
        )
        assert key.file_mtime == mtime
        assert key.file_size == 512
