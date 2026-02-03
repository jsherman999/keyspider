"""Tests for fingerprint calculation and matching."""

import pytest

from keyspider.core.fingerprint import (
    calculate_md5_fingerprint,
    calculate_sha256_fingerprint,
    detect_key_type,
    extract_comment,
    fingerprints_match,
    normalize_fingerprint,
)

# A known RSA public key for testing
SAMPLE_RSA_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7n test@example.com"
SAMPLE_ED25519_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI user@host"


class TestCalculateFingerprints:
    def test_sha256_from_authorized_keys_line(self):
        fp = calculate_sha256_fingerprint(SAMPLE_RSA_KEY)
        assert fp is not None
        assert fp.startswith("SHA256:")

    def test_sha256_from_ed25519(self):
        fp = calculate_sha256_fingerprint(SAMPLE_ED25519_KEY)
        assert fp is not None
        assert fp.startswith("SHA256:")

    def test_md5_from_authorized_keys_line(self):
        fp = calculate_md5_fingerprint(SAMPLE_RSA_KEY)
        assert fp is not None
        assert fp.startswith("MD5:")
        # MD5 fingerprint should be colon-separated hex
        parts = fp.replace("MD5:", "").split(":")
        assert len(parts) == 16

    def test_sha256_invalid_key(self):
        fp = calculate_sha256_fingerprint("not a valid key")
        assert fp is None

    def test_consistent_fingerprints(self):
        fp1 = calculate_sha256_fingerprint(SAMPLE_RSA_KEY)
        fp2 = calculate_sha256_fingerprint(SAMPLE_RSA_KEY)
        assert fp1 == fp2

    def test_different_keys_different_fingerprints(self):
        fp1 = calculate_sha256_fingerprint(SAMPLE_RSA_KEY)
        fp2 = calculate_sha256_fingerprint(SAMPLE_ED25519_KEY)
        assert fp1 != fp2


class TestDetectKeyType:
    def test_rsa(self):
        assert detect_key_type("ssh-rsa AAAA...") == "rsa"

    def test_ed25519(self):
        assert detect_key_type("ssh-ed25519 AAAA...") == "ed25519"

    def test_ecdsa(self):
        assert detect_key_type("ecdsa-sha2-nistp256 AAAA...") == "ecdsa"

    def test_dsa(self):
        assert detect_key_type("ssh-dss AAAA...") == "dsa"

    def test_unknown(self):
        assert detect_key_type("unknown-type AAAA...") is None

    def test_empty(self):
        assert detect_key_type("") is None


class TestExtractComment:
    def test_with_comment(self):
        assert extract_comment("ssh-rsa AAAA... user@host") == "user@host"

    def test_without_comment(self):
        assert extract_comment("ssh-rsa AAAA...") is None

    def test_multi_word_comment(self):
        assert extract_comment("ssh-rsa AAAA... my key comment") == "my key comment"


class TestNormalizeFingerprint:
    def test_sha256_prefix(self):
        assert normalize_fingerprint("SHA256:abc123") == "SHA256:abc123"

    def test_md5_prefix(self):
        assert normalize_fingerprint("MD5:aa:bb:cc") == "MD5:aa:bb:cc"

    def test_add_sha256_prefix(self):
        fp = normalize_fingerprint("abc123def456ghi789")
        assert fp == "SHA256:abc123def456ghi789"

    def test_detect_md5(self):
        fp = normalize_fingerprint("aa:bb:cc:dd:ee:ff")
        assert fp == "MD5:aa:bb:cc:dd:ee:ff"


class TestFingerprintsMatch:
    def test_same_fingerprint(self):
        assert fingerprints_match("SHA256:abc123", "SHA256:abc123")

    def test_different_fingerprint(self):
        assert not fingerprints_match("SHA256:abc123", "SHA256:xyz789")

    def test_with_and_without_prefix(self):
        assert fingerprints_match("SHA256:abc123def456ghi789", "abc123def456ghi789")
