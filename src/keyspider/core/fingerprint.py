"""Fingerprint calculation and matching."""

from __future__ import annotations

import base64
import hashlib
import logging
import re

logger = logging.getLogger(__name__)


def calculate_sha256_fingerprint(public_key_data: str) -> str | None:
    """Calculate SHA256 fingerprint from a public key string.

    Accepts formats:
    - Full authorized_keys line: "ssh-rsa AAAA... comment"
    - Just the base64 part: "AAAA..."
    - PEM-formatted public key

    Returns: "SHA256:base64digest" or None on error.
    """
    try:
        key_b64 = _extract_key_data(public_key_data)
        if not key_b64:
            return None
        key_bytes = base64.b64decode(key_b64)
        digest = hashlib.sha256(key_bytes).digest()
        fp = base64.b64encode(digest).rstrip(b"=").decode("ascii")
        return f"SHA256:{fp}"
    except Exception as e:
        logger.debug("Failed to calculate SHA256 fingerprint: %s", e)
        return None


def calculate_md5_fingerprint(public_key_data: str) -> str | None:
    """Calculate MD5 fingerprint from a public key string.

    Returns: "MD5:xx:xx:xx:..." or None on error.
    """
    try:
        key_b64 = _extract_key_data(public_key_data)
        if not key_b64:
            return None
        key_bytes = base64.b64decode(key_b64)
        digest = hashlib.md5(key_bytes).hexdigest()
        fp = ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
        return f"MD5:{fp}"
    except Exception as e:
        logger.debug("Failed to calculate MD5 fingerprint: %s", e)
        return None


def _extract_key_data(public_key_data: str) -> str | None:
    """Extract the base64-encoded key data from various public key formats."""
    public_key_data = public_key_data.strip()

    # authorized_keys format: type base64 [comment]
    parts = public_key_data.split()
    if len(parts) >= 2 and parts[0] in (
        "ssh-rsa", "ssh-ed25519", "ssh-dss",
        "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    ):
        return parts[1]

    # PEM format
    if public_key_data.startswith("-----"):
        lines = public_key_data.splitlines()
        b64_lines = [l for l in lines if not l.startswith("-----")]
        return "".join(b64_lines)

    # Assume it's raw base64
    if re.match(r"^[A-Za-z0-9+/=]+$", public_key_data):
        return public_key_data

    return None


def detect_key_type(public_key_data: str) -> str | None:
    """Detect the key type from a public key line."""
    parts = public_key_data.strip().split()
    if not parts:
        return None

    type_map = {
        "ssh-rsa": "rsa",
        "ssh-ed25519": "ed25519",
        "ssh-dss": "dsa",
        "ecdsa-sha2-nistp256": "ecdsa",
        "ecdsa-sha2-nistp384": "ecdsa",
        "ecdsa-sha2-nistp521": "ecdsa",
    }
    return type_map.get(parts[0])


def extract_comment(public_key_data: str) -> str | None:
    """Extract the comment from a public key line."""
    parts = public_key_data.strip().split(None, 2)
    if len(parts) >= 3:
        return parts[2]
    return None


def normalize_fingerprint(fingerprint: str) -> str:
    """Normalize a fingerprint string.

    Ensures SHA256: prefix is present and consistent.
    """
    fingerprint = fingerprint.strip()
    if fingerprint.startswith("SHA256:"):
        return fingerprint
    if fingerprint.startswith("MD5:"):
        return fingerprint
    # If no prefix, assume SHA256
    if ":" not in fingerprint or len(fingerprint) > 50:
        return f"SHA256:{fingerprint}"
    # Looks like MD5 (colon-separated hex)
    return f"MD5:{fingerprint}"


def fingerprints_match(fp1: str, fp2: str) -> bool:
    """Check if two fingerprints match (handles different formats)."""
    fp1 = normalize_fingerprint(fp1)
    fp2 = normalize_fingerprint(fp2)
    return fp1 == fp2
