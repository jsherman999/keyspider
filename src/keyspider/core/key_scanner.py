"""Key file discovery and fingerprinting on remote servers."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from keyspider.core.fingerprint import (
    calculate_md5_fingerprint,
    calculate_sha256_fingerprint,
    detect_key_type,
    extract_comment,
)
from keyspider.core.ssh_connector import SSHConnectionPool

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredKey:
    """A key discovered on a remote server."""

    fingerprint_sha256: str | None
    fingerprint_md5: str | None
    key_type: str | None
    public_key_data: str
    comment: str | None
    file_path: str
    file_type: str  # private_key | public_key | authorized_keys | host_key
    unix_owner: str | None
    unix_permissions: str | None
    is_host_key: bool = False


async def scan_server_keys(
    pool: SSHConnectionPool,
    hostname: str,
    port: int = 22,
    os_type: str = "linux",
) -> list[DiscoveredKey]:
    """Scan a server for all SSH key material."""
    keys: list[DiscoveredKey] = []

    # 1. Get list of user home directories
    home_dirs = await _get_home_directories(pool, hostname, port, os_type)

    # 2. Scan authorized_keys and identity files for each user
    for username, home_dir in home_dirs:
        user_keys = await _scan_user_ssh_dir(pool, hostname, port, username, home_dir)
        keys.extend(user_keys)

    # 3. Scan host keys
    host_keys = await _scan_host_keys(pool, hostname, port)
    keys.extend(host_keys)

    logger.info("Found %d keys on %s:%d", len(keys), hostname, port)
    return keys


async def _get_home_directories(
    pool: SSHConnectionPool, hostname: str, port: int, os_type: str
) -> list[tuple[str, str]]:
    """Parse /etc/passwd to get user home directories."""
    try:
        result = await pool.run_command(
            hostname,
            "cat /etc/passwd",
            port=port,
        )
        if result.exit_status != 0:
            logger.warning("Failed to read /etc/passwd on %s", hostname)
            return [("root", "/root")]

        users = []
        for line in result.stdout.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 6:
                username = parts[0]
                home = parts[5]
                shell = parts[6] if len(parts) > 6 else ""
                # Skip system users with nologin/false shells
                if shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false"):
                    continue
                if home and not home.startswith("/dev"):
                    users.append((username, home))
        return users or [("root", "/root")]

    except Exception as e:
        logger.warning("Error getting home directories from %s: %s", hostname, e)
        return [("root", "/root")]


async def _scan_user_ssh_dir(
    pool: SSHConnectionPool,
    hostname: str,
    port: int,
    username: str,
    home_dir: str,
) -> list[DiscoveredKey]:
    """Scan a user's .ssh directory for keys."""
    keys: list[DiscoveredKey] = []
    ssh_dir = f"{home_dir}/.ssh"

    # Check authorized_keys
    for ak_path in [f"{ssh_dir}/authorized_keys", f"{ssh_dir}/authorized_keys2"]:
        ak_keys = await _parse_authorized_keys(pool, hostname, port, ak_path, username)
        keys.extend(ak_keys)

    # Check identity files (public keys)
    identity_patterns = ["id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub", "id_dsa.pub"]
    for pattern in identity_patterns:
        pub_path = f"{ssh_dir}/{pattern}"
        pub_key = await _read_public_key_file(pool, hostname, port, pub_path, username)
        if pub_key:
            keys.append(pub_key)

    # Check for private keys (we only record metadata, never content)
    priv_patterns = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]
    for pattern in priv_patterns:
        priv_path = f"{ssh_dir}/{pattern}"
        priv_meta = await _check_private_key(pool, hostname, port, priv_path, username)
        if priv_meta:
            keys.append(priv_meta)

    return keys


async def _parse_authorized_keys(
    pool: SSHConnectionPool,
    hostname: str,
    port: int,
    file_path: str,
    owner: str,
) -> list[DiscoveredKey]:
    """Parse an authorized_keys file for public keys."""
    keys: list[DiscoveredKey] = []
    try:
        result = await pool.run_command(hostname, f"cat {file_path}", port=port)
        if result.exit_status != 0:
            return []

        perms = await _get_file_permissions(pool, hostname, port, file_path)

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle options prefix (e.g., 'no-pty,command="..." ssh-rsa ...')
            key_data = _strip_authorized_keys_options(line)
            if not key_data:
                continue

            fp_sha = calculate_sha256_fingerprint(key_data)
            fp_md5 = calculate_md5_fingerprint(key_data)
            key_type = detect_key_type(key_data)
            comment = extract_comment(key_data)

            if fp_sha or fp_md5:
                keys.append(DiscoveredKey(
                    fingerprint_sha256=fp_sha,
                    fingerprint_md5=fp_md5,
                    key_type=key_type,
                    public_key_data=key_data,
                    comment=comment,
                    file_path=file_path,
                    file_type="authorized_keys",
                    unix_owner=owner,
                    unix_permissions=perms,
                ))
    except Exception as e:
        logger.debug("Error reading %s on %s: %s", file_path, hostname, e)

    return keys


async def _read_public_key_file(
    pool: SSHConnectionPool,
    hostname: str,
    port: int,
    file_path: str,
    owner: str,
) -> DiscoveredKey | None:
    """Read a single public key file."""
    try:
        result = await pool.run_command(hostname, f"cat {file_path}", port=port)
        if result.exit_status != 0:
            return None

        key_data = result.stdout.strip()
        if not key_data:
            return None

        perms = await _get_file_permissions(pool, hostname, port, file_path)
        fp_sha = calculate_sha256_fingerprint(key_data)
        fp_md5 = calculate_md5_fingerprint(key_data)

        if not fp_sha and not fp_md5:
            return None

        return DiscoveredKey(
            fingerprint_sha256=fp_sha,
            fingerprint_md5=fp_md5,
            key_type=detect_key_type(key_data),
            public_key_data=key_data,
            comment=extract_comment(key_data),
            file_path=file_path,
            file_type="public_key",
            unix_owner=owner,
            unix_permissions=perms,
        )
    except Exception as e:
        logger.debug("Error reading %s on %s: %s", file_path, hostname, e)
        return None


async def _check_private_key(
    pool: SSHConnectionPool,
    hostname: str,
    port: int,
    file_path: str,
    owner: str,
) -> DiscoveredKey | None:
    """Check if a private key file exists and get its metadata.

    IMPORTANT: We never read or store private key content.
    We derive the fingerprint from the corresponding .pub file.
    """
    try:
        result = await pool.run_command(hostname, f"test -f {file_path} && echo exists", port=port)
        if result.exit_status != 0 or "exists" not in (result.stdout or ""):
            return None

        perms = await _get_file_permissions(pool, hostname, port, file_path)

        # Try to get fingerprint from the corresponding public key file
        pub_path = f"{file_path}.pub"
        pub_result = await pool.run_command(hostname, f"cat {pub_path}", port=port)
        fp_sha = None
        fp_md5 = None
        key_type = None
        pub_data = ""

        if pub_result.exit_status == 0 and pub_result.stdout:
            pub_data = pub_result.stdout.strip()
            fp_sha = calculate_sha256_fingerprint(pub_data)
            fp_md5 = calculate_md5_fingerprint(pub_data)
            key_type = detect_key_type(pub_data)

        return DiscoveredKey(
            fingerprint_sha256=fp_sha,
            fingerprint_md5=fp_md5,
            key_type=key_type,
            public_key_data=pub_data,
            comment=extract_comment(pub_data) if pub_data else None,
            file_path=file_path,
            file_type="private_key",
            unix_owner=owner,
            unix_permissions=perms,
        )
    except Exception as e:
        logger.debug("Error checking %s on %s: %s", file_path, hostname, e)
        return None


async def _scan_host_keys(
    pool: SSHConnectionPool,
    hostname: str,
    port: int,
) -> list[DiscoveredKey]:
    """Scan for SSH host keys."""
    keys: list[DiscoveredKey] = []
    host_key_patterns = [
        "/etc/ssh/ssh_host_rsa_key.pub",
        "/etc/ssh/ssh_host_ed25519_key.pub",
        "/etc/ssh/ssh_host_ecdsa_key.pub",
        "/etc/ssh/ssh_host_dsa_key.pub",
    ]

    for path in host_key_patterns:
        try:
            result = await pool.run_command(hostname, f"cat {path}", port=port)
            if result.exit_status != 0:
                continue

            key_data = result.stdout.strip()
            if not key_data:
                continue

            fp_sha = calculate_sha256_fingerprint(key_data)
            fp_md5 = calculate_md5_fingerprint(key_data)

            if fp_sha or fp_md5:
                perms = await _get_file_permissions(pool, hostname, port, path)
                keys.append(DiscoveredKey(
                    fingerprint_sha256=fp_sha,
                    fingerprint_md5=fp_md5,
                    key_type=detect_key_type(key_data),
                    public_key_data=key_data,
                    comment=extract_comment(key_data),
                    file_path=path,
                    file_type="host_key",
                    unix_owner="root",
                    unix_permissions=perms,
                    is_host_key=True,
                ))
        except Exception as e:
            logger.debug("Error reading host key %s on %s: %s", path, hostname, e)

    return keys


async def _get_file_permissions(
    pool: SSHConnectionPool,
    hostname: str,
    port: int,
    file_path: str,
) -> str | None:
    """Get file permissions as octal string."""
    try:
        result = await pool.run_command(
            hostname, f"stat -c '%a' {file_path} 2>/dev/null || stat -f '%Lp' {file_path} 2>/dev/null",
            port=port,
        )
        if result.exit_status == 0 and result.stdout:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _strip_authorized_keys_options(line: str) -> str | None:
    """Strip options prefix from an authorized_keys line.

    authorized_keys lines can have options before the key type:
    command="...",no-pty ssh-rsa AAAA... comment
    """
    key_types = ("ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-nistp")
    for kt in key_types:
        idx = line.find(kt)
        if idx >= 0:
            return line[idx:]
    return None
