"""Key file discovery and fingerprinting on remote servers."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime

import asyncssh

from keyspider.core.fingerprint import (
    calculate_md5_fingerprint,
    calculate_sha256_fingerprint,
    detect_key_type,
    extract_comment,
)
from keyspider.core.sftp_reader import SFTPReader

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
    file_mtime: datetime | None = None
    file_size: int | None = None


async def scan_server_keys(
    conn: asyncssh.SSHClientConnection,
    hostname: str,
    port: int = 22,
    os_type: str = "linux",
) -> list[DiscoveredKey]:
    """Scan a server for all SSH key material."""
    keys: list[DiscoveredKey] = []

    # 1. Get list of user home directories
    home_dirs = await _get_home_directories(conn, os_type)

    # 2. Scan authorized_keys and identity files for each user
    for username, home_dir in home_dirs:
        user_keys = await _scan_user_ssh_dir(conn, username, home_dir)
        keys.extend(user_keys)

    # 3. Scan host keys
    host_keys = await _scan_host_keys(conn)
    keys.extend(host_keys)

    logger.info("Found %d keys on %s:%d", len(keys), hostname, port)
    return keys


async def _get_home_directories(
    conn: asyncssh.SSHClientConnection, os_type: str
) -> list[tuple[str, str]]:
    """Parse /etc/passwd to get user home directories."""
    try:
        content = await SFTPReader.read_file(conn, "/etc/passwd")
        if not content:
            return [("root", "/root")]

        users = []
        for line in content.splitlines():
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
        logger.warning("Error getting home directories: %s", e)
        return [("root", "/root")]


async def _scan_user_ssh_dir(
    conn: asyncssh.SSHClientConnection,
    username: str,
    home_dir: str,
) -> list[DiscoveredKey]:
    """Scan a user's .ssh directory for keys."""
    keys: list[DiscoveredKey] = []
    ssh_dir = f"{home_dir}/.ssh"

    # Check authorized_keys
    for ak_path in [f"{ssh_dir}/authorized_keys", f"{ssh_dir}/authorized_keys2"]:
        ak_keys = await _parse_authorized_keys(conn, ak_path, username)
        keys.extend(ak_keys)

    # Check identity files (public keys)
    identity_patterns = ["id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub", "id_dsa.pub"]
    for pattern in identity_patterns:
        pub_path = f"{ssh_dir}/{pattern}"
        pub_key = await _read_public_key_file(conn, pub_path, username)
        if pub_key:
            keys.append(pub_key)

    # Check for private keys (we only record metadata, never content)
    priv_patterns = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]
    for pattern in priv_patterns:
        priv_path = f"{ssh_dir}/{pattern}"
        priv_meta = await _check_private_key(conn, priv_path, username)
        if priv_meta:
            keys.append(priv_meta)

    return keys


async def _parse_authorized_keys(
    conn: asyncssh.SSHClientConnection,
    file_path: str,
    owner: str,
) -> list[DiscoveredKey]:
    """Parse an authorized_keys file for public keys."""
    keys: list[DiscoveredKey] = []
    try:
        content = await SFTPReader.read_file(conn, file_path)
        if content is None:
            return []

        file_info = await SFTPReader.stat_file(conn, file_path)
        perms = file_info.permissions if file_info else None
        mtime = file_info.mtime if file_info else None
        size = file_info.size if file_info else None

        for line in content.splitlines():
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
                    file_mtime=mtime,
                    file_size=size,
                ))
    except Exception as e:
        logger.debug("Error reading %s: %s", file_path, e)

    return keys


async def _read_public_key_file(
    conn: asyncssh.SSHClientConnection,
    file_path: str,
    owner: str,
) -> DiscoveredKey | None:
    """Read a single public key file."""
    try:
        content = await SFTPReader.read_file(conn, file_path)
        if content is None:
            return None

        key_data = content.strip()
        if not key_data:
            return None

        file_info = await SFTPReader.stat_file(conn, file_path)
        perms = file_info.permissions if file_info else None
        mtime = file_info.mtime if file_info else None
        size = file_info.size if file_info else None

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
            file_mtime=mtime,
            file_size=size,
        )
    except Exception as e:
        logger.debug("Error reading %s: %s", file_path, e)
        return None


async def _check_private_key(
    conn: asyncssh.SSHClientConnection,
    file_path: str,
    owner: str,
) -> DiscoveredKey | None:
    """Check if a private key file exists and get its metadata.

    IMPORTANT: We never read or store private key content.
    We derive the fingerprint from the corresponding .pub file.
    """
    try:
        file_info = await SFTPReader.stat_file(conn, file_path)
        if file_info is None:
            return None

        perms = file_info.permissions
        mtime = file_info.mtime
        size = file_info.size

        # Try to get fingerprint from the corresponding public key file
        pub_path = f"{file_path}.pub"
        pub_content = await SFTPReader.read_file(conn, pub_path)
        fp_sha = None
        fp_md5 = None
        key_type = None
        pub_data = ""

        if pub_content:
            pub_data = pub_content.strip()
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
            file_mtime=mtime,
            file_size=size,
        )
    except Exception as e:
        logger.debug("Error checking %s: %s", file_path, e)
        return None


async def _scan_host_keys(
    conn: asyncssh.SSHClientConnection,
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
            content = await SFTPReader.read_file(conn, path)
            if content is None:
                continue

            key_data = content.strip()
            if not key_data:
                continue

            fp_sha = calculate_sha256_fingerprint(key_data)
            fp_md5 = calculate_md5_fingerprint(key_data)

            if fp_sha or fp_md5:
                file_info = await SFTPReader.stat_file(conn, path)
                perms = file_info.permissions if file_info else None
                mtime = file_info.mtime if file_info else None
                size = file_info.size if file_info else None

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
                    file_mtime=mtime,
                    file_size=size,
                ))
        except Exception as e:
            logger.debug("Error reading host key %s: %s", path, e)

    return keys


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
