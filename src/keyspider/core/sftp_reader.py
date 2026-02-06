"""Secure file reading via SFTP - no shell command injection possible."""

from __future__ import annotations

import logging
import stat
from dataclasses import dataclass
from datetime import datetime, timezone

import asyncssh

logger = logging.getLogger(__name__)


@dataclass
class FileInfo:
    """File metadata from SFTP stat."""

    mtime: datetime | None
    size: int
    permissions: str  # Octal string like "0644"
    exists: bool = True


class SFTPReader:
    """Wraps asyncssh SFTP client for secure file operations."""

    @staticmethod
    async def read_file(
        conn: asyncssh.SSHClientConnection,
        path: str,
        max_bytes: int = 10 * 1024 * 1024,
    ) -> str | None:
        """Read a file via SFTP. Returns content or None if not found."""
        try:
            async with conn.start_sftp_client() as sftp:
                try:
                    attrs = await sftp.stat(path)
                except asyncssh.SFTPNoSuchFile:
                    return None

                if attrs.size and attrs.size > max_bytes:
                    logger.warning(
                        "File %s is %d bytes, exceeds max %d, truncating",
                        path, attrs.size, max_bytes,
                    )

                async with sftp.open(path, "r") as f:
                    content = await f.read(max_bytes)
                    if isinstance(content, bytes):
                        return content.decode("utf-8", errors="replace")
                    return content
        except asyncssh.SFTPNoSuchFile:
            return None
        except (asyncssh.SFTPError, asyncssh.Error, OSError) as e:
            logger.debug("SFTP read failed for %s: %s", path, e)
            return None

    @staticmethod
    async def read_file_tail(
        conn: asyncssh.SSHClientConnection,
        path: str,
        max_lines: int = 50000,
        max_bytes: int = 50 * 1024 * 1024,
    ) -> str | None:
        """Read the last N lines of a file via SFTP.

        Reads from the end of the file to find enough newlines.
        """
        try:
            async with conn.start_sftp_client() as sftp:
                try:
                    attrs = await sftp.stat(path)
                except asyncssh.SFTPNoSuchFile:
                    return None

                file_size = attrs.size or 0
                if file_size == 0:
                    return ""

                # If file is small enough, just read it all
                read_size = min(file_size, max_bytes)

                async with sftp.open(path, "rb") as f:
                    if read_size < file_size:
                        # Seek to near end
                        await f.seek(file_size - read_size)
                    raw = await f.read(read_size)

                content = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                lines = content.splitlines()

                # If we seeked into the middle, drop the first partial line
                if read_size < file_size and lines:
                    lines = lines[1:]

                if len(lines) > max_lines:
                    lines = lines[-max_lines:]

                return "\n".join(lines)
        except asyncssh.SFTPNoSuchFile:
            return None
        except (asyncssh.SFTPError, asyncssh.Error, OSError) as e:
            logger.debug("SFTP tail read failed for %s: %s", path, e)
            return None

    @staticmethod
    async def stat_file(
        conn: asyncssh.SSHClientConnection,
        path: str,
    ) -> FileInfo | None:
        """Get file metadata via SFTP stat."""
        try:
            async with conn.start_sftp_client() as sftp:
                attrs = await sftp.stat(path)
                mtime = None
                if attrs.mtime is not None:
                    mtime = datetime.fromtimestamp(attrs.mtime, tz=timezone.utc)

                perms = ""
                if attrs.permissions is not None:
                    perms = oct(stat.S_IMODE(attrs.permissions))[2:]  # e.g. "644"
                    perms = perms.zfill(4)  # "0644"

                return FileInfo(
                    mtime=mtime,
                    size=attrs.size or 0,
                    permissions=perms,
                )
        except asyncssh.SFTPNoSuchFile:
            return None
        except (asyncssh.SFTPError, asyncssh.Error, OSError) as e:
            logger.debug("SFTP stat failed for %s: %s", path, e)
            return None

    @staticmethod
    async def list_dir(
        conn: asyncssh.SSHClientConnection,
        path: str,
    ) -> list[str] | None:
        """List directory entries via SFTP."""
        try:
            async with conn.start_sftp_client() as sftp:
                entries = await sftp.listdir(path)
                return entries
        except asyncssh.SFTPNoSuchFile:
            return None
        except (asyncssh.SFTPError, asyncssh.Error, OSError) as e:
            logger.debug("SFTP listdir failed for %s: %s", path, e)
            return None

    @staticmethod
    async def file_exists(
        conn: asyncssh.SSHClientConnection,
        path: str,
    ) -> bool:
        """Check if a file exists via SFTP stat."""
        try:
            async with conn.start_sftp_client() as sftp:
                await sftp.stat(path)
                return True
        except asyncssh.SFTPNoSuchFile:
            return False
        except (asyncssh.SFTPError, asyncssh.Error, OSError):
            return False

    @staticmethod
    async def get_file_size(
        conn: asyncssh.SSHClientConnection,
        path: str,
    ) -> int | None:
        """Get file size in bytes, or None if not found."""
        try:
            async with conn.start_sftp_client() as sftp:
                attrs = await sftp.stat(path)
                return attrs.size or 0
        except (asyncssh.SFTPNoSuchFile, asyncssh.SFTPError, asyncssh.Error, OSError):
            return None
