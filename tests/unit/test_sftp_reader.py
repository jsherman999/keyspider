"""Tests for the SFTP reader module (mocked asyncssh)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from keyspider.core.sftp_reader import SFTPReader, FileInfo


class MockSFTPAttrs:
    """Mock for asyncssh SFTPAttrs."""
    def __init__(self, size=100, mtime=1700000000, permissions=0o100644):
        self.size = size
        self.mtime = mtime
        self.permissions = permissions


class MockSFTPFile:
    """Mock for an SFTP file handle."""
    def __init__(self, content: bytes | str = b"file content"):
        self._content = content if isinstance(content, bytes) else content.encode()
        self._pos = 0

    async def read(self, size=-1):
        if size < 0:
            return self._content[self._pos:]
        return self._content[self._pos:self._pos + size]

    async def seek(self, pos):
        self._pos = pos

    async def write(self, data):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class MockSFTPClient:
    """Mock for asyncssh SFTPClient."""
    def __init__(self, files=None, raise_on_stat=False):
        self._files = files or {}
        self._raise_on_stat = raise_on_stat

    async def stat(self, path):
        if self._raise_on_stat:
            import asyncssh
            raise asyncssh.SFTPNoSuchFile("Not found")
        if path not in self._files:
            import asyncssh
            raise asyncssh.SFTPNoSuchFile(f"No such file: {path}")
        return self._files[path]["attrs"]

    def open(self, path, mode="r"):
        if path not in self._files:
            import asyncssh
            raise asyncssh.SFTPNoSuchFile(f"No such file: {path}")
        return MockSFTPFile(self._files[path].get("content", b""))

    async def listdir(self, path):
        if path not in self._files:
            import asyncssh
            raise asyncssh.SFTPNoSuchFile(f"No such dir: {path}")
        return self._files[path].get("entries", [])

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


def _make_conn(sftp_client):
    """Create a mock SSH connection that returns the given SFTP client."""
    conn = MagicMock()
    conn.start_sftp_client = MagicMock(return_value=sftp_client)
    return conn


class TestSFTPReaderStatFile:
    @pytest.mark.asyncio
    async def test_stat_existing_file(self):
        sftp = MockSFTPClient(files={
            "/etc/passwd": {
                "attrs": MockSFTPAttrs(size=1024, mtime=1700000000, permissions=0o100644),
            }
        })
        conn = _make_conn(sftp)
        info = await SFTPReader.stat_file(conn, "/etc/passwd")
        assert info is not None
        assert info.size == 1024
        assert info.permissions == "0644"
        assert info.mtime is not None
        assert isinstance(info.mtime, datetime)

    @pytest.mark.asyncio
    async def test_stat_nonexistent_file(self):
        sftp = MockSFTPClient(files={})
        conn = _make_conn(sftp)
        info = await SFTPReader.stat_file(conn, "/no/such/file")
        assert info is None


class TestSFTPReaderFileExists:
    @pytest.mark.asyncio
    async def test_file_exists(self):
        sftp = MockSFTPClient(files={
            "/etc/passwd": {"attrs": MockSFTPAttrs()},
        })
        conn = _make_conn(sftp)
        assert await SFTPReader.file_exists(conn, "/etc/passwd") is True

    @pytest.mark.asyncio
    async def test_file_not_exists(self):
        sftp = MockSFTPClient(files={})
        conn = _make_conn(sftp)
        assert await SFTPReader.file_exists(conn, "/no/file") is False


class TestSFTPReaderListDir:
    @pytest.mark.asyncio
    async def test_list_dir(self):
        sftp = MockSFTPClient(files={
            "/home/user/.ssh": {
                "attrs": MockSFTPAttrs(),
                "entries": ["authorized_keys", "id_rsa", "id_rsa.pub"],
            }
        })
        conn = _make_conn(sftp)
        entries = await SFTPReader.list_dir(conn, "/home/user/.ssh")
        assert entries is not None
        assert len(entries) == 3
        assert "authorized_keys" in entries

    @pytest.mark.asyncio
    async def test_list_dir_nonexistent(self):
        sftp = MockSFTPClient(files={})
        conn = _make_conn(sftp)
        entries = await SFTPReader.list_dir(conn, "/no/such/dir")
        assert entries is None


class TestFileInfo:
    def test_dataclass_creation(self):
        info = FileInfo(
            mtime=datetime(2023, 1, 1, tzinfo=timezone.utc),
            size=1024,
            permissions="0644",
        )
        assert info.exists is True
        assert info.size == 1024
        assert info.permissions == "0644"
