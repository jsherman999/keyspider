"""SSH key management CLI commands."""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from keyspider.db.session import async_session_factory
from keyspider.models.key_location import KeyLocation
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey

console = Console()
app = typer.Typer(no_args_is_help=True)


@app.command("list")
def list_keys(
    key_type: str | None = typer.Option(None, "--type", help="Filter by key type"),
    host_keys: bool = typer.Option(False, "--host-keys", help="Show only host keys"),
):
    """List all discovered SSH keys."""
    asyncio.run(_list_keys(key_type, host_keys))


async def _list_keys(key_type: str | None, host_keys: bool):
    async with async_session_factory() as session:
        stmt = select(SSHKey).order_by(SSHKey.created_at.desc())
        if key_type:
            stmt = stmt.where(SSHKey.key_type == key_type)
        if host_keys:
            stmt = stmt.where(SSHKey.is_host_key.is_(True))

        result = await session.execute(stmt)
        keys = result.scalars().all()

    if not keys:
        console.print("[yellow]No keys found.[/yellow]")
        return

    table = Table(title="SSH Keys")
    table.add_column("ID", style="dim")
    table.add_column("Fingerprint (SHA256)")
    table.add_column("Type")
    table.add_column("Bits")
    table.add_column("Comment")
    table.add_column("Host Key")
    table.add_column("First Seen")

    for key in keys:
        table.add_row(
            str(key.id),
            key.fingerprint_sha256,
            key.key_type,
            str(key.key_bits) if key.key_bits else "-",
            key.comment or "-",
            "Yes" if key.is_host_key else "No",
            str(key.first_seen_at),
        )

    console.print(table)


@app.command("show")
def show_key(
    fingerprint: str = typer.Argument(..., help="SHA256 fingerprint of the key"),
):
    """Show key details."""
    asyncio.run(_show_key(fingerprint))


async def _show_key(fingerprint: str):
    async with async_session_factory() as session:
        result = await session.execute(
            select(SSHKey).where(SSHKey.fingerprint_sha256 == fingerprint)
        )
        key = result.scalar_one_or_none()

    if not key:
        console.print(f"[red]Key not found: {fingerprint}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]SSH Key #{key.id}[/bold]")
    console.print(f"  SHA256:     {key.fingerprint_sha256}")
    console.print(f"  MD5:        {key.fingerprint_md5 or '-'}")
    console.print(f"  Type:       {key.key_type}")
    console.print(f"  Bits:       {key.key_bits or '-'}")
    console.print(f"  Comment:    {key.comment or '-'}")
    console.print(f"  Host Key:   {'Yes' if key.is_host_key else 'No'}")
    console.print(f"  First Seen: {key.first_seen_at}")
    if key.public_key_data:
        console.print(f"  Public Key: {key.public_key_data[:80]}...")


@app.command("locate")
def locate_key(
    fingerprint: str = typer.Argument(..., help="SHA256 fingerprint of the key"),
):
    """Show all file locations for a key."""
    asyncio.run(_locate_key(fingerprint))


async def _locate_key(fingerprint: str):
    async with async_session_factory() as session:
        result = await session.execute(
            select(SSHKey).where(SSHKey.fingerprint_sha256 == fingerprint)
        )
        key = result.scalar_one_or_none()
        if not key:
            console.print(f"[red]Key not found: {fingerprint}[/red]")
            raise typer.Exit(1)

        result = await session.execute(
            select(KeyLocation, Server)
            .join(Server, KeyLocation.server_id == Server.id)
            .where(KeyLocation.ssh_key_id == key.id)
        )
        locations = result.all()

    if not locations:
        console.print("[yellow]No locations found for this key.[/yellow]")
        return

    table = Table(title=f"Locations for {fingerprint}")
    table.add_column("Server")
    table.add_column("File Path")
    table.add_column("Type")
    table.add_column("Owner")
    table.add_column("Permissions")
    table.add_column("Last Verified")

    for loc, server in locations:
        table.add_row(
            f"{server.hostname} ({server.ip_address})",
            loc.file_path,
            loc.file_type,
            loc.unix_owner or "-",
            loc.unix_permissions or "-",
            str(loc.last_verified_at) if loc.last_verified_at else "-",
        )

    console.print(table)
