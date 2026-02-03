"""Server management CLI commands."""

from __future__ import annotations

import asyncio
import csv
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from keyspider.db.session import async_session_factory
from keyspider.models.server import Server

console = Console()
app = typer.Typer(no_args_is_help=True)


@app.command("list")
def list_servers():
    """List all known servers."""
    asyncio.run(_list_servers())


async def _list_servers():
    async with async_session_factory() as session:
        result = await session.execute(select(Server).order_by(Server.hostname))
        servers = result.scalars().all()

    if not servers:
        console.print("[yellow]No servers found.[/yellow]")
        return

    table = Table(title="Servers")
    table.add_column("ID", style="dim")
    table.add_column("Hostname")
    table.add_column("IP Address")
    table.add_column("OS")
    table.add_column("Port")
    table.add_column("Reachable")
    table.add_column("Last Scanned")

    for s in servers:
        table.add_row(
            str(s.id),
            s.hostname,
            s.ip_address,
            s.os_type,
            str(s.ssh_port),
            "Yes" if s.is_reachable else "[red]No[/red]",
            str(s.last_scanned_at) if s.last_scanned_at else "-",
        )

    console.print(table)


@app.command("add")
def add_server(
    host: str = typer.Argument(..., help="Hostname or IP address"),
    port: int = typer.Option(22, "--port", "-p", help="SSH port"),
    os_type: str = typer.Option("linux", "--os", help="OS type (linux/aix)"),
):
    """Add a server manually."""
    asyncio.run(_add_server(host, port, os_type))


async def _add_server(host: str, port: int, os_type: str):
    async with async_session_factory() as session:
        server = Server(
            hostname=host,
            ip_address=host,
            ssh_port=port,
            os_type=os_type,
            discovered_via="manual",
        )
        session.add(server)
        await session.commit()
        console.print(f"[green]Server added: {host}:{port} (ID: {server.id})[/green]")


@app.command("import")
def import_servers(
    file: Path = typer.Argument(..., help="CSV file with hostname,ip,port,os_type columns"),
):
    """Bulk import servers from a CSV file."""
    asyncio.run(_import_servers(file))


async def _import_servers(file: Path):
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    async with async_session_factory() as session:
        count = 0
        with open(file) as f:
            reader = csv.DictReader(f)
            for row in reader:
                server = Server(
                    hostname=row.get("hostname", row.get("host", "")),
                    ip_address=row.get("ip_address", row.get("ip", row.get("hostname", ""))),
                    ssh_port=int(row.get("port", row.get("ssh_port", 22))),
                    os_type=row.get("os_type", row.get("os", "linux")),
                    discovered_via="manual",
                )
                session.add(server)
                count += 1

        await session.commit()
        console.print(f"[green]Imported {count} servers.[/green]")


@app.command("show")
def show_server(
    host: str = typer.Argument(..., help="Hostname or IP address"),
):
    """Show server details."""
    asyncio.run(_show_server(host))


async def _show_server(host: str):
    async with async_session_factory() as session:
        result = await session.execute(
            select(Server).where(
                (Server.hostname == host) | (Server.ip_address == host)
            )
        )
        server = result.scalar_one_or_none()

    if not server:
        console.print(f"[red]Server not found: {host}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Server: {server.hostname}[/bold]")
    console.print(f"  ID:           {server.id}")
    console.print(f"  IP Address:   {server.ip_address}")
    console.print(f"  OS Type:      {server.os_type}")
    console.print(f"  OS Version:   {server.os_version or '-'}")
    console.print(f"  SSH Port:     {server.ssh_port}")
    console.print(f"  Reachable:    {'Yes' if server.is_reachable else 'No'}")
    console.print(f"  Discovered:   {server.discovered_via or '-'}")
    console.print(f"  Last Scanned: {server.last_scanned_at or '-'}")
    console.print(f"  Created:      {server.created_at}")
