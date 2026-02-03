"""Report CLI commands."""

from __future__ import annotations

import asyncio
import csv
import json
import sys

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select

from keyspider.db.session import async_session_factory
from keyspider.models.access_event import AccessEvent
from keyspider.models.access_path import AccessPath
from keyspider.models.key_location import KeyLocation
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey
from keyspider.models.unreachable_source import UnreachableSource
from keyspider.models.watch_session import WatchSession

console = Console()
app = typer.Typer(no_args_is_help=True)


@app.command("unreachable")
def unreachable_report(
    severity: str | None = typer.Option(None, "--severity", "-s", help="Filter by severity"),
):
    """List unreachable sources."""
    asyncio.run(_unreachable_report(severity))


async def _unreachable_report(severity: str | None):
    async with async_session_factory() as session:
        stmt = (
            select(UnreachableSource, Server)
            .join(Server, UnreachableSource.target_server_id == Server.id)
            .where(UnreachableSource.acknowledged.is_(False))
            .order_by(UnreachableSource.severity, UnreachableSource.last_seen_at.desc())
        )
        if severity:
            stmt = stmt.where(UnreachableSource.severity == severity)

        result = await session.execute(stmt)
        rows = result.all()

    if not rows:
        console.print("[green]No unreachable sources found.[/green]")
        return

    table = Table(title="Unreachable Sources")
    table.add_column("ID", style="dim")
    table.add_column("Source IP")
    table.add_column("Reverse DNS")
    table.add_column("Target Server")
    table.add_column("Severity")
    table.add_column("Events")
    table.add_column("Last Seen")

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
    }

    for ur, server in rows:
        style = severity_styles.get(ur.severity, "")
        table.add_row(
            str(ur.id),
            ur.source_ip,
            ur.reverse_dns or "-",
            server.hostname,
            f"[{style}]{ur.severity}[/{style}]",
            str(ur.event_count),
            str(ur.last_seen_at),
        )

    console.print(table)


@app.command("exposure")
def exposure_report():
    """Show keys found on multiple servers."""
    asyncio.run(_exposure_report())


async def _exposure_report():
    async with async_session_factory() as session:
        stmt = (
            select(
                SSHKey.id,
                SSHKey.fingerprint_sha256,
                SSHKey.key_type,
                SSHKey.comment,
                func.count(func.distinct(KeyLocation.server_id)).label("server_count"),
            )
            .join(KeyLocation, SSHKey.id == KeyLocation.ssh_key_id)
            .group_by(SSHKey.id)
            .having(func.count(func.distinct(KeyLocation.server_id)) > 1)
            .order_by(func.count(func.distinct(KeyLocation.server_id)).desc())
        )
        result = await session.execute(stmt)
        rows = result.all()

    if not rows:
        console.print("[green]No keys found on multiple servers.[/green]")
        return

    table = Table(title="Key Exposure Report")
    table.add_column("Key ID", style="dim")
    table.add_column("Fingerprint")
    table.add_column("Type")
    table.add_column("Comment")
    table.add_column("Servers")

    for row in rows:
        table.add_row(
            str(row.id),
            row.fingerprint_sha256,
            row.key_type,
            row.comment or "-",
            str(row.server_count),
        )

    console.print(table)


@app.command("summary")
def summary_report():
    """Show environment summary."""
    asyncio.run(_summary_report())


async def _summary_report():
    async with async_session_factory() as session:
        total_servers = (await session.execute(select(func.count(Server.id)))).scalar() or 0
        reachable = (await session.execute(
            select(func.count(Server.id)).where(Server.is_reachable.is_(True))
        )).scalar() or 0
        total_keys = (await session.execute(select(func.count(SSHKey.id)))).scalar() or 0
        total_locations = (await session.execute(select(func.count(KeyLocation.id)))).scalar() or 0
        total_events = (await session.execute(select(func.count(AccessEvent.id)))).scalar() or 0
        total_paths = (await session.execute(select(func.count(AccessPath.id)))).scalar() or 0
        active_watchers = (await session.execute(
            select(func.count(WatchSession.id)).where(WatchSession.status == "active")
        )).scalar() or 0
        unreachable = (await session.execute(
            select(func.count(UnreachableSource.id)).where(UnreachableSource.acknowledged.is_(False))
        )).scalar() or 0

    console.print("[bold]Keyspider Environment Summary[/bold]")
    console.print(f"  Servers:            {total_servers} ({reachable} reachable)")
    console.print(f"  SSH Keys:           {total_keys}")
    console.print(f"  Key Locations:      {total_locations}")
    console.print(f"  Access Events:      {total_events}")
    console.print(f"  Access Paths:       {total_paths}")
    console.print(f"  Active Watchers:    {active_watchers}")
    console.print(f"  Unreachable Alerts: {unreachable}")


@app.command("export")
def export_report(
    format: str = typer.Option("json", "--format", "-f", help="Export format (json/csv)"),
):
    """Export summary report to JSON or CSV."""
    asyncio.run(_export_report(format))


async def _export_report(format: str):
    async with async_session_factory() as session:
        result = await session.execute(
            select(UnreachableSource).where(UnreachableSource.acknowledged.is_(False))
        )
        items = result.scalars().all()

    if format == "json":
        data = [
            {
                "id": item.id,
                "source_ip": item.source_ip,
                "reverse_dns": item.reverse_dns,
                "severity": item.severity,
                "event_count": item.event_count,
                "last_seen_at": str(item.last_seen_at),
            }
            for item in items
        ]
        console.print(json.dumps(data, indent=2))
    elif format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(["id", "source_ip", "reverse_dns", "severity", "event_count", "last_seen_at"])
        for item in items:
            writer.writerow([
                item.id, item.source_ip, item.reverse_dns,
                item.severity, item.event_count, str(item.last_seen_at),
            ])
    else:
        console.print(f"[red]Unknown format: {format}[/red]")
