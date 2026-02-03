"""Scan management CLI commands."""

from __future__ import annotations

import asyncio
import time

import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table
from sqlalchemy import select

from keyspider.db.session import async_session_factory
from keyspider.models.scan_job import ScanJob
from keyspider.models.server import Server
from keyspider.workers.scan_tasks import scan_single_server
from keyspider.workers.spider_tasks import spider_crawl

console = Console()
app = typer.Typer(no_args_is_help=True)


@app.command("full")
def full_scan():
    """Run a full environment scan of all servers."""
    asyncio.run(_full_scan())


async def _full_scan():
    async with async_session_factory() as session:
        job = ScanJob(job_type="full_scan", status="pending", initiated_by="cli")
        session.add(job)
        await session.commit()

        result = await session.execute(
            select(Server).where(Server.is_reachable.is_(True))
        )
        servers = result.scalars().all()

        if not servers:
            console.print("[yellow]No reachable servers found.[/yellow]")
            return

        for server in servers:
            scan_single_server.delay(job.id, server.id)

        console.print(f"[green]Full scan started (Job ID: {job.id})[/green]")
        console.print(f"  Servers queued: {len(servers)}")


@app.command("server")
def scan_server(
    host: str = typer.Argument(..., help="Hostname or IP of the server to scan"),
):
    """Scan a single server."""
    asyncio.run(_scan_server(host))


async def _scan_server(host: str):
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

        job = ScanJob(
            job_type="server_scan",
            status="pending",
            initiated_by="cli",
            seed_server_id=server.id,
        )
        session.add(job)
        await session.commit()

        scan_single_server.delay(job.id, server.id)
        console.print(f"[green]Server scan started (Job ID: {job.id})[/green]")
        console.print(f"  Target: {server.hostname} ({server.ip_address})")


@app.command("spider")
def spider(
    host: str = typer.Argument(..., help="Seed server hostname or IP"),
    depth: int = typer.Option(10, "--depth", "-d", help="Maximum crawl depth"),
):
    """Spider crawl from a seed server."""
    asyncio.run(_spider(host, depth))


async def _spider(host: str, depth: int):
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

        job = ScanJob(
            job_type="spider_crawl",
            status="pending",
            initiated_by="cli",
            seed_server_id=server.id,
            max_depth=depth,
        )
        session.add(job)
        await session.commit()

        spider_crawl.delay(job.id, server.id, depth)
        console.print(f"[green]Spider crawl started (Job ID: {job.id})[/green]")
        console.print(f"  Seed: {server.hostname} ({server.ip_address})")
        console.print(f"  Max depth: {depth}")


@app.command("status")
def scan_status(
    job_id: int | None = typer.Argument(None, help="Specific job ID to check"),
):
    """Check scan status."""
    asyncio.run(_scan_status(job_id))


async def _scan_status(job_id: int | None):
    async with async_session_factory() as session:
        if job_id:
            result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
            job = result.scalar_one_or_none()
            if not job:
                console.print(f"[red]Job not found: {job_id}[/red]")
                raise typer.Exit(1)
            _print_job(job)
        else:
            result = await session.execute(
                select(ScanJob).order_by(ScanJob.created_at.desc()).limit(10)
            )
            jobs = result.scalars().all()
            if not jobs:
                console.print("[yellow]No scan jobs found.[/yellow]")
                return

            table = Table(title="Recent Scan Jobs")
            table.add_column("ID", style="dim")
            table.add_column("Type")
            table.add_column("Status")
            table.add_column("Initiated By")
            table.add_column("Servers")
            table.add_column("Keys")
            table.add_column("Events")
            table.add_column("Created")

            for j in jobs:
                status_style = {
                    "completed": "green",
                    "running": "blue",
                    "failed": "red",
                    "pending": "yellow",
                    "cancelled": "dim",
                }.get(j.status, "")
                table.add_row(
                    str(j.id),
                    j.job_type,
                    f"[{status_style}]{j.status}[/{status_style}]",
                    j.initiated_by,
                    str(j.servers_scanned),
                    str(j.keys_found),
                    str(j.events_parsed),
                    str(j.created_at),
                )
            console.print(table)


@app.command("cancel")
def cancel_scan(
    job_id: int = typer.Argument(..., help="Job ID to cancel"),
):
    """Cancel a running scan."""
    asyncio.run(_cancel_scan(job_id))


async def _cancel_scan(job_id: int):
    async with async_session_factory() as session:
        result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
        job = result.scalar_one_or_none()
        if not job:
            console.print(f"[red]Job not found: {job_id}[/red]")
            raise typer.Exit(1)

        if job.status not in ("pending", "running"):
            console.print(f"[yellow]Job is already {job.status}[/yellow]")
            return

        job.status = "cancelled"
        await session.commit()
        console.print(f"[green]Job {job_id} cancelled.[/green]")


def _print_job(job: ScanJob):
    console.print(f"[bold]Scan Job #{job.id}[/bold]")
    console.print(f"  Type:         {job.job_type}")
    console.print(f"  Status:       {job.status}")
    console.print(f"  Initiated by: {job.initiated_by}")
    console.print(f"  Servers:      {job.servers_scanned}")
    console.print(f"  Keys found:   {job.keys_found}")
    console.print(f"  Events:       {job.events_parsed}")
    console.print(f"  Unreachable:  {job.unreachable_found}")
    if job.error_message:
        console.print(f"  [red]Error: {job.error_message}[/red]")
    console.print(f"  Created:      {job.created_at}")
    if job.started_at:
        console.print(f"  Started:      {job.started_at}")
    if job.completed_at:
        console.print(f"  Completed:    {job.completed_at}")
