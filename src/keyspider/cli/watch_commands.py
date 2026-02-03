"""Watch session CLI commands."""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from keyspider.db.session import async_session_factory
from keyspider.models.server import Server
from keyspider.models.watch_session import WatchSession
from keyspider.workers.watch_tasks import start_watcher, stop_watcher

console = Console()
app = typer.Typer(no_args_is_help=True)


@app.command("start")
def watch_start(
    host: str = typer.Argument(..., help="Hostname or IP to watch"),
    depth: int = typer.Option(3, "--depth", "-d", help="Auto-spider depth"),
    no_spider: bool = typer.Option(False, "--no-spider", help="Disable auto-spider"),
):
    """Start watching a server for SSH events."""
    asyncio.run(_watch_start(host, depth, not no_spider))


async def _watch_start(host: str, depth: int, auto_spider: bool):
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

        watch = WatchSession(
            server_id=server.id,
            auto_spider=auto_spider,
            spider_depth=depth,
        )
        session.add(watch)
        await session.commit()

        start_watcher.delay(watch.id)
        console.print(f"[green]Watcher started (Session ID: {watch.id})[/green]")
        console.print(f"  Server: {server.hostname} ({server.ip_address})")
        console.print(f"  Auto-spider: {auto_spider} (depth: {depth})")


@app.command("stop")
def watch_stop(
    session_id: int = typer.Argument(..., help="Watch session ID"),
):
    """Stop a watch session."""
    stop_watcher.delay(session_id)
    console.print(f"[green]Stop signal sent for session {session_id}[/green]")


@app.command("list")
def watch_list():
    """List active watch sessions."""
    asyncio.run(_watch_list())


async def _watch_list():
    async with async_session_factory() as session:
        result = await session.execute(
            select(WatchSession, Server)
            .join(Server, WatchSession.server_id == Server.id)
            .order_by(WatchSession.started_at.desc())
        )
        rows = result.all()

    if not rows:
        console.print("[yellow]No watch sessions found.[/yellow]")
        return

    table = Table(title="Watch Sessions")
    table.add_column("ID", style="dim")
    table.add_column("Server")
    table.add_column("Status")
    table.add_column("Events")
    table.add_column("Auto-Spider")
    table.add_column("Started")

    for watch, server in rows:
        status_style = {
            "active": "green",
            "paused": "yellow",
            "stopped": "dim",
            "error": "red",
        }.get(watch.status, "")
        table.add_row(
            str(watch.id),
            f"{server.hostname} ({server.ip_address})",
            f"[{status_style}]{watch.status}[/{status_style}]",
            str(watch.events_captured),
            f"{'Yes' if watch.auto_spider else 'No'} (d={watch.spider_depth})",
            str(watch.started_at),
        )

    console.print(table)


@app.command("events")
def watch_events(
    session_id: int = typer.Argument(..., help="Watch session ID"),
):
    """Stream events from a watch session to the terminal."""
    asyncio.run(_watch_events(session_id))


async def _watch_events(session_id: int):
    async with async_session_factory() as db_session:
        result = await db_session.execute(
            select(WatchSession, Server)
            .join(Server, WatchSession.server_id == Server.id)
            .where(WatchSession.id == session_id)
        )
        row = result.first()
        if not row:
            console.print(f"[red]Session not found: {session_id}[/red]")
            raise typer.Exit(1)

        watch, server = row
        console.print(f"[bold]Streaming events for {server.hostname}...[/bold]")
        console.print("Press Ctrl+C to stop.\n")

        from keyspider.core.watcher import LogWatcher

        watcher = LogWatcher(
            hostname=server.ip_address,
            port=server.ssh_port,
            os_type=server.os_type,
        )

        def on_event(event):
            style = "green" if event.event_type == "accepted" else "red"
            console.print(
                f"[{style}]{event.event_type:12}[/{style}] "
                f"{event.timestamp.strftime('%H:%M:%S')} "
                f"{event.source_ip:>15} -> {event.username:<12} "
                f"[dim]{event.auth_method or ''}[/dim] "
                f"{'[cyan]' + event.fingerprint + '[/cyan]' if event.fingerprint else ''}"
            )

        watcher.on_event(on_event)

        try:
            await watcher.start()
        except KeyboardInterrupt:
            await watcher.stop()
            console.print("\n[yellow]Stopped.[/yellow]")
