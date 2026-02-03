"""Database management CLI commands."""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console

console = Console()
app = typer.Typer(no_args_is_help=True)


@app.command()
def init():
    """Initialize the database (create all tables)."""
    asyncio.run(_init_db())


async def _init_db():
    from keyspider.db.session import Base, engine
    import keyspider.models  # noqa: F401 — register all models

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()
    console.print("[green]Database initialized successfully.[/green]")


@app.command()
def migrate():
    """Run database migrations with Alembic."""
    import subprocess
    result = subprocess.run(["alembic", "upgrade", "head"], capture_output=True, text=True)
    if result.returncode == 0:
        console.print("[green]Migrations applied successfully.[/green]")
        if result.stdout:
            console.print(result.stdout)
    else:
        console.print(f"[red]Migration failed:[/red]\n{result.stderr}")
        raise typer.Exit(1)


@app.command()
def seed():
    """Create a default admin user."""
    asyncio.run(_seed_db())


async def _seed_db():
    from passlib.hash import bcrypt
    from sqlalchemy import select

    from keyspider.db.session import async_session_factory
    from keyspider.models.user import User

    async with async_session_factory() as session:
        result = await session.execute(select(User).where(User.username == "admin"))
        if result.scalar_one_or_none():
            console.print("[yellow]Admin user already exists.[/yellow]")
            return

        user = User(
            username="admin",
            password_hash=bcrypt.hash("admin"),
            display_name="Administrator",
            role="admin",
        )
        session.add(user)
        await session.commit()
        console.print("[green]Default admin user created (username: admin, password: admin).[/green]")
        console.print("[yellow]Change this password immediately in production![/yellow]")
