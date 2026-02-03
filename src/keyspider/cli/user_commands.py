"""User management CLI commands."""

from __future__ import annotations

import asyncio
import secrets

import typer
from passlib.hash import bcrypt
from rich.console import Console
from sqlalchemy import select

from keyspider.db.session import async_session_factory
from keyspider.models.api_key import APIKey
from keyspider.models.user import User

console = Console()
app = typer.Typer(no_args_is_help=True)


@app.command("create")
def create_user(
    username: str = typer.Argument(..., help="Username"),
    role: str = typer.Option("viewer", "--role", "-r", help="User role (admin/operator/viewer)"),
):
    """Create a new user."""
    password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    asyncio.run(_create_user(username, password, role))


async def _create_user(username: str, password: str, role: str):
    async with async_session_factory() as session:
        result = await session.execute(select(User).where(User.username == username))
        if result.scalar_one_or_none():
            console.print(f"[red]User already exists: {username}[/red]")
            raise typer.Exit(1)

        user = User(
            username=username,
            password_hash=bcrypt.hash(password),
            role=role,
        )
        session.add(user)
        await session.commit()
        console.print(f"[green]User created: {username} (role: {role})[/green]")


@app.command("apikey")
def create_apikey(
    name: str = typer.Argument(..., help="API key name"),
    username: str = typer.Option(..., "--user", "-u", help="Username to associate"),
):
    """Generate an API key for a user."""
    asyncio.run(_create_apikey(name, username))


async def _create_apikey(name: str, username: str):
    async with async_session_factory() as session:
        result = await session.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            console.print(f"[red]User not found: {username}[/red]")
            raise typer.Exit(1)

        raw_key = secrets.token_urlsafe(48)
        key_hash = bcrypt.hash(raw_key)

        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_prefix=raw_key[:8],
            name=name,
            permissions=["read", "write"],
        )
        session.add(api_key)
        await session.commit()

        console.print(f"[green]API key created: {name}[/green]")
        console.print(f"[bold]Key: {raw_key}[/bold]")
        console.print("[yellow]Save this key now — it cannot be retrieved later.[/yellow]")
