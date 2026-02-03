"""CLI entry point."""

import typer

from keyspider.cli.db_commands import app as db_app
from keyspider.cli.key_commands import app as key_app
from keyspider.cli.report_commands import app as report_app
from keyspider.cli.scan_commands import app as scan_app
from keyspider.cli.server_commands import app as server_app
from keyspider.cli.user_commands import app as user_app
from keyspider.cli.watch_commands import app as watch_app

app = typer.Typer(
    name="keyspider",
    help="SSH key usage monitoring and tracking.",
    no_args_is_help=True,
)

app.add_typer(server_app, name="server", help="Server management")
app.add_typer(scan_app, name="scan", help="Scan operations")
app.add_typer(key_app, name="keys", help="SSH key management")
app.add_typer(watch_app, name="watch", help="Real-time log watching")
app.add_typer(report_app, name="report", help="Reports and alerts")
app.add_typer(user_app, name="user", help="User management")
app.add_typer(db_app, name="db", help="Database operations")


if __name__ == "__main__":
    app()
