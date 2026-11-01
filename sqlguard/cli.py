from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table
from sqlguard.linter import lint_sql

app = typer.Typer(help="SQLGuard: Static SQL query linter for CI/CD pipelines.")
console = Console()


@app.command()
def check(
    path: Path = typer.Argument(..., exists=True, help="SQL file or directory to scan."),
    indexes: str = typer.Option(
        "",
        "--indexes",
        "-i",
        help="Comma-separated list of indexed columns (e.g. 'users.id,orders.user_id').",
    ),
    fail_on: str = typer.Option(
        "warning",
        "--fail-on",
        help="Minimum severity to fail CI exit code: 'critical' or 'warning'.",
    ),
) -> None:
    sql_files = [path] if path.is_file() else list(path.rglob("*.sql"))
    if not sql_files:
        console.print("[yellow]No .sql files found to scan.[/yellow]")
        raise typer.Exit(code=0)

    index_set = {col.strip() for col in indexes.split(",") if col.strip()}
    total_violations = []

    for sql_file in sql_files:
        content = sql_file.read_text(encoding="utf-8")
        file_violations = lint_sql(content, indexed_columns=index_set)
        for v in file_violations:
            total_violations.append((str(sql_file), v))

    if not total_violations:
        console.print(f"[bold green]Scanned {len(sql_files)} file(s): 0 issues found.[/bold green]")
        raise typer.Exit(code=0)

    table = Table(title="SQLGuard Audit Report", show_lines=True)
    table.add_column("File:Line", style="cyan", no_wrap=True)
    table.add_column("Rule", style="bold")
    table.add_column("Severity")
    table.add_column("Issue Description")
    table.add_column("SQL Snippet", style="dim")

    should_fail = False
    for filename, v in total_violations:
        sev_style = "bold red" if v.severity == "CRITICAL" else "bold yellow"
        table.add_row(
            f"{filename}:{v.line}",
            v.rule_id,
            f"[{sev_style}]{v.severity}[/{sev_style}]",
            v.message,
            v.snippet,
        )
        if v.severity == "CRITICAL" or (
            fail_on.lower() == "warning" and v.severity == "WARNING"
        ):
            should_fail = True

    console.print(table)
    raise typer.Exit(code=1 if should_fail else 0)


if __name__ == "__main__":
    app()