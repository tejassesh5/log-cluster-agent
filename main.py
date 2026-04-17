import typer
from rich.console import Console

app = typer.Typer(help="SOC log clustering agent — cut alert fatigue")
console = Console()


@app.command()
def cluster(
    log_file: str = typer.Argument(..., help="Path to log file (CSV or JSON)"),
    clusters: int = typer.Option(10, help="Target number of clusters"),
    output: str = typer.Option("table", help="Output format: table, json, csv"),
):
    """Cluster security log events into distinct incidents."""
    console.print(f"[bold green]Ingesting:[/bold green] {log_file}")
    console.print(f"[bold]Target clusters:[/bold] {clusters}")
    console.print("[yellow]Clustering engine not yet implemented — scaffold only.[/yellow]")


if __name__ == "__main__":
    app()
