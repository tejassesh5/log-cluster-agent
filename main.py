import typer
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box

import ingestor
import clusterer
import labeller
from config import GEMINI_API_KEY, DEFAULT_CLUSTERS

app = typer.Typer(help="SOC log clustering agent — cut alert fatigue")
console = Console()


@app.command()
def cluster(
    log_file: str = typer.Argument(..., help="Path to log file (CSV, JSON, or plain text)"),
    n_clusters: int = typer.Option(DEFAULT_CLUSTERS, "--clusters", "-k", help="Number of clusters"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip Gemini AI cluster labelling"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table, json, csv"),
    outfile: str = typer.Option("", "--outfile", help="Save output to file"),
    min_size: int = typer.Option(1, "--min-size", help="Minimum cluster size to show"),
):
    """Cluster security logs and surface distinct incidents for triage."""
    p = Path(log_file)
    if not p.exists():
        console.print(f"[red]Error:[/red] File not found: {log_file}")
        raise typer.Exit(1)

    console.print(f"[dim]Loading:[/dim] {log_file}")
    entries = ingestor.load(log_file)
    console.print(f"[dim]Loaded {len(entries)} log entries[/dim]")

    if not entries:
        console.print("[yellow]No log entries found.[/yellow]")
        raise typer.Exit(0)

    console.print(f"[dim]Clustering into up to {n_clusters} groups...[/dim]")
    clusters = clusterer.cluster(entries, n_clusters=n_clusters)
    clusters = [c for c in clusters if c.size >= min_size]

    if not no_ai and GEMINI_API_KEY:
        console.print("[dim]AI labelling clusters...[/dim]")
        clusters = labeller.label_clusters(clusters, GEMINI_API_KEY)

    if output == "table":
        _print_table(clusters, len(entries))
    elif output == "json":
        content = _to_json(clusters, len(entries))
        if outfile:
            Path(outfile).write_text(content, encoding="utf-8")
            console.print(f"[green]Saved:[/green] {outfile}")
        else:
            console.print(content)
    elif output == "csv":
        content = _to_csv(clusters)
        if outfile:
            Path(outfile).write_text(content, encoding="utf-8")
            console.print(f"[green]Saved:[/green] {outfile}")
        else:
            console.print(content)


def _print_table(clusters, total: int):
    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        title=f"Log Cluster Report — {total} entries -> {len(clusters)} clusters"
    )
    table.add_column("#", width=4)
    table.add_column("Size", width=6)
    table.add_column("Label / Top Terms", width=35)
    table.add_column("Unique IPs", width=12)
    table.add_column("Sample Entry", width=50)

    for i, cl in enumerate(clusters, 1):
        label = cl.label or ", ".join(cl.top_terms[:3])
        table.add_row(
            str(i),
            str(cl.size),
            label,
            str(len(cl.unique_ips)),
            cl.sample[:80],
        )

    console.print(table)
    console.print(f"\n[bold]Total:[/bold] {total} events -> [bold green]{len(clusters)} distinct clusters[/bold green]")
    if clusters:
        console.print(
            f"[dim]Top cluster: {clusters[0].size} events "
            f"({clusters[0].size * 100 // total}% of traffic)[/dim]"
        )


def _to_json(clusters, total: int) -> str:
    import json
    return json.dumps({
        "total_entries": total,
        "clusters": [
            {
                "id": cl.id,
                "size": cl.size,
                "label": cl.label,
                "top_terms": cl.top_terms,
                "unique_ips": list(cl.unique_ips),
                "sample": cl.sample,
            }
            for cl in clusters
        ]
    }, indent=2)


def _to_csv(clusters) -> str:
    import csv, io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["cluster_id", "size", "label", "top_terms", "unique_ips", "sample"])
    for cl in clusters:
        w.writerow([cl.id, cl.size, cl.label, "|".join(cl.top_terms), len(cl.unique_ips), cl.sample[:100]])
    return buf.getvalue()


if __name__ == "__main__":
    app()
