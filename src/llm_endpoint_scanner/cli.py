"""Command-line interface."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import ConfigError, load_config
from .models import Verdict
from .runner import run_scan, write_json_report

app = typer.Typer(
    help="Black-box security scanner for LLM endpoints.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)

_VERDICT_STYLE = {
    Verdict.SUCCESS.value: "bold red",
    Verdict.INCONCLUSIVE.value: "yellow",
    Verdict.FAILED.value: "green",
}


@app.callback()
def main() -> None:
    """Black-box security scanner for LLM endpoints."""


@app.command()
def scan(
    config_path: Path = typer.Argument(..., help="Path to the endpoint YAML config."),
) -> None:
    """Scan the endpoint described by CONFIG_PATH."""
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        err_console.print(f"[bold red]Config error:[/] {exc}")
        raise typer.Exit(code=2) from None

    console.print(f"Scanning [bold]{cfg.endpoint.url}[/] ...")
    report = run_scan(cfg)

    for result in report.probes:
        verdict = result.judgment.verdict.value
        style = _VERDICT_STYLE[verdict]
        console.print(
            f"  [{style}]{verdict:<12}[/] {result.category}/{result.name}"
        )

    table = Table(title="Summary")
    table.add_column("Category")
    table.add_column("Verdict")
    for category, verdict in report.summary.items():
        table.add_row(category, f"[{_VERDICT_STYLE[verdict]}]{verdict}[/]")
    console.print(table)
    console.print(
        f"Overall: [{_VERDICT_STYLE[report.overall_verdict]}]"
        f"{report.overall_verdict}[/] "
        f"({report.duration_seconds}s, run {report.run_id})"
    )

    write_json_report(report, cfg.report.json_path)
    console.print(f"JSON report written to {cfg.report.json_path}")


if __name__ == "__main__":
    app()
