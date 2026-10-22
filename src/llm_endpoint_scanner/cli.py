"""Command-line interface."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import ConfigError, load_config
from .models import Verdict
from .probes import ALL_CATEGORIES
from .runner import run_scan, write_json_report, write_markdown_report

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


class FailOn(str, Enum):
    NEVER = "never"
    SUCCESS = "success"
    INCONCLUSIVE = "inconclusive"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"llm-endpoint-scanner {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Print the scanner version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Black-box security scanner for LLM endpoints."""


def _print_plan(cfg_path: Path) -> None:
    """--dry-run: show exactly what would be sent, send nothing (NFR-1)."""
    cfg = load_config(cfg_path)
    console.print(f"[bold]Dry run[/] — no requests will be sent to {cfg.endpoint.url}")
    console.print(
        f"Endpoint: {cfg.endpoint.method} {cfg.endpoint.url} "
        f"(headers: {', '.join(sorted(cfg.endpoint.headers)) or 'none'})"
    )
    console.print(
        f"Limits: timeout={cfg.limits.timeout_seconds}s, "
        f"max_rps={cfg.limits.max_requests_per_second}, "
        f"max_probe_length={cfg.limits.max_probe_length}"
    )
    console.print("Baseline: 1 neutral control prompt (sent first)")
    table = Table(title="Planned probes")
    table.add_column("Category")
    table.add_column("Probe")
    table.add_column("Severity")
    table.add_column("Requests", justify="right")
    table.add_column("Payload chars", justify="right")
    total = 1  # baseline
    for category in ALL_CATEGORIES:
        for probe in category.probes():
            total += probe.repetitions
            table.add_row(
                category.category,
                probe.name,
                probe.severity,
                str(probe.repetitions),
                str(len(probe.payload_template)),
            )
    console.print(table)
    console.print(f"Total planned requests: {total}")


@app.command()
def scan(
    config_path: Annotated[
        Path, typer.Argument(help="Path to the endpoint YAML config.")
    ],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print planned requests; send nothing."),
    ] = False,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on",
            help="Exit 1 when the overall verdict reaches this level (for CI gating).",
        ),
    ] = FailOn.NEVER,
) -> None:
    """Scan the endpoint described by CONFIG_PATH."""
    try:
        if dry_run:
            _print_plan(config_path)
            return
        cfg = load_config(config_path)
    except ConfigError as exc:
        err_console.print(f"[bold red]Config error:[/] {exc}")
        raise typer.Exit(code=2) from None

    console.print(f"Scanning [bold]{cfg.endpoint.url}[/] ...")
    report = run_scan(cfg)

    for result in report.probes:
        verdict = result.judgment.verdict.value
        style = _VERDICT_STYLE[verdict]
        console.print(f"  [{style}]{verdict:<12}[/] {result.category}/{result.name}")

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
    write_markdown_report(report, cfg.report.markdown_path)
    console.print(f"Markdown report written to {cfg.report.markdown_path}")

    triggered = (
        fail_on is FailOn.SUCCESS and report.overall_verdict == Verdict.SUCCESS.value
    ) or (
        fail_on is FailOn.INCONCLUSIVE
        and report.overall_verdict
        in (Verdict.SUCCESS.value, Verdict.INCONCLUSIVE.value)
    )
    if triggered:
        err_console.print(
            f"Failing because --fail-on={fail_on.value} and the overall "
            f"verdict is {report.overall_verdict}."
        )
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
