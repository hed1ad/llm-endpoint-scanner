"""Command-line interface."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import ConfigError, ScanConfig, load_config
from .models import Verdict
from .runner import run_scan, scan_categories, write_json_report, write_markdown_report
from .selection import ScanPlan, SelectionError, plan_scan

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


def _split_names(values: list[str] | None) -> list[str]:
    """--include/--exclude accept repeated flags and comma-separated names."""
    return [
        name.strip()
        for value in values or []
        for name in value.split(",")
        if name.strip()
    ]


def _print_plan(cfg: ScanConfig, plan: ScanPlan) -> None:
    """--dry-run: show exactly what would be sent, send nothing (NFR-1)."""
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
    console.print("Baseline: 1 neutral control prompt (sent first, counts in budget)")
    table = Table(title="Planned probes")
    table.add_column("Category")
    table.add_column("Probe")
    table.add_column("Severity")
    table.add_column("Requests", justify="right")
    table.add_column("Payload chars", justify="right")
    for probe in plan.probes:
        table.add_row(
            probe.category,
            probe.name,
            probe.severity,
            str(probe.repetitions),
            str(len(probe.payload_template)),
        )
    console.print(table)
    for probe, reason in plan.skipped:
        console.print(f"[dim]Skipped:[/] {probe.category}/{probe.name} — {reason}")
    console.print(f"Total planned requests: {plan.total_requests}")


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
    include: Annotated[
        list[str] | None,
        typer.Option(
            "--include",
            help="Run only these categories/probes (repeatable, comma-separated).",
        ),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            help="Skip these categories/probes (repeatable, comma-separated).",
        ),
    ] = None,
    max_requests: Annotated[
        int | None,
        typer.Option(
            "--max-requests",
            help="Hard request budget for the whole scan, baseline included.",
            min=1,
        ),
    ] = None,
) -> None:
    """Scan the endpoint described by CONFIG_PATH."""
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        err_console.print(f"[bold red]Config error:[/] {exc}")
        raise typer.Exit(code=2) from None

    include_names = _split_names(include)
    exclude_names = _split_names(exclude)
    try:
        plan = plan_scan(
            include_names,
            exclude_names,
            max_requests,
            categories=scan_categories(cfg),
        )
    except SelectionError as exc:
        err_console.print(f"[bold red]Selection error:[/] {exc}")
        raise typer.Exit(code=2) from None

    if dry_run:
        _print_plan(cfg, plan)
        return

    console.print(f"Scanning [bold]{cfg.endpoint.url}[/] ...")
    report = run_scan(
        cfg, include=include_names, exclude=exclude_names, max_requests=max_requests
    )

    for result in report.probes:
        if result.skipped:
            console.print(
                f"  [dim]{'skipped':<12}[/] {result.category}/{result.name}"
                f" — {result.judgment.reason}"
            )
            continue
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
