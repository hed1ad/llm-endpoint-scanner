"""Scan selection and request budgeting (FR-8).

Selection is by category name and/or probe name; the request budget
(--max-requests) is a hard cap on the whole scan and includes the single
baseline control prompt, which always runs first.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from .models import Probe
from .probes import ALL_CATEGORIES

# The neutral control prompt (Spec §6.2) always runs first and counts
# against the budget like any other request.
BASELINE_REQUESTS = 1


class SelectionError(Exception):
    """Invalid include/exclude/max_requests; raised before any request is sent."""


@dataclass(frozen=True)
class ScanPlan:
    """Resolved scan: probes to run, budget-skipped probes, request total."""

    probes: list[Probe] = field(default_factory=list)
    skipped: list[tuple[Probe, str]] = field(default_factory=list)
    total_requests: int = 0


def _check_names(names: Sequence[str], flag: str) -> None:
    categories = {c.category for c in ALL_CATEGORIES}
    probes = {p.name for c in ALL_CATEGORIES for p in c.probes()}
    unknown = sorted(set(names) - categories - probes)
    if unknown:
        raise SelectionError(
            f"Unknown {flag} name(s): {', '.join(unknown)}. "
            f"Known categories: {', '.join(sorted(categories))}. "
            f"Known probes: {', '.join(sorted(probes))}."
        )


def select_probes(
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
) -> list[Probe]:
    """Resolve include/exclude to the probe list, preserving category order."""
    if include and exclude:
        raise SelectionError("--include and --exclude cannot be used together.")
    _check_names(include or [], "--include")
    _check_names(exclude or [], "--exclude")
    selected: list[Probe] = []
    for category in ALL_CATEGORIES:
        for probe in category.probes():
            if (
                include
                and category.category not in include
                and probe.name not in include
            ):
                continue
            if exclude and (category.category in exclude or probe.name in exclude):
                continue
            selected.append(probe)
    return selected


def plan_scan(
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
    max_requests: int | None = None,
) -> ScanPlan:
    """Apply selection and the request budget.

    A probe runs only if all its repetitions fit in the remaining budget;
    otherwise it is skipped with a reason and a later, cheaper probe may
    still run. The budget is never exceeded.
    """
    if max_requests is not None and max_requests < BASELINE_REQUESTS:
        raise SelectionError(
            f"max_requests must be at least {BASELINE_REQUESTS} "
            f"(the baseline control prompt counts), got {max_requests}."
        )
    probes: list[Probe] = []
    skipped: list[tuple[Probe, str]] = []
    spent = BASELINE_REQUESTS
    for probe in select_probes(include, exclude):
        if max_requests is not None and probe.repetitions > max_requests - spent:
            skipped.append(
                (
                    probe,
                    f"Request budget exceeded: probe needs {probe.repetitions} "
                    f"request(s), only {max_requests - spent} left "
                    f"(max_requests={max_requests}).",
                )
            )
            continue
        probes.append(probe)
        spent += probe.repetitions
    return ScanPlan(probes=probes, skipped=skipped, total_requests=spent)
