"""FR-9: user-defined probes from the config's ``custom_probes`` list.

Custom probes are converted into the same Probe/ProbeCategory structures the
built-in packs use, so the runner, selection, judges, and reports treat them
identically (NFR-3). Categories named in the config may be new; unknown
categories simply have no compliance mapping (FR-7 reports ``None``).
"""

from __future__ import annotations

from collections.abc import Sequence

from ..config import CustomProbeConfig
from ..models import Probe
from .base import ProbeCategory


class _CustomCategory:
    def __init__(self, category: str, probes: list[Probe]) -> None:
        self.category = category
        self._probes = probes

    def probes(self) -> list[Probe]:
        return list(self._probes)


def custom_probe_categories(
    custom: Sequence[CustomProbeConfig],
) -> list[ProbeCategory]:
    """Group custom probes by category, preserving config order."""
    by_category: dict[str, list[Probe]] = {}
    for probe in custom:
        by_category.setdefault(probe.category, []).append(
            Probe(
                category=probe.category,
                name=probe.name,
                payload_template=probe.payload_template,
                severity=probe.severity,
                repetitions=probe.repetitions,
                # Same rule as the built-in burst probes (FR-6): repetitions
                # above 1 intentionally ignore the client-side rate limit.
                respect_rate_limit=probe.repetitions <= 1,
            )
        )
    return [_CustomCategory(name, probes) for name, probes in by_category.items()]
