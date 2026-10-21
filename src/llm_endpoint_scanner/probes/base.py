"""Probe category protocol (NFR-3)."""

from __future__ import annotations

from typing import Protocol

from ..models import Probe


class ProbeCategory(Protocol):
    category: str

    def probes(self) -> list[Probe]: ...
