"""Shared data types for probes, verdicts and results."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Probe:
    category: str
    name: str
    payload_template: str
    severity: str


@dataclass(frozen=True)
class Judgment:
    verdict: Verdict
    confidence: float
    method: str
    reason: str


@dataclass(frozen=True)
class ProbeResult:
    category: str
    name: str
    severity: str
    payload_sent: str
    response: str | None
    judgment: Judgment
