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
    # How many times the payload is sent. Values > 1 are used by burst
    # probes (FR-6) that test server-side rate limiting.
    repetitions: int = 1
    # Burst probes intentionally ignore the configured client-side rate
    # limit: exceeding it is exactly what they test for (FR-6).
    respect_rate_limit: bool = True


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
    # Request accounting, primarily for burst probes (FR-6): how many
    # requests were sent and how many the endpoint accepted.
    requests_sent: int = 1
    requests_accepted: int = 1
