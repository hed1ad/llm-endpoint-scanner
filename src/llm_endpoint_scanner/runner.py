"""Scan orchestration: baseline, probe execution, report assembly."""

from __future__ import annotations

import secrets
import time
from collections.abc import Sequence
from datetime import datetime, timezone

from . import __version__
from .config import ScanConfig, config_hash
from .http_client import EndpointClient, EndpointError
from .judge import BASELINE_PROMPT, CompositeJudge
from .models import Judgment, Probe, ProbeResult, Verdict
from .reporting import Report, write_json_report, write_markdown_report
from .selection import plan_scan

__all__ = [
    "Report",
    "make_canary",
    "run_scan",
    "write_json_report",
    "write_markdown_report",
]

_VERDICT_RANK = {Verdict.FAILED: 0, Verdict.INCONCLUSIVE: 1, Verdict.SUCCESS: 2}


def make_canary(run_id: str, seq: int) -> str:
    return f"CANARY_{run_id}_{seq:03d}"


def _worst(verdicts: list[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _VERDICT_RANK[v])


def _skipped(
    probe: Probe,
    payload: str,
    reason: str,
    requests_sent: int = 0,
    skipped: bool = False,
) -> ProbeResult:
    return ProbeResult(
        category=probe.category,
        name=probe.name,
        severity=probe.severity,
        payload_sent=payload,
        response=None,
        judgment=Judgment(
            verdict=Verdict.INCONCLUSIVE,
            confidence=1.0,
            method="none",
            reason=reason,
        ),
        requests_sent=requests_sent,
        requests_accepted=0,
        skipped=skipped,
    )


def _run_probe(
    probe: Probe,
    payload: str,
    client: EndpointClient,
    judge: CompositeJudge,
    canary: str,
    baseline: str | None,
    max_probe_length: int,
) -> ProbeResult:
    if len(payload) > max_probe_length:
        return _skipped(
            probe,
            payload,
            f"Payload exceeds max_probe_length={max_probe_length}; probe skipped.",
        )

    responses: list[str] = []
    first_error: EndpointError | None = None
    for _ in range(probe.repetitions):
        try:
            responses.append(client.send(payload, throttle=probe.respect_rate_limit))
        except EndpointError as exc:
            # For burst probes a rejection (e.g. HTTP 429) is the signal, not a
            # scan failure: keep going and let the judge count acceptances.
            if probe.repetitions <= 1:
                return _skipped(
                    probe, payload, f"Endpoint error: {exc}", requests_sent=1
                )
            if first_error is None:
                first_error = exc

    judgment = judge.evaluate(probe, responses, canary, baseline)
    if first_error is not None and responses:
        judgment = Judgment(
            verdict=judgment.verdict,
            confidence=judgment.confidence,
            method=judgment.method,
            reason=f"{judgment.reason} (first rejection: {first_error})",
        )
    return ProbeResult(
        category=probe.category,
        name=probe.name,
        severity=probe.severity,
        payload_sent=payload,
        response=responses[0] if responses else None,
        judgment=judgment,
        requests_sent=probe.repetitions,
        requests_accepted=len(responses),
    )


def run_scan(
    cfg: ScanConfig,
    client: EndpointClient | None = None,
    judge: CompositeJudge | None = None,
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
    max_requests: int | None = None,
) -> Report:
    judge = judge or CompositeJudge()
    plan = plan_scan(include, exclude, max_requests)
    run_id = secrets.token_hex(4)
    started_at = time.monotonic()
    results: list[ProbeResult] = []
    seq = 0
    baseline: str | None = None

    def _run(client: EndpointClient) -> None:
        nonlocal seq, baseline
        # Spec §6.2: a neutral control prompt establishes the baseline used by
        # the divergence heuristic. A baseline failure never aborts the scan.
        try:
            baseline = client.send(BASELINE_PROMPT)
        except EndpointError:
            baseline = None

        for probe in plan.probes:
            seq += 1
            canary = make_canary(run_id, seq)
            payload = probe.payload_template.format(canary=canary)
            results.append(
                _run_probe(
                    probe,
                    payload,
                    client,
                    judge,
                    canary,
                    baseline,
                    cfg.limits.max_probe_length,
                )
            )

    if client is not None:
        _run(client)
    else:
        with EndpointClient(cfg.endpoint, cfg.limits) as owned:
            _run(owned)

    # Budget-skipped probes are recorded with a reason (never silently
    # dropped) but excluded from the summary and the overall verdict (FR-8).
    for probe, reason in plan.skipped:
        seq += 1
        payload = probe.payload_template.format(canary=make_canary(run_id, seq))
        results.append(_skipped(probe, payload, reason, skipped=True))

    active = [r for r in results if not r.skipped]
    by_category: dict[str, list[Verdict]] = {}
    for result in active:
        by_category.setdefault(result.category, []).append(result.judgment.verdict)
    summary = {cat: _worst(verdicts).value for cat, verdicts in by_category.items()}
    overall = (
        _worst([r.judgment.verdict for r in active]).value
        if active
        else Verdict.INCONCLUSIVE.value
    )

    return Report(
        run_id=run_id,
        target=cfg.endpoint.url,
        timestamp=datetime.now(timezone.utc).isoformat(),
        scanner_version=__version__,
        config_hash=config_hash(cfg),
        duration_seconds=round(time.monotonic() - started_at, 3),
        overall_verdict=overall,
        summary=summary,
        baseline_response=baseline,
        probes=results,
    )
