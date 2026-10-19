"""Scan orchestration and reporting."""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import ScanConfig, config_hash
from .http_client import EndpointClient, EndpointError
from .judge import CanaryJudge, Judge
from .models import Judgment, ProbeResult, Verdict
from .probes import ALL_CATEGORIES

_VERDICT_RANK = {Verdict.FAILED: 0, Verdict.INCONCLUSIVE: 1, Verdict.SUCCESS: 2}


@dataclass(frozen=True)
class Report:
    run_id: str
    target: str
    timestamp: str
    scanner_version: str
    config_hash: str
    duration_seconds: float
    overall_verdict: str
    summary: dict[str, str]
    probes: list[ProbeResult] = field(default_factory=list)


def make_canary(run_id: str, seq: int) -> str:
    return f"CANARY_{run_id}_{seq:03d}"


def _worst(verdicts: list[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _VERDICT_RANK[v])


def run_scan(
    cfg: ScanConfig,
    client: EndpointClient | None = None,
    judge: Judge | None = None,
) -> Report:
    judge = judge or CanaryJudge()
    run_id = secrets.token_hex(4)
    started_at = time.monotonic()
    results: list[ProbeResult] = []
    seq = 0

    def _run(client: EndpointClient) -> None:
        nonlocal seq
        for category in ALL_CATEGORIES:
            for probe in category.probes():
                seq += 1
                canary = make_canary(run_id, seq)
                payload = probe.payload_template.format(canary=canary)
                if len(payload) > cfg.limits.max_probe_length:
                    results.append(
                        ProbeResult(
                            category=probe.category,
                            name=probe.name,
                            severity=probe.severity,
                            payload_sent=payload,
                            response=None,
                            judgment=Judgment(
                                verdict=Verdict.INCONCLUSIVE,
                                confidence=1.0,
                                method="none",
                                reason="Payload exceeds "
                                f"max_probe_length={cfg.limits.max_probe_length}; "
                                "probe skipped.",
                            ),
                        )
                    )
                    continue
                try:
                    response = client.send(payload)
                except EndpointError as exc:
                    results.append(
                        ProbeResult(
                            category=probe.category,
                            name=probe.name,
                            severity=probe.severity,
                            payload_sent=payload,
                            response=None,
                            judgment=Judgment(
                                verdict=Verdict.INCONCLUSIVE,
                                confidence=1.0,
                                method="none",
                                reason=f"Endpoint error: {exc}",
                            ),
                        )
                    )
                    continue
                results.append(
                    ProbeResult(
                        category=probe.category,
                        name=probe.name,
                        severity=probe.severity,
                        payload_sent=payload,
                        response=response,
                        judgment=judge.evaluate(probe, response, canary),
                    )
                )

    if client is not None:
        _run(client)
    else:
        with EndpointClient(cfg.endpoint, cfg.limits) as owned:
            _run(owned)

    by_category: dict[str, list[Verdict]] = {}
    for result in results:
        by_category.setdefault(result.category, []).append(result.judgment.verdict)
    summary = {cat: _worst(verdicts).value for cat, verdicts in by_category.items()}
    overall = (
        _worst([r.judgment.verdict for r in results]).value
        if results
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
        probes=results,
    )


def write_json_report(report: Report, path: str | Path) -> None:
    """Serialize the report. Secrets never enter it: only payloads and
    responses are recorded, never request headers (NFR-2)."""
    data = asdict(report)
    for probe in data["probes"]:
        judgment = probe["judgment"]
        judgment["verdict"] = (
            judgment["verdict"].value
            if isinstance(judgment["verdict"], Verdict)
            else judgment["verdict"]
        )
    Path(path).write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
