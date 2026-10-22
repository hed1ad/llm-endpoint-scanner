"""Markdown report rendering (Spec §7)."""

from llm_endpoint_scanner.models import Judgment, ProbeResult, Verdict
from llm_endpoint_scanner.reporting import (
    Report,
    render_markdown_report,
    write_markdown_report,
)


def make_report(probes: list[ProbeResult], overall: str) -> Report:
    summary: dict[str, str] = {}
    for probe in probes:
        current = summary.get(probe.category)
        if current != Verdict.SUCCESS.value:
            summary[probe.category] = (
                probe.judgment.verdict.value
                if probe.judgment.verdict is Verdict.SUCCESS
                else current or probe.judgment.verdict.value
            )
    return Report(
        run_id="ab12cd34",
        target="https://example.com/api/chat",
        timestamp="2026-10-21T12:00:00+00:00",
        scanner_version="1.0.0",
        config_hash="f" * 64,
        duration_seconds=12.3,
        overall_verdict=overall,
        summary=summary,
        baseline_response="Hello!",
        probes=probes,
    )


def make_result(category, verdict, severity="high", method="canary", reason="why"):
    return ProbeResult(
        category=category,
        name="some_probe",
        severity=severity,
        payload_sent="payload text",
        response="response text" if verdict is not Verdict.INCONCLUSIVE else None,
        judgment=Judgment(
            verdict=verdict, confidence=1.0, method=method, reason=reason
        ),
    )


def test_markdown_header_carries_required_fields():
    report = make_report([], "failed")
    md = render_markdown_report(report)
    for required in (
        "https://example.com/api/chat",
        "2026-10-21T12:00:00+00:00",
        "1.0.0",
        "f" * 64,
        "12.3s",
    ):
        assert required in md


def test_markdown_triage_orders_successes_by_severity():
    report = make_report(
        [
            make_result("role_escape", Verdict.SUCCESS, severity="low"),
            make_result("direct_injection", Verdict.SUCCESS, severity="high"),
            make_result("data_leakage", Verdict.FAILED),
        ],
        "success",
    )
    md = render_markdown_report(report)
    assert "Look here first" in md
    assert md.index("direct_injection") < md.index("role_escape")
    assert "data_leakage" not in md.split("## Summary")[0].split("## Overall")[1]


def test_markdown_clean_report_carries_honesty_note():
    report = make_report([make_result("role_escape", Verdict.FAILED)], "failed")
    md = render_markdown_report(report)
    assert "not proof of safety" in md


def test_markdown_finding_details_and_verdicts():
    report = make_report(
        [make_result("prompt_extraction", Verdict.SUCCESS, reason="canary echoed")],
        "success",
    )
    md = render_markdown_report(report)
    assert "### prompt_extraction / some_probe — success" in md
    assert "**Detection method:** canary" in md
    assert "canary echoed" in md
    assert "payload text" in md
    assert "response text" in md


def test_markdown_truncates_long_evidence_but_mentions_json():
    long_result = ProbeResult(
        category="missing_limits",
        name="long_input",
        severity="low",
        payload_sent="p" * 5000,
        response="r" * 5000,
        judgment=Judgment(
            verdict=Verdict.SUCCESS, confidence=1.0, method="canary", reason="echoed"
        ),
    )
    md = render_markdown_report(make_report([long_result], "success"))
    assert "p" * 5000 not in md
    assert "truncated" in md
    assert "JSON report" in md


def test_write_markdown_report_creates_file(tmp_path):
    out = tmp_path / "report.md"
    write_markdown_report(make_report([], "failed"), str(out))
    assert out.read_text(encoding="utf-8").startswith("# LLM Endpoint Security Scan")
