"""FR-7: Compliance mapping — OWASP LLM Top 10 2025 and MITRE ATLAS."""

import json
import re

from llm_endpoint_scanner.compliance import (
    ATLAS_FRAMEWORK,
    FRAMEWORK_VERSIONS,
    OWASP_FRAMEWORK,
    compliance_for,
)
from llm_endpoint_scanner.models import Judgment, ProbeResult, Verdict
from llm_endpoint_scanner.probes import ALL_CATEGORIES
from llm_endpoint_scanner.reporting import (
    Report,
    render_markdown_report,
    write_json_report,
)

OWASP_ID_RE = re.compile(r"LLM\d{2}$")
ATLAS_ID_RE = re.compile(r"AML\.T\d{4}(\.\d{3})?$")


def make_report(probes: list[ProbeResult]) -> Report:
    return Report(
        run_id="ab12cd34",
        target="https://example.com/api/chat",
        timestamp="2026-10-22T12:00:00+00:00",
        scanner_version="1.0.0",
        config_hash="f" * 64,
        duration_seconds=1.0,
        overall_verdict="success",
        summary={p.category: p.judgment.verdict.value for p in probes},
        probes=probes,
    )


def make_result(category: str) -> ProbeResult:
    return ProbeResult(
        category=category,
        name="some_probe",
        severity="high",
        payload_sent="payload text",
        response="response text",
        judgment=Judgment(
            verdict=Verdict.SUCCESS, confidence=1.0, method="canary", reason="why"
        ),
    )


def test_every_builtin_category_has_nonempty_valid_mapping():
    categories = {c.category for c in ALL_CATEGORIES}
    assert categories
    for category in categories:
        mapping = compliance_for(category)
        assert mapping is not None, category
        owasp, atlas = mapping["owasp_llm_top10_2025"], mapping["mitre_atlas"]
        assert owasp and atlas, category
        assert all(OWASP_ID_RE.match(i) for i in owasp), category
        assert all(ATLAS_ID_RE.match(i) for i in atlas), category


def test_unknown_category_maps_to_none():
    assert compliance_for("no_such_category") is None


def test_json_report_carries_compliance(tmp_path):
    probes = [make_result("prompt_extraction"), make_result("missing_limits")]
    out = tmp_path / "report.json"
    write_json_report(make_report(probes), str(out))
    data = json.loads(out.read_text(encoding="utf-8"))

    assert data["compliance_frameworks"] == list(FRAMEWORK_VERSIONS)
    assert OWASP_FRAMEWORK in data["compliance_frameworks"]
    assert ATLAS_FRAMEWORK in data["compliance_frameworks"]

    for category in data["summary"]:
        mapping = data["compliance"][category]
        assert mapping["owasp_llm_top10_2025"]
        assert mapping["mitre_atlas"]

    for probe in data["probes"]:
        assert probe["compliance"] == data["compliance"][probe["category"]]
    assert data["compliance"]["prompt_extraction"]["owasp_llm_top10_2025"] == ["LLM07"]
    assert data["compliance"]["missing_limits"]["mitre_atlas"] == ["AML.T0029"]


def test_markdown_report_carries_compliance_column_and_versions():
    report = make_report([make_result("direct_injection"), make_result("data_leakage")])
    md = render_markdown_report(report)

    header = md.split("## Overall")[0]
    assert OWASP_FRAMEWORK in header
    assert ATLAS_FRAMEWORK in header

    summary_header = next(
        line for line in md.splitlines() if line.startswith("| Category")
    )
    assert "Compliance" in summary_header

    assert "OWASP LLM01; ATLAS AML.T0051.000" in md
    assert "OWASP LLM02; ATLAS AML.T0057" in md
    assert "**Compliance:**" in md  # per-finding detail
