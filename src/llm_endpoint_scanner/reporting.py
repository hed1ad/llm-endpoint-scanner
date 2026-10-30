"""Scan report: data model plus JSON and Markdown renderers (Spec §7).

Both formats are produced from the same scan. JSON is for automation,
Markdown for humans. Secrets never enter either: only payloads and responses
are recorded, never request headers (NFR-2).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from .compliance import FRAMEWORK_VERSIONS, compliance_for
from .models import ProbeResult, Verdict

# Long payloads (e.g. the FR-6 long-input probe) and long responses are
# truncated in the human-readable report; the JSON report keeps them verbatim.
_MD_EVIDENCE_LIMIT = 2000

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


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
    baseline_response: str | None = None
    probes: list[ProbeResult] = field(default_factory=list)

    def triage(self) -> list[tuple[str, str]]:
        """Categories that succeeded, worst severity first — "look here first"."""
        worst_by_category: dict[str, str] = {}
        for result in self.probes:
            if result.skipped or result.judgment.verdict is not Verdict.SUCCESS:
                continue
            current = worst_by_category.get(result.category, "low")
            if _SEVERITY_RANK.get(result.severity, 0) > _SEVERITY_RANK.get(current, 0):
                worst_by_category[result.category] = result.severity
        return sorted(
            worst_by_category.items(),
            key=lambda item: _SEVERITY_RANK.get(item[1], 0),
            reverse=True,
        )


def write_json_report(report: Report, path: str) -> None:
    data = asdict(report)
    # FR-7: framework versions in the header, compliance per probe and per
    # category in the summary section.
    data["compliance_frameworks"] = list(FRAMEWORK_VERSIONS)
    data["compliance"] = {
        category: compliance_for(category) for category in report.summary
    }
    for probe in data["probes"]:
        probe["compliance"] = compliance_for(probe["category"])
        judgment = probe["judgment"]
        judgment["verdict"] = (
            judgment["verdict"].value
            if isinstance(judgment["verdict"], Verdict)
            else judgment["verdict"]
        )
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def _md_evidence(text: str) -> str:
    if len(text) > _MD_EVIDENCE_LIMIT:
        return text[:_MD_EVIDENCE_LIMIT] + (
            f"\n\n… [truncated, {len(text)} chars total — "
            "see the JSON report for the full text]"
        )
    return text


def _md_compliance(category: str) -> str:
    mapping = compliance_for(category)
    if mapping is None:
        return "—"
    owasp = ", ".join(mapping["owasp_llm_top10_2025"])
    atlas = ", ".join(mapping["mitre_atlas"])
    return f"OWASP {owasp}; ATLAS {atlas}"


def _md_header(report: Report) -> list[str]:
    return [
        "# LLM Endpoint Security Scan Report",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Scan timestamp:** {report.timestamp}",
        f"- **Scanner version:** {report.scanner_version}",
        f"- **Config hash (SHA-256):** `{report.config_hash}`",
        f"- **Run ID:** `{report.run_id}`",
        f"- **Total duration:** {report.duration_seconds}s",
        f"- **Compliance frameworks:** {'; '.join(FRAMEWORK_VERSIONS)}",
        "",
    ]


def _md_verdict(report: Report) -> list[str]:
    lines = [f"## Overall verdict: {report.overall_verdict.upper()}", ""]
    triage = report.triage()
    if triage:
        lines += [
            "**Look here first** — categories where at least one probe succeeded,",
            "ordered by severity:",
            "",
        ]
        lines += [
            f"{idx}. `{category}` (severity: {severity})"
            for idx, (category, severity) in enumerate(triage, 1)
        ]
    else:
        lines += [
            "No probe succeeded. Note: a clean report is not proof of safety —",
            "detection beyond canary markers is heuristic (see Limitations).",
        ]
    lines.append("")
    return lines


def _md_summary(report: Report) -> list[str]:
    lines = [
        "## Summary",
        "",
        "| Category | Verdict | Probes | Succeeded | Compliance |",
        "|---|---|---|---|---|",
    ]
    for category, verdict in report.summary.items():
        probes = [p for p in report.probes if p.category == category]
        succeeded = sum(1 for p in probes if p.judgment.verdict is Verdict.SUCCESS)
        lines.append(
            f"| {_md_escape(category)} | {verdict} | {len(probes)} | {succeeded} "
            f"| {_md_compliance(category)} |"
        )
    lines.append("")
    return lines


def _md_response(result: ProbeResult) -> list[str]:
    if result.skipped:
        return ["_Probe not executed._"]
    if result.response is None:
        return ["_No response (endpoint error)._"]
    return ["```text", _md_evidence(result.response), "```"]


def _md_finding(result: ProbeResult) -> list[str]:
    judgment = result.judgment
    verdict = "skipped" if result.skipped else judgment.verdict.value
    lines = [
        f"### {result.category} / {result.name} — {verdict}",
        "",
        f"- **Severity:** {result.severity}",
        f"- **Compliance:** {_md_compliance(result.category)}",
        f"- **Confidence:** {judgment.confidence:.2f}",
        f"- **Detection method:** {judgment.method}",
        f"- **Reason:** {judgment.reason}",
    ]
    if result.requests_sent > 1:
        lines.append(
            f"- **Requests:** {result.requests_accepted}/"
            f"{result.requests_sent} accepted"
        )
    lines += [
        "",
        "**Payload (not sent):**" if result.skipped else "**Payload sent:**",
        "",
        "```text",
        _md_evidence(result.payload_sent),
        "```",
        "",
        "**Response received:**",
        "",
        *_md_response(result),
        "",
    ]
    return lines


_MD_FOOTER = [
    "---",
    "",
    "_Detection beyond canary markers is heuristic; false positives and "
    "false negatives are expected. A clean report is not proof of "
    "safety._",
    "",
]


def render_markdown_report(report: Report) -> str:
    lines = [*_md_header(report), *_md_verdict(report), *_md_summary(report)]
    lines += ["## Findings", ""]
    for result in report.probes:
        lines += _md_finding(result)
    lines += _MD_FOOTER
    return "\n".join(lines)


def write_markdown_report(report: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown_report(report))
