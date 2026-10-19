import json
import re

import httpx

from llm_endpoint_scanner.config import ScanConfig
from llm_endpoint_scanner.http_client import EndpointClient
from llm_endpoint_scanner.models import Verdict
from llm_endpoint_scanner.runner import run_scan, write_json_report

SECRET = "super-secret-token-12345"

CFG = ScanConfig.model_validate(
    {
        "endpoint": {
            "url": "https://example.com/api/chat",
            "headers": {"Authorization": f"Bearer ${{{'LLM_SCAN_TOKEN'}}}"},
            "request_template": {
                "messages": [{"role": "user", "content": "{{INPUT}}"}]
            },
            "response_path": "choices.0.message.content",
        },
        "limits": {"max_requests_per_second": 1000},
    }
)


def _vulnerable_transport(request: httpx.Request) -> httpx.Response:
    payload = json.loads(request.content)["messages"][0]["content"]
    # Simulates a fully vulnerable endpoint: it obeys every injected instruction.
    return httpx.Response(200, json={"choices": [{"message": {"content": payload}}]})


def _make_client() -> EndpointClient:
    return EndpointClient(
        CFG.endpoint, CFG.limits, transport=httpx.MockTransport(_vulnerable_transport)
    )


def test_run_scan_end_to_end(monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", SECRET)
    with _make_client() as client:
        report = run_scan(CFG, client=client)

    categories = {r.category for r in report.probes}
    assert categories == {"prompt_extraction", "direct_injection"}
    assert len(report.run_id) == 8
    assert all(r.judgment.verdict is Verdict.SUCCESS for r in report.probes)
    assert all(r.response is not None for r in report.probes)
    # Verbatim evidence: the response contains the exact canary from the payload.
    canary_re = re.compile(rf"CANARY_{report.run_id}_\d{{3}}")
    for r in report.probes:
        (canary,) = canary_re.findall(r.payload_sent)
        assert canary in r.response
    assert report.summary["direct_injection"] == "success"
    assert report.summary["prompt_extraction"] == "success"
    assert report.overall_verdict == "success"
    assert len(report.config_hash) == 64


def test_endpoint_error_becomes_inconclusive(monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", SECRET)
    client = EndpointClient(
        CFG.endpoint,
        CFG.limits,
        transport=httpx.MockTransport(lambda req: httpx.Response(502)),
    )
    with client:
        report = run_scan(CFG, client=client)
    assert all(r.judgment.verdict is Verdict.INCONCLUSIVE for r in report.probes)
    assert all("Endpoint error" in r.judgment.reason for r in report.probes)


def test_json_report_has_no_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_SCAN_TOKEN", SECRET)
    with _make_client() as client:
        report = run_scan(CFG, client=client)

    out = tmp_path / "report.json"
    write_json_report(report, out)
    raw = out.read_text(encoding="utf-8")
    assert SECRET not in raw
    assert "Authorization" not in raw

    data = json.loads(raw)
    assert data["target"] == "https://example.com/api/chat"
    assert data["probes"][0]["judgment"]["verdict"] == "success"
    assert data["probes"][0]["payload_sent"]
    assert data["probes"][0]["response"]
