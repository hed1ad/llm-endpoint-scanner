"""End-to-end against the bundled mock server over real HTTP (NFR-4).

The vulnerable mock must produce a damning report; the hardened mock must
come back clean of `success` verdicts. This is the offline development loop
from the spec, exercised as a test.
"""

import importlib
import socket
import sys
import threading
from pathlib import Path

import pytest

from llm_endpoint_scanner.config import ScanConfig
from llm_endpoint_scanner.models import Verdict
from llm_endpoint_scanner.runner import run_scan

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))
mock_server = importlib.import_module("mock_server")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(params=["vulnerable", "hardened"])
def mock_endpoint(request):
    server = mock_server.make_server(_free_port(), mode=request.param)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield request.param, f"http://127.0.0.1:{server.server_address[1]}/chat"
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


def _config(url: str) -> ScanConfig:
    return ScanConfig.model_validate(
        {
            "endpoint": {
                "url": url,
                "request_template": {
                    "messages": [{"role": "user", "content": "{{INPUT}}"}]
                },
                "response_path": "choices.0.message.content",
            },
            "limits": {"timeout_seconds": 5, "max_requests_per_second": 5},
        }
    )


def test_scan_against_mock_modes(mock_endpoint):
    mode, url = mock_endpoint
    report = run_scan(_config(url))

    if mode == "vulnerable":
        assert report.overall_verdict == Verdict.SUCCESS.value
        succeeded = {
            r.category for r in report.probes if r.judgment.verdict is Verdict.SUCCESS
        }
        assert "prompt_extraction" in succeeded
        assert "direct_injection" in succeeded
        assert "missing_limits" in succeeded
        # The vulnerable mock leaks a fake API key: pattern detection fires.
        leakage = [r for r in report.probes if r.category == "data_leakage"]
        assert any(r.judgment.method == "leakage_pattern" for r in leakage)
    else:
        assert report.overall_verdict != Verdict.SUCCESS.value
        assert all(r.judgment.verdict is not Verdict.SUCCESS for r in report.probes)
        burst = next(r for r in report.probes if r.name == "burst_acceptance")
        assert burst.requests_accepted < burst.requests_sent
        long_input = next(r for r in report.probes if r.name == "long_input")
        assert long_input.judgment.verdict is Verdict.INCONCLUSIVE
