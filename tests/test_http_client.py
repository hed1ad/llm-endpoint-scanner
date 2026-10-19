import httpx
import pytest

from llm_endpoint_scanner.config import EndpointConfig, LimitsConfig
from llm_endpoint_scanner.http_client import (
    EndpointClient,
    EndpointError,
    extract_path,
    render_request,
)

ENDPOINT = EndpointConfig(
    url="https://example.com/api/chat",
    headers={"Authorization": "Bearer ${LLM_SCAN_TOKEN}"},
    request_template={"messages": [{"role": "user", "content": "{{INPUT}}"}]},
    response_path="choices.0.message.content",
)
LIMITS = LimitsConfig(max_requests_per_second=1000)


def test_render_request_replaces_marker():
    body = render_request(ENDPOINT.request_template, "PAYLOAD")
    assert body["messages"][0]["content"] == "PAYLOAD"
    assert "{{INPUT}}" not in str(body)
    assert ENDPOINT.request_template["messages"][0]["content"] == "{{INPUT}}"


def test_extract_path_nested_with_index():
    data = {"choices": [{"message": {"content": "hello"}}]}
    assert extract_path(data, "choices.0.message.content") == "hello"


def test_extract_path_miss_reports_segment():
    with pytest.raises(EndpointError, match="missing key 'missing'"):
        extract_path({"choices": {}}, "choices.missing.content")
    with pytest.raises(EndpointError, match="missing list index '5'"):
        extract_path({"choices": []}, "choices.5.message.content")


def _echo_transport(request: httpx.Request) -> httpx.Response:
    import json

    text = json.loads(request.content)["messages"][0]["content"]
    return httpx.Response(
        200, json={"choices": [{"message": {"content": f"echo: {text}"}}]}
    )


def test_send_success(monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "tok123")
    client = EndpointClient(ENDPOINT, LIMITS, transport=httpx.MockTransport(_echo_transport))
    try:
        assert client.send("hello") == "echo: hello"
    finally:
        client.close()


def test_send_http_500_raises(monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    client = EndpointClient(
        ENDPOINT,
        LIMITS,
        transport=httpx.MockTransport(lambda req: httpx.Response(500)),
    )
    try:
        with pytest.raises(EndpointError, match="HTTP 500"):
            client.send("x")
    finally:
        client.close()


def test_send_timeout_raises(monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("boom", request=request)

    client = EndpointClient(
        ENDPOINT, LIMITS, transport=httpx.MockTransport(timeout_handler)
    )
    try:
        with pytest.raises(EndpointError, match="timed out"):
            client.send("x")
    finally:
        client.close()


def test_send_non_json_raises(monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    client = EndpointClient(
        ENDPOINT,
        LIMITS,
        transport=httpx.MockTransport(lambda req: httpx.Response(200, text="not json")),
    )
    try:
        with pytest.raises(EndpointError, match="non-JSON"):
            client.send("x")
    finally:
        client.close()
