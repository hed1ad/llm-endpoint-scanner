import time
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from llm_endpoint_scanner.config import EndpointConfig, LimitsConfig
from llm_endpoint_scanner.http_client import (
    EndpointClient,
    EndpointError,
    extract_path,
    parse_retry_after,
    render_request,
)

ENDPOINT = EndpointConfig(
    url="https://example.com/api/chat",
    headers={"Authorization": "Bearer ${LLM_SCAN_TOKEN}"},
    request_template={"messages": [{"role": "user", "content": "{{INPUT}}"}]},
    response_path="choices.0.message.content",
)
LIMITS = LimitsConfig(max_requests_per_second=1000)
LIMITS_NO_RETRY = LimitsConfig(max_requests_per_second=1000, max_retries=0)


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
    client = EndpointClient(
        ENDPOINT, LIMITS, transport=httpx.MockTransport(_echo_transport)
    )
    try:
        assert client.send("hello") == "echo: hello"
    finally:
        client.close()


def test_send_http_500_raises(monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    client = EndpointClient(
        ENDPOINT,
        LIMITS_NO_RETRY,
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
        ENDPOINT, LIMITS_NO_RETRY, transport=httpx.MockTransport(timeout_handler)
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


@pytest.fixture
def sleep_log(monkeypatch):
    """Replace time.sleep with a recorder so retries never actually wait."""
    delays: list[float] = []
    monkeypatch.setattr(time, "sleep", delays.append)
    return delays


def _ok_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})


def test_parse_retry_after_seconds():
    assert parse_retry_after("7") == 7.0
    assert parse_retry_after(" 2.5 ") == 2.5
    assert parse_retry_after("-5") == 0.0


def test_parse_retry_after_http_date():
    future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30))
    delay = parse_retry_after(future)
    assert delay is not None
    assert 25 < delay <= 30


def test_parse_retry_after_garbage():
    assert parse_retry_after(None) is None
    assert parse_retry_after("") is None
    assert parse_retry_after("soon-ish") is None


def test_send_retries_then_succeeds_with_backoff(monkeypatch, sleep_log):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    calls = 0

    def flaky(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            return httpx.Response(503)
        return _ok_response(request)

    client = EndpointClient(ENDPOINT, LIMITS, transport=httpx.MockTransport(flaky))
    try:
        assert client.send("x", throttle=False) == "ok"
    finally:
        client.close()
    assert calls == 3
    assert sleep_log == [1.0, 2.0]  # exponential: base * 2**attempt


def test_send_honors_retry_after_header(monkeypatch, sleep_log):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    calls = 0

    def throttled(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return _ok_response(request)

    client = EndpointClient(ENDPOINT, LIMITS, transport=httpx.MockTransport(throttled))
    try:
        assert client.send("x", throttle=False) == "ok"
    finally:
        client.close()
    assert sleep_log == [7.0]


def test_send_retry_after_capped(monkeypatch, sleep_log):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    calls = 0

    def throttled(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "120"})
        return _ok_response(request)

    limits = LimitsConfig(max_requests_per_second=1000, max_retry_delay_seconds=5)
    client = EndpointClient(ENDPOINT, limits, transport=httpx.MockTransport(throttled))
    try:
        assert client.send("x", throttle=False) == "ok"
    finally:
        client.close()
    assert sleep_log == [5.0]


def test_send_exhausts_retries(monkeypatch, sleep_log):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    calls = 0

    def always_busy(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429)

    limits = LimitsConfig(max_requests_per_second=1000, max_retries=2)
    client = EndpointClient(
        ENDPOINT, limits, transport=httpx.MockTransport(always_busy)
    )
    try:
        with pytest.raises(
            EndpointError, match=r"HTTP 429 \(gave up after 3 attempts\)"
        ):
            client.send("x", throttle=False)
    finally:
        client.close()
    assert calls == 3


def test_send_does_not_retry_definitive_4xx(monkeypatch, sleep_log):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    calls = 0

    def bad_request(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(400)

    client = EndpointClient(
        ENDPOINT, LIMITS, transport=httpx.MockTransport(bad_request)
    )
    try:
        with pytest.raises(EndpointError, match="HTTP 400"):
            client.send("x", throttle=False)
    finally:
        client.close()
    assert calls == 1
    assert sleep_log == []


def test_send_retries_transport_error(monkeypatch, sleep_log):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    calls = 0

    def unstable(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("connection reset", request=request)
        return _ok_response(request)

    client = EndpointClient(ENDPOINT, LIMITS, transport=httpx.MockTransport(unstable))
    try:
        assert client.send("x", throttle=False) == "ok"
    finally:
        client.close()
    assert calls == 2


def test_send_retry_disabled_raises_immediately(monkeypatch, sleep_log):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    calls = 0

    def busy(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429)

    client = EndpointClient(ENDPOINT, LIMITS, transport=httpx.MockTransport(busy))
    try:
        with pytest.raises(EndpointError, match="HTTP 429") as exc_info:
            client.send("x", throttle=False, retry=False)
    finally:
        client.close()
    assert calls == 1
    assert "gave up" not in str(exc_info.value)
    assert sleep_log == []
