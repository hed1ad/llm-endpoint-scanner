"""HTTP transport: request rendering, response extraction, throttled client."""

from __future__ import annotations

import copy
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from .config import INPUT_MARKER, EndpointConfig, LimitsConfig, resolve_env_headers


class EndpointError(Exception):
    """The endpoint failed to answer in a usable way; scan continues."""


# Transient statuses worth retrying; other 4xx are definitive answers.
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


def parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header (delay-seconds or HTTP-date) into seconds."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        retry_at = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds())


def render_request(template: Any, payload: str) -> Any:
    """Replace the INPUT_MARKER occurrence in a deep copy of the template."""

    def render(node: Any) -> Any:
        if isinstance(node, str):
            return node.replace(INPUT_MARKER, payload)
        if isinstance(node, dict):
            return {key: render(value) for key, value in node.items()}
        if isinstance(node, list):
            return [render(item) for item in node]
        return node

    return render(copy.deepcopy(template))


def extract_path(data: Any, path: str) -> str:
    """Walk a dotted path with list indices, e.g. 'choices.0.message.content'."""
    node = data
    for segment in path.split("."):
        if isinstance(node, list):
            if not segment.isdigit() or int(segment) >= len(node):
                raise EndpointError(
                    f"response_path '{path}' does not match response structure "
                    f"(missing list index '{segment}')"
                )
            node = node[int(segment)]
        elif isinstance(node, dict):
            if segment not in node:
                raise EndpointError(
                    f"response_path '{path}' does not match response structure "
                    f"(missing key '{segment}')"
                )
            node = node[segment]
        else:
            raise EndpointError(
                f"response_path '{path}' does not match response structure "
                f"(hit scalar at '{segment}')"
            )
    if not isinstance(node, str):
        raise EndpointError(
            f"response_path '{path}' resolved to non-string value "
            f"(type: {type(node).__name__})"
        )
    return node


class EndpointClient:
    def __init__(
        self,
        endpoint: EndpointConfig,
        limits: LimitsConfig,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._limits = limits
        self._client = httpx.Client(timeout=limits.timeout_seconds, transport=transport)
        self._min_interval = 1.0 / limits.max_requests_per_second
        self._last_request_at: float | None = None

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> EndpointClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def send(self, payload: str, *, throttle: bool = True, retry: bool = True) -> str:
        """Send one probe payload.

        Transient failures (timeouts, connection errors, HTTP 429/5xx) are
        retried with exponential backoff, honoring Retry-After, unless
        ``retry=False`` — burst probes use that because a rejection (429) is
        their signal, not a failure.
        """
        body = render_request(self._endpoint.request_template, payload)
        headers = resolve_env_headers(self._endpoint.headers)
        attempts = 1 + self._limits.max_retries if retry else 1
        last_error: EndpointError | None = None

        for attempt in range(attempts):
            if throttle:
                self._throttle()
            try:
                response = self._client.request(
                    self._endpoint.method,
                    self._endpoint.url,
                    json=body,
                    headers=headers,
                )
            except httpx.TimeoutException:
                last_error = EndpointError(
                    f"Request timed out after {self._limits.timeout_seconds}s"
                )
                self._wait_before_retry(attempt, attempts, None)
                continue
            except httpx.TransportError as exc:
                last_error = EndpointError(f"Transport error: {exc}")
                self._wait_before_retry(attempt, attempts, None)
                continue
            except httpx.HTTPError as exc:
                raise EndpointError(f"Transport error: {exc}") from exc

            if response.status_code in RETRYABLE_STATUS:
                last_error = EndpointError(
                    f"Endpoint returned HTTP {response.status_code}"
                )
                self._wait_before_retry(attempt, attempts, response)
                continue
            return self._extract_answer(response)

        assert last_error is not None  # the loop only exhausts via failures
        if attempts > 1:
            raise EndpointError(f"{last_error} (gave up after {attempts} attempts)")
        raise last_error

    def _extract_answer(self, response: httpx.Response) -> str:
        if response.status_code >= 400:
            raise EndpointError(f"Endpoint returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise EndpointError("Endpoint returned non-JSON response") from exc
        return extract_path(data, self._endpoint.response_path)

    def _wait_before_retry(
        self, attempt: int, attempts: int, response: httpx.Response | None
    ) -> None:
        if attempt >= attempts - 1:
            return
        delay: float | None = None
        if response is not None:
            delay = parse_retry_after(response.headers.get("retry-after"))
        if delay is None:
            delay = self._limits.retry_backoff_seconds * (2**attempt)
        delay = min(delay, self._limits.max_retry_delay_seconds)
        if delay > 0:
            time.sleep(delay)

    def _throttle(self) -> None:
        now = time.monotonic()
        if self._last_request_at is not None:
            elapsed = now - self._last_request_at
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
        self._last_request_at = time.monotonic()
