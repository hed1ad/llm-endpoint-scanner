"""HTTP transport: request rendering, response extraction, throttled client."""

from __future__ import annotations

import copy
import time
from typing import Any

import httpx

from .config import INPUT_MARKER, EndpointConfig, LimitsConfig, resolve_env_headers


class EndpointError(Exception):
    """The endpoint failed to answer in a usable way; scan continues."""


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

    def send(self, payload: str, *, throttle: bool = True) -> str:
        if throttle:
            self._throttle()
        body = render_request(self._endpoint.request_template, payload)
        headers = resolve_env_headers(self._endpoint.headers)
        try:
            response = self._client.request(
                self._endpoint.method,
                self._endpoint.url,
                json=body,
                headers=headers,
            )
        except httpx.TimeoutException as exc:
            raise EndpointError(
                f"Request timed out after {self._limits.timeout_seconds}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise EndpointError(f"Transport error: {exc}") from exc

        if response.status_code >= 400:
            raise EndpointError(f"Endpoint returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise EndpointError("Endpoint returned non-JSON response") from exc
        return extract_path(data, self._endpoint.response_path)

    def _throttle(self) -> None:
        now = time.monotonic()
        if self._last_request_at is not None:
            elapsed = now - self._last_request_at
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
        self._last_request_at = time.monotonic()
