"""Endpoint configuration: parsing, validation, hashing (REQ-C1..C4)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

INPUT_MARKER = "{{INPUT}}"
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    """Invalid configuration; raised before any request is sent."""


class EndpointConfig(BaseModel):
    url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    request_template: dict[str, Any]
    response_path: str


class LimitsConfig(BaseModel):
    timeout_seconds: float = 30
    max_requests_per_second: float = 2
    max_probe_length: int = 8000


class ReportConfig(BaseModel):
    json_path: str = "report.json"
    markdown_path: str = "report.md"


class ScanConfig(BaseModel):
    endpoint: EndpointConfig
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)


def _count_markers(node: Any) -> int:
    if isinstance(node, str):
        return node.count(INPUT_MARKER)
    if isinstance(node, dict):
        return sum(_count_markers(k) + _count_markers(v) for k, v in node.items())
    if isinstance(node, list):
        return sum(_count_markers(item) for item in node)
    return 0


def resolve_env_headers(headers: dict[str, str]) -> dict[str, str]:
    """Substitute ${VAR} references; error names the variable, never its value."""

    def substitute(value: str) -> str:
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in os.environ:
                raise ConfigError(
                    f"Header references environment variable ${{{name}}} "
                    "which is not set"
                )
            return os.environ[name]

        return _ENV_VAR_RE.sub(repl, value)

    return {key: substitute(value) for key, value in headers.items()}


def load_config(path: str | Path) -> ScanConfig:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"Config in {path} must be a YAML mapping")

    try:
        cfg = ScanConfig.model_validate(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}"
            for err in exc.errors()
        )
        raise ConfigError(f"Invalid config in {path}: {details}") from exc

    if not cfg.endpoint.response_path.strip():
        raise ConfigError("endpoint.response_path must not be empty")

    markers = _count_markers(cfg.endpoint.request_template)
    if markers != 1:
        raise ConfigError(
            f"endpoint.request_template must contain exactly one {INPUT_MARKER} "
            f"marker, found {markers}"
        )

    resolve_env_headers(cfg.endpoint.headers)
    return cfg


def config_hash(cfg: ScanConfig) -> str:
    canonical = json.dumps(cfg.model_dump(), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
