"""Endpoint configuration: parsing, validation, hashing (REQ-C1..C4)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import string
from pathlib import Path
from typing import Any

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

INPUT_MARKER = "{{INPUT}}"
CANARY_PLACEHOLDER = "canary"
SEVERITIES = ("low", "medium", "high", "critical")
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

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
    max_retries: int = Field(default=3, ge=0)
    retry_backoff_seconds: float = Field(default=1.0, ge=0)
    max_retry_delay_seconds: float = Field(default=30.0, ge=0)


class ReportConfig(BaseModel):
    json_path: str = "report.json"
    markdown_path: str = "report.md"


class CustomProbeConfig(BaseModel):
    """FR-9: a user-defined probe; runs exactly like a built-in one."""

    model_config = ConfigDict(extra="forbid")

    name: str
    category: str
    payload_template: str
    severity: str
    repetitions: int = Field(default=1, ge=1)

    @field_validator("name", "category")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("severity")
    @classmethod
    def _known_severity(cls, value: str) -> str:
        if value not in SEVERITIES:
            raise ValueError(f"must be one of: {', '.join(SEVERITIES)}")
        return value

    @field_validator("payload_template")
    @classmethod
    def _only_canary_placeholder(cls, value: str) -> str:
        try:
            fields = {
                field_name
                for _, field_name, _, _ in string.Formatter().parse(value)
                if field_name is not None
            }
        except ValueError as exc:
            raise ValueError(f"invalid format string: {exc}") from exc
        if CANARY_PLACEHOLDER not in fields:
            raise ValueError("must contain the {canary} placeholder")
        unknown = fields - {CANARY_PLACEHOLDER}
        if unknown:
            raise ValueError(
                f"unknown placeholder(s): {', '.join(sorted(unknown))}; "
                "only {canary} is supported"
            )
        return value


class ScanConfig(BaseModel):
    endpoint: EndpointConfig
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    custom_probes: list[CustomProbeConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_custom_probe_names(self) -> ScanConfig:
        names = [probe.name for probe in self.custom_probes]
        dupes = sorted({name for name in names if names.count(name) > 1})
        if dupes:
            raise ValueError(f"duplicate custom probe name(s): {', '.join(dupes)}")
        return self


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
