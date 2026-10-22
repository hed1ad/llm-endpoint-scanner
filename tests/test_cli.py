"""CLI behavior: dry-run, exit codes, report files."""

import json

import httpx
from typer.testing import CliRunner

import llm_endpoint_scanner.runner as runner_module
from llm_endpoint_scanner.cli import app
from llm_endpoint_scanner.config import ScanConfig

runner = CliRunner()

VALID_YAML = """\
endpoint:
  url: https://example.com/api/chat
  method: POST
  headers:
    Authorization: "Bearer ${LLM_SCAN_TOKEN}"
    Content-Type: application/json
  request_template:
    messages:
      - role: user
        content: "{{INPUT}}"
  response_path: "choices.0.message.content"
limits:
  timeout_seconds: 5
  max_requests_per_second: 1000
report:
  json_path: __JSON_PATH__
  markdown_path: __MD_PATH__
"""


def _write_config(tmp_path) -> str:
    path = tmp_path / "config.yaml"
    path.write_text(
        VALID_YAML.replace("__JSON_PATH__", str(tmp_path / "report.json")).replace(
            "__MD_PATH__", str(tmp_path / "report.md")
        ),
        encoding="utf-8",
    )
    return str(path)


def _echo_client(cfg: ScanConfig) -> "runner_module.EndpointClient":
    def transport(request: httpx.Request) -> httpx.Response:
        text = json.loads(request.content)["messages"][0]["content"]
        return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})

    return runner_module.EndpointClient(
        cfg.endpoint, cfg.limits, transport=httpx.MockTransport(transport)
    )


def test_dry_run_sends_no_requests(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("dry-run must not construct a client")

    monkeypatch.setattr(runner_module, "EndpointClient", fail_if_called)
    result = runner.invoke(app, ["scan", _write_config(tmp_path), "--dry-run"])
    assert result.exit_code == 0
    assert "no requests will be sent" in result.output
    # All six spec categories appear in the plan.
    for category in (
        "prompt_extraction",
        "direct_injection",
        "indirect_injection",
        "role_escape",
        "data_leakage",
        "missing_limits",
    ):
        assert category in result.output


def test_scan_writes_both_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")

    real_run_scan = runner_module.run_scan

    def patched(cfg, client=None, judge=None, **kwargs):
        return real_run_scan(cfg, client=client or _echo_client(cfg), **kwargs)

    monkeypatch.setattr("llm_endpoint_scanner.cli.run_scan", patched)
    result = runner.invoke(app, ["scan", _write_config(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "report.json").is_file()
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert md.startswith("# LLM Endpoint Security Scan")


def test_scan_fail_on_success_exits_1(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")

    real_run_scan = runner_module.run_scan

    def patched(cfg, client=None, judge=None, **kwargs):
        return real_run_scan(cfg, client=client or _echo_client(cfg), **kwargs)

    monkeypatch.setattr("llm_endpoint_scanner.cli.run_scan", patched)
    result = runner.invoke(
        app, ["scan", _write_config(tmp_path), "--fail-on", "success"]
    )
    assert result.exit_code == 1


def test_scan_invalid_config_exits_2(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_SCAN_TOKEN", raising=False)
    result = runner.invoke(app, ["scan", str(tmp_path / "missing.yaml")])
    assert result.exit_code == 2
    assert "Config error" in result.output


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "llm-endpoint-scanner" in result.output
