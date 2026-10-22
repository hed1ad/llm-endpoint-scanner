"""FR-8: scan selection (--include/--exclude) and request budget."""

import json

import httpx
import pytest
from typer.testing import CliRunner

from llm_endpoint_scanner.cli import app
from llm_endpoint_scanner.config import ScanConfig
from llm_endpoint_scanner.http_client import EndpointClient
from llm_endpoint_scanner.judge import BASELINE_PROMPT
from llm_endpoint_scanner.runner import run_scan, write_json_report
from llm_endpoint_scanner.selection import SelectionError, plan_scan

runner = CliRunner()

CFG = ScanConfig.model_validate(
    {
        "endpoint": {
            "url": "https://example.com/api/chat",
            "request_template": {
                "messages": [{"role": "user", "content": "{{INPUT}}"}]
            },
            "response_path": "choices.0.message.content",
        },
        "limits": {"max_requests_per_second": 1000},
    }
)

VALID_YAML = """\
endpoint:
  url: https://example.com/api/chat
  method: POST
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


def _counting_client(counter: dict) -> EndpointClient:
    def transport(request: httpx.Request) -> httpx.Response:
        counter["sent"] += 1
        text = json.loads(request.content)["messages"][0]["content"]
        return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})

    return EndpointClient(
        CFG.endpoint, CFG.limits, transport=httpx.MockTransport(transport)
    )


def test_include_category_runs_only_that_category():
    counter = {"sent": 0}
    with _counting_client(counter) as client:
        report = run_scan(CFG, client=client, include=["role_escape"])

    assert {r.category for r in report.probes} == {"role_escape"}
    assert not any(r.skipped for r in report.probes)
    assert len(report.probes) == 3
    # 1 baseline + 3 single-request probes.
    assert counter["sent"] == 4
    assert report.summary == {"role_escape": "success"}
    assert report.overall_verdict == "success"


def test_include_probe_name_and_comma_separated():
    counter = {"sent": 0}
    with _counting_client(counter) as client:
        report = run_scan(
            CFG, client=client, include=["off_role_poem", "off_role_math"]
        )

    assert {r.name for r in report.probes} == {"off_role_poem", "off_role_math"}
    assert counter["sent"] == 3  # baseline + 2 probes


def test_exclude_category_and_probe():
    counter = {"sent": 0}
    with _counting_client(counter) as client:
        report = run_scan(
            CFG,
            client=client,
            exclude=["missing_limits", "repeat_instructions"],
        )

    names = {r.name for r in report.probes}
    assert "burst_acceptance" not in names
    assert "long_input" not in names
    assert "repeat_instructions" not in names
    # 1 baseline + 26 probe requests - 12 excluded (burst 10 + 2 single probes).
    assert counter["sent"] == 1 + 26 - 12


def test_unknown_names_fail_fast():
    with pytest.raises(SelectionError, match="Unknown --include"):
        plan_scan(include=["no_such_probe"])
    with pytest.raises(SelectionError, match="Unknown --exclude"):
        plan_scan(exclude=["no_such_category"])
    with pytest.raises(SelectionError, match="cannot be used together"):
        plan_scan(include=["role_escape"], exclude=["missing_limits"])
    with pytest.raises(SelectionError, match="max_requests"):
        plan_scan(max_requests=0)


def test_budget_never_exceeded_and_skips_with_reason():
    counter = {"sent": 0}
    with _counting_client(counter) as client:
        report = run_scan(CFG, client=client, include=["role_escape"], max_requests=3)

    assert counter["sent"] == 3  # baseline + 2 probes; budget is a hard cap
    ran = [r for r in report.probes if not r.skipped]
    skipped = [r for r in report.probes if r.skipped]
    assert len(ran) == 2
    assert len(skipped) == 1
    assert skipped[0].requests_sent == 0
    assert "budget" in skipped[0].judgment.reason
    # Skipped probes are excluded from summary and overall verdict but the
    # category still reflects the probes that actually ran.
    assert report.summary == {"role_escape": "success"}
    assert report.overall_verdict == "success"


def test_budget_smaller_than_burst_skips_burst_but_runs_cheaper_probe():
    counter = {"sent": 0}
    with _counting_client(counter) as client:
        report = run_scan(
            CFG, client=client, include=["missing_limits"], max_requests=2
        )

    assert counter["sent"] == 2  # baseline + long_input; burst does not fit
    burst = next(r for r in report.probes if r.name == "burst_acceptance")
    long_input = next(r for r in report.probes if r.name == "long_input")
    assert burst.skipped
    assert not long_input.skipped


def test_baseline_only_budget_skips_everything():
    counter = {"sent": 0}
    with _counting_client(counter) as client:
        report = run_scan(CFG, client=client, max_requests=1)

    assert counter["sent"] == 1  # only the baseline request
    assert report.probes and all(r.skipped for r in report.probes)
    # Skipped probes do not participate in summary or the overall verdict.
    assert report.summary == {}
    assert report.overall_verdict == "inconclusive"
    assert report.triage() == []


def test_budget_skip_serialized(tmp_path):
    counter = {"sent": 0}
    with _counting_client(counter) as client:
        report = run_scan(CFG, client=client, include=["role_escape"], max_requests=3)

    out = tmp_path / "report.json"
    write_json_report(report, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    skipped = [p for p in data["probes"] if p["skipped"]]
    assert len(skipped) == 1
    assert "budget" in skipped[0]["judgment"]["reason"]


def test_baseline_still_first_with_selection():
    seen: list[str] = []

    def transport(request: httpx.Request) -> httpx.Response:
        text = json.loads(request.content)["messages"][0]["content"]
        seen.append(text)
        return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})

    client = EndpointClient(
        CFG.endpoint, CFG.limits, transport=httpx.MockTransport(transport)
    )
    with client:
        run_scan(CFG, client=client, include=["off_role_poem"])

    assert seen[0] == BASELINE_PROMPT
    assert len(seen) == 2


def test_cli_unknown_name_exits_2(tmp_path):
    result = runner.invoke(app, ["scan", _write_config(tmp_path), "--include", "nope"])
    assert result.exit_code == 2
    assert "Selection error" in result.output
    assert "nope" in result.output


def test_cli_include_and_exclude_together_exits_2(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            _write_config(tmp_path),
            "--include",
            "role_escape",
            "--exclude",
            "missing_limits",
        ],
    )
    assert result.exit_code == 2
    assert "cannot be used together" in result.output


def test_cli_dry_run_reflects_selection_and_budget(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            _write_config(tmp_path),
            "--dry-run",
            "--include",
            "role_escape,off_role_poem",
            "--max-requests",
            "3",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "off_role_poem" in result.output
    assert "off_role_math" in result.output
    assert "direct_injection" not in result.output
    assert "Skipped:" in result.output
    assert "Total planned requests: 3" in result.output


def test_cli_dry_run_unknown_name_exits_2(tmp_path):
    result = runner.invoke(
        app, ["scan", _write_config(tmp_path), "--dry-run", "--exclude", "nope"]
    )
    assert result.exit_code == 2
    assert "Selection error" in result.output
