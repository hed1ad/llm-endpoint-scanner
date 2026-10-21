import pytest

from llm_endpoint_scanner.config import ConfigError, config_hash, load_config

VALID_YAML = """\
endpoint:
  url: https://example.com/api/chat
  method: POST
  headers:
    Authorization: "Bearer ${LLM_SCAN_TOKEN}"
    Content-Type: application/json
  request_template:
    model: "bot-v2"
    messages:
      - role: user
        content: "{{INPUT}}"
  response_path: "choices.0.message.content"
limits:
  timeout_seconds: 10
  max_requests_per_second: 100
"""


@pytest.fixture
def config_path(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "secret-token-value")
    path = tmp_path / "config.yaml"
    path.write_text(VALID_YAML, encoding="utf-8")
    return path


def test_load_valid_config(config_path):
    cfg = load_config(config_path)
    assert cfg.endpoint.url == "https://example.com/api/chat"
    assert cfg.limits.timeout_seconds == 10
    assert cfg.endpoint.response_path == "choices.0.message.content"


def test_invalid_yaml(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("endpoint: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError, match="Invalid YAML"):
        load_config(path)


def test_missing_input_marker(tmp_path):
    path = tmp_path / "no_marker.yaml"
    path.write_text(VALID_YAML.replace("{{INPUT}}", "static text"), encoding="utf-8")
    with pytest.raises(ConfigError, match="exactly one"):
        load_config(path)


def test_two_input_markers(tmp_path):
    path = tmp_path / "two_markers.yaml"
    path.write_text(
        VALID_YAML.replace('content: "{{INPUT}}"', 'content: "{{INPUT}} {{INPUT}}"'),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="exactly one"):
        load_config(path)


def test_missing_env_var_names_variable_not_value(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_SCAN_TOKEN", raising=False)
    path = tmp_path / "config.yaml"
    path.write_text(VALID_YAML, encoding="utf-8")
    with pytest.raises(ConfigError, match="LLM_SCAN_TOKEN") as exc_info:
        load_config(path)
    assert "secret" not in str(exc_info.value).lower()


def test_empty_response_path(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_SCAN_TOKEN", "x")
    path = tmp_path / "empty_path.yaml"
    path.write_text(
        VALID_YAML.replace(
            'response_path: "choices.0.message.content"', 'response_path: ""'
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="response_path"):
        load_config(path)


def test_config_hash_stable(config_path):
    cfg = load_config(config_path)
    assert config_hash(cfg) == config_hash(cfg)
    assert len(config_hash(cfg)) == 64
