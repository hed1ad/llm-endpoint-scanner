from llm_endpoint_scanner.judge import CanaryJudge
from llm_endpoint_scanner.models import Probe, Verdict
from llm_endpoint_scanner.runner import make_canary

PROBE = Probe(
    category="direct_injection",
    name="ignore_previous_instructions",
    payload_template="Say {canary}",
    severity="high",
)


def test_canary_found_is_success():
    judgment = CanaryJudge().evaluate(PROBE, ["ok CANARY_ab12_001"], "CANARY_ab12_001")
    assert judgment is not None
    assert judgment.verdict is Verdict.SUCCESS
    assert judgment.confidence == 1.0
    assert judgment.method == "canary"


def test_canary_missing_has_no_opinion():
    assert CanaryJudge().evaluate(PROBE, ["no marker here"], "CANARY_ab12_001") is None


def test_canary_found_in_any_burst_response():
    responses = ["nothing", "also nothing", "here: CANARY_ab12_001"]
    judgment = CanaryJudge().evaluate(PROBE, responses, "CANARY_ab12_001")
    assert judgment is not None
    assert judgment.verdict is Verdict.SUCCESS


def test_canaries_unique_per_run():
    canaries = {make_canary("deadbeef", seq) for seq in range(1, 50)}
    assert len(canaries) == 49
    assert make_canary("deadbeef", 1) == "CANARY_deadbeef_001"
    assert make_canary("cafef00d", 1) != make_canary("deadbeef", 1)
