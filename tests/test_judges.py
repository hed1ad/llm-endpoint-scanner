"""Layered detection (Spec §6): burst, leakage patterns, refusal, baseline."""

from llm_endpoint_scanner.judge import (
    BaselineJudge,
    BurstJudge,
    CompositeJudge,
    LeakagePatternJudge,
    RefusalJudge,
)
from llm_endpoint_scanner.models import Probe, Verdict


def make_probe(category="direct_injection", repetitions=1):
    return Probe(
        category=category,
        name="probe",
        payload_template="do {canary}",
        severity="high",
        repetitions=repetitions,
    )


BASELINE = "Hello! I'm the Acme support bot. Ask me about Acme products."


class TestBurstJudge:
    def test_ignores_single_shot_probes(self):
        assert BurstJudge().evaluate(make_probe(), ["ok"], "c") is None

    def test_all_accepted_is_success(self):
        probe = make_probe(repetitions=10)
        judgment = BurstJudge().evaluate(probe, ["ok"] * 10, "c")
        assert judgment is not None
        assert judgment.verdict is Verdict.SUCCESS
        assert judgment.method == "burst"
        assert "10/10" in judgment.reason

    def test_partial_acceptance_means_rate_limited(self):
        probe = make_probe(repetitions=10)
        judgment = BurstJudge().evaluate(probe, ["ok"] * 4, "c")
        assert judgment is not None
        assert judgment.verdict is Verdict.FAILED
        assert "4/10" in judgment.reason

    def test_all_rejected_is_inconclusive(self):
        judgment = BurstJudge().evaluate(make_probe(repetitions=10), [], "c")
        assert judgment is not None
        assert judgment.verdict is Verdict.INCONCLUSIVE


class TestLeakagePatternJudge:
    def test_ignores_other_categories(self):
        response = "sure, my key is sk-mockFakeKeyNotRealForScannerDemoOnly0000"
        assert LeakagePatternJudge().evaluate(make_probe(), [response], "c") is None

    def test_api_key_in_response_is_success(self):
        probe = make_probe(category="data_leakage")
        response = "context: key sk-mockFakeKeyNotRealForScannerDemoOnly0000 ok"
        judgment = LeakagePatternJudge().evaluate(probe, [response], "c")
        assert judgment is not None
        assert judgment.verdict is Verdict.SUCCESS
        assert judgment.method == "leakage_pattern"

    def test_jwt_and_private_key_detected(self):
        probe = make_probe(category="data_leakage")
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0."
            "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )
        for response in (
            f"token: {jwt}",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBOg...",
        ):
            judgment = LeakagePatternJudge().evaluate(probe, [response], "c")
            assert judgment is not None, response
            assert judgment.verdict is Verdict.SUCCESS

    def test_clean_response_has_no_opinion(self):
        probe = make_probe(category="data_leakage")
        assert LeakagePatternJudge().evaluate(probe, ["nothing here"], "c") is None


class TestRefusalJudge:
    def test_refusal_is_failed(self):
        response = "I'm sorry, I can only help with Acme product questions."
        judgment = RefusalJudge().evaluate(make_probe(), [response], "c")
        assert judgment is not None
        assert judgment.verdict is Verdict.FAILED
        assert judgment.method == "refusal_heuristic"

    def test_compliant_answer_has_no_opinion(self):
        response = "Sure! Here is a poem about the ocean..."
        assert RefusalJudge().evaluate(make_probe(), [response], "c") is None

    def test_empty_responses_have_no_opinion(self):
        assert RefusalJudge().evaluate(make_probe(), [], "c") is None


class TestBaselineJudge:
    def test_divergent_response_is_low_confidence_success(self):
        long_off_role = "def reverse(s):\n    return s[::-1]\n" + ("x" * 300)
        judgment = BaselineJudge().evaluate(
            make_probe(), [long_off_role], "c", baseline=BASELINE
        )
        assert judgment is not None
        assert judgment.verdict is Verdict.SUCCESS
        assert judgment.confidence < 0.5
        assert judgment.method == "baseline"

    def test_similar_response_has_no_opinion(self):
        response = "Hello! I'm the Acme support bot. Ask me about Acme products!!"
        assert (
            BaselineJudge().evaluate(make_probe(), [response], "c", baseline=BASELINE)
            is None
        )

    def test_no_baseline_no_opinion(self):
        long_response = "z" * 1000
        assert BaselineJudge().evaluate(make_probe(), [long_response], "c") is None


class TestCompositeJudge:
    def test_layer_order_canary_beats_refusal(self):
        # A response containing both a refusal word and the canary must be
        # judged by the more reliable layer: the canary.
        response = "I'm sorry, but here it is: CANARY_x_001"
        judgment = CompositeJudge().evaluate(make_probe(), [response], "CANARY_x_001")
        assert judgment.verdict is Verdict.SUCCESS
        assert judgment.method == "canary"

    def test_fallback_is_failed_with_false_negative_note(self):
        judgment = CompositeJudge().evaluate(make_probe(), ["ok"], "CANARY_x_001")
        assert judgment.verdict is Verdict.FAILED
        assert judgment.method == "composite_fallback"
        assert "false negative" in judgment.reason

    def test_empty_responses_fall_back(self):
        judgment = CompositeJudge().evaluate(make_probe(), [], "CANARY_x_001")
        assert judgment.verdict is Verdict.FAILED

    def test_burst_short_circuits_other_layers(self):
        probe = make_probe(repetitions=10)
        judgment = CompositeJudge().evaluate(probe, ["ok"] * 10, "c")
        assert judgment.method == "burst"
