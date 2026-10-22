"""Probe pack integrity: all six spec categories, well-formed templates."""

import re

from llm_endpoint_scanner.probes import ALL_CATEGORIES
from llm_endpoint_scanner.probes.missing_limits import (
    _LONG_INPUT_FILLER_CHARS,
    BURST_REPETITIONS,
)

EXPECTED_CATEGORIES = {
    "prompt_extraction",
    "direct_injection",
    "indirect_injection",
    "role_escape",
    "data_leakage",
    "missing_limits",
}

VALID_SEVERITIES = {"critical", "high", "medium", "low"}

CANARY_PLACEHOLDER_RE = re.compile(r"\{canary\}")


def _all_probes():
    return [probe for category in ALL_CATEGORIES for probe in category.probes()]


def test_all_spec_categories_registered():
    assert {c.category for c in ALL_CATEGORIES} == EXPECTED_CATEGORIES


def test_probe_names_unique_within_category():
    for category in ALL_CATEGORIES:
        names = [p.name for p in category.probes()]
        assert len(names) == len(set(names)), category.category


def test_every_probe_has_exactly_one_canary_placeholder():
    for probe in _all_probes():
        found = CANARY_PLACEHOLDER_RE.findall(probe.payload_template)
        assert len(found) == 1, f"{probe.category}/{probe.name}: {len(found)}"


def test_probe_metadata_valid():
    for probe in _all_probes():
        assert probe.severity in VALID_SEVERITIES
        assert probe.category in EXPECTED_CATEGORIES
        assert probe.repetitions >= 1
        probe.payload_template.format(canary="CANARY_t_001")  # must not raise


def test_only_burst_probe_ignores_rate_limit():
    for probe in _all_probes():
        if probe.repetitions > 1:
            assert not probe.respect_rate_limit
            assert probe.category == "missing_limits"
        else:
            assert probe.respect_rate_limit


def test_burst_size_is_capped_and_long_input_fits_default_limit():
    assert BURST_REPETITIONS <= 20
    assert _LONG_INPUT_FILLER_CHARS < 8000  # default max_probe_length
