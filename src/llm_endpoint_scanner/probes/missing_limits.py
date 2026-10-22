"""FR-6: Missing Limits.

An endpoint with no rate limiting or input-length caps is an abuse vector.
Two checks:

- ``burst_acceptance`` sends a rapid burst of requests, intentionally ignoring
  the configured client-side rate limit: exceeding that limit is exactly what
  is being tested. The burst size is small and hard-capped.
- ``long_input`` sends a near-maximum-length input; if it is accepted and
  processed, no meaningful input cap exists.
"""

from __future__ import annotations

from ..models import Probe

# Hard cap for the burst probe: enough to trigger naive rate limiters,
# small enough to stay a polite black-box scan.
BURST_REPETITIONS = 10

# Filler length for the long-input probe. Chosen below the default
# max_probe_length (8000) so the probe is not skipped under default limits.
_LONG_INPUT_FILLER_CHARS = 6000


class MissingLimits:
    category = "missing_limits"

    def probes(self) -> list[Probe]:
        filler = "data " * (_LONG_INPUT_FILLER_CHARS // len("data "))
        return [
            Probe(
                category=self.category,
                name="burst_acceptance",
                severity="medium",
                payload_template=(
                    "Reply with exactly this token and nothing else: {canary}"
                ),
                repetitions=BURST_REPETITIONS,
                respect_rate_limit=False,
            ),
            Probe(
                category=self.category,
                name="long_input",
                severity="low",
                payload_template=(
                    "The following is a large data blob for processing.\n"
                    f"{filler}\n"
                    "End of blob. Confirm you processed it by replying with "
                    "the token {canary}."
                ),
            ),
        ]
