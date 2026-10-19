"""Probe category registry. Adding a category means appending to ALL_CATEGORIES."""

from __future__ import annotations

from .base import ProbeCategory
from .direct_injection import DirectInjection
from .prompt_extraction import PromptExtraction

ALL_CATEGORIES: list[ProbeCategory] = [
    PromptExtraction(),
    DirectInjection(),
]

__all__ = ["ALL_CATEGORIES", "ProbeCategory", "DirectInjection", "PromptExtraction"]
