"""Probe category registry. Adding a category means appending to ALL_CATEGORIES."""

from __future__ import annotations

from .base import ProbeCategory
from .data_leakage import DataLeakage
from .direct_injection import DirectInjection
from .indirect_injection import IndirectInjection
from .missing_limits import MissingLimits
from .prompt_extraction import PromptExtraction
from .role_escape import RoleEscape

ALL_CATEGORIES: list[ProbeCategory] = [
    PromptExtraction(),
    DirectInjection(),
    IndirectInjection(),
    RoleEscape(),
    DataLeakage(),
    MissingLimits(),
]

__all__ = [
    "ALL_CATEGORIES",
    "ProbeCategory",
    "PromptExtraction",
    "DirectInjection",
    "IndirectInjection",
    "RoleEscape",
    "DataLeakage",
    "MissingLimits",
]
