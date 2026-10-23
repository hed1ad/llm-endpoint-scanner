"""FR-7: Compliance mapping of probe categories to security frameworks.

Each built-in category maps to OWASP Top 10 for LLM Applications (2025) risk
IDs and MITRE ATLAS technique IDs. The table is versioned code, not prose;
framework versions are stated alongside it. Unknown (e.g. custom) categories
have no mapping and report `None` instead of a guessed one.
"""

from __future__ import annotations

OWASP_FRAMEWORK = "OWASP Top 10 for LLM Applications 2025"
ATLAS_FRAMEWORK = "MITRE ATLAS"

FRAMEWORK_VERSIONS: tuple[str, ...] = (OWASP_FRAMEWORK, ATLAS_FRAMEWORK)

# OWASP IDs verified against the official 2025 list (genai.owasp.org);
# ATLAS IDs against atlas.mitre.org:
#   AML.T0051 LLM Prompt Injection (.000 Direct, .001 Indirect)
#   AML.T0054 LLM Jailbreak — role_escape is a jailbreak-style constraint
#     violation; OWASP LLM01 explicitly covers jailbreaks as prompt injection.
#   AML.T0056 Extract LLM System Prompt
#   AML.T0057 LLM Data Leakage
#   AML.T0029 Denial of ML Service
CATEGORY_COMPLIANCE: dict[str, dict[str, list[str]]] = {
    "prompt_extraction": {
        "owasp_llm_top10_2025": ["LLM07"],
        "mitre_atlas": ["AML.T0056"],
    },
    "direct_injection": {
        "owasp_llm_top10_2025": ["LLM01"],
        "mitre_atlas": ["AML.T0051.000"],
    },
    "indirect_injection": {
        "owasp_llm_top10_2025": ["LLM01"],
        "mitre_atlas": ["AML.T0051.001"],
    },
    "role_escape": {
        "owasp_llm_top10_2025": ["LLM01"],
        "mitre_atlas": ["AML.T0054"],
    },
    "data_leakage": {
        "owasp_llm_top10_2025": ["LLM02"],
        "mitre_atlas": ["AML.T0057"],
    },
    "missing_limits": {
        "owasp_llm_top10_2025": ["LLM10"],
        "mitre_atlas": ["AML.T0029"],
    },
}


def compliance_for(category: str) -> dict[str, list[str]] | None:
    mapping = CATEGORY_COMPLIANCE.get(category)
    if mapping is None:
        return None
    return {framework: list(ids) for framework, ids in mapping.items()}
