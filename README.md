<div align="center">

<img src="docs/logo.svg" alt="llm-endpoint-scanner logo" width="140">

# llm-endpoint-scanner

**DAST for LLM applications.** Probe any deployed LLM service through its HTTP
endpoint — no access to code, prompts, or configuration required.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![Status](https://img.shields.io/badge/status-early%20development-orange)](Spec.md#11-milestones)

</div>

---

## Why

Your company ships several LLM-powered services — a support chatbot, an
in-product assistant, a doc summarizer — built by different teams, on different
models. You're the AppSec engineer with no code access and no time.

**Which services behave dangerously, and where do you look first?**

This tool answers that in ~10 minutes instead of a week of manual probing.

## What it does

Sends a set of probes to the endpoint and judges the responses:

| Probe | Question it answers |
|---|---|
| 🕵️ Prompt extraction | Will the model reveal its system prompt? |
| 💉 Direct injection | Does "ignore previous instructions" work? |
| 📄 Indirect injection | Can instructions hide inside a submitted document? |
| 🎭 Role escape | Will the support bot write poems and solve math for free? |
| 🚰 Data leakage | Do responses contain other users' data or internals? |
| 🚦 Missing limits | Rate limiting? Input length caps? |

Results come out as **JSON** (for automation) and **Markdown** (for humans),
with verbatim request/response evidence for every finding.

## Quickstart

```bash
pip install -e .

# try it safely against the built-in mock server
python examples/mock_server.py
llm-scan run examples/config.example.yaml
```

Point it at a real endpoint with a small YAML config — no adapter code needed:

```yaml
endpoint:
  url: https://internal.example.com/api/chat
  method: POST
  headers:
    Authorization: "Bearer ${LLM_SCAN_TOKEN}"
  request_template:
    messages:
      - role: user
        content: "{{INPUT}}"
  response_path: "choices.0.message.content"
```

## How it differs from garak / PyRIT / promptfoo

Those tools test the **model** — you give them access to the model or provider.
This scanner tests the **application**: the endpoint, behind which there may be
RAG, agents, filters, and glue code. That is usually where the vulnerability
lives. Full rationale: [Spec.md §9](Spec.md#9-comparison-with-existing-tools).

## Limitations

Detecting whether an attack succeeded is harder than carrying it out. Beyond
canary-marker checks, detection relies on heuristics and can produce both
false positives and false negatives. **A clean report is not proof of safety** —
this tool answers "where to look first," not "is it secure."
See [Spec.md §10](Spec.md#10-limitations).

## Documentation

- [Spec.md](Spec.md) — full specification, requirements, milestone plan
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [examples/](examples) — sample config and local mock server

## License

[MIT](LICENSE)
