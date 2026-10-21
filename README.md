<div align="center">

<img src="docs/logo.png" alt="llm-endpoint-scanner logo" width="140">

# llm-endpoint-scanner

**DAST for LLM applications.** Probe any deployed LLM service through its HTTP
endpoint — no access to code, prompts, or configuration required.

</div>

---

## Why

Your company ships several LLM-powered services — a support chatbot, an
in-product assistant, a doc summarizer — built by different teams, on different
models. You're the AppSec engineer with no code access and no time.

**Which services behave dangerously, and where do you look first?**

This tool answers that in ~10 minutes instead of a week of manual probing.

## Status

**M1 is complete.** The scanner runs end-to-end: YAML config → HTTP probes →
canary-based detection → JSON report with verbatim evidence.

What works today:

- Declarative endpoint config (YAML): arbitrary JSON request bodies with a
  `{{INPUT}}` injection point, dotted-path response extraction, secrets via
  env vars, fail-fast validation.
- Two attack categories with canary-marker detection:
  - **Prompt extraction** — will the model reveal its system prompt?
  - **Direct injection** — does "ignore previous instructions" work?
- JSON report per probe: payload sent, response received, verdict
  (`success` / `failed` / `inconclusive`), confidence, detection method.
  Secrets never appear in reports.
- Local mock server (`examples/`) for offline development and testing.

Planned next (see [Spec.md §11](Spec.md#11-milestones)):

| Milestone | Scope |
|---|---|
| **M2** | Remaining probe categories: indirect injection, role escape, data leakage, missing limits |
| **M3** | Baseline & heuristic detection, Markdown report |
| **M4** | Hardening: `--dry-run`, richer mock server, docs, CI |

## Quick start

```bash
pip install -e ".[dev]"

# scan the bundled vulnerable mock endpoint
python examples/mock_server.py &
llm-scan scan examples/config.mock.yaml
```

To scan a real service, write a config describing its endpoint:

```yaml
endpoint:
  url: https://internal.example.com/api/chat
  method: POST
  headers:
    Authorization: "Bearer ${LLM_SCAN_TOKEN}"   # secrets come from env vars
    Content-Type: application/json
  request_template:
    model: "support-bot-v2"
    messages:
      - role: user
        content: "{{INPUT}}"
  response_path: "choices.0.message.content"

limits:
  timeout_seconds: 30
  max_requests_per_second: 2

report:
  json_path: report.json
```

```bash
export LLM_SCAN_TOKEN=...
llm-scan scan my-service.yaml
```

## What it does

Sends a set of probes to the endpoint and judges the responses:

| Probe | Question it answers | Status |
|---|---|---|
| Prompt extraction | Will the model reveal its system prompt? | ✅ M1 |
| Direct injection | Does "ignore previous instructions" work? | ✅ M1 |
| Indirect injection | Can instructions hide inside a submitted document? | planned (M2) |
| Role escape | Will the support bot write poems and solve math for free? | planned (M2) |
| Data leakage | Do responses contain other users' data or internals? | planned (M2) |
| Missing limits | Rate limiting? Input length caps? | planned (M2) |

Detection is layered (Spec.md §6): today it is **canary markers** — a unique
per-run token embedded in the probe; if it comes back, the injected
instruction was executed. Baseline comparison and heuristics arrive in M3.

Results come out as **JSON** (for automation), with verbatim request/response
evidence for every finding. A **Markdown** report for humans is planned in M3.

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

## Development

```bash
pip install -e ".[dev]"
pre-commit install        # ruff check --fix and ruff format on every commit

python -m pytest -q       # run the test suite
ruff check .              # lint
ruff format --check .     # formatting
```

CI runs on every push to `main` and every pull request:

- **Tests** — pytest on Python 3.10–3.13
- **Semgrep** — secrets detection (`p/secrets` ruleset)
- **TruffleHog** — verified secret scanning over full git history

## Documentation

- [Spec.md](Spec.md) — full specification, requirements, milestone plan
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute

## License

[MIT](LICENSE)
