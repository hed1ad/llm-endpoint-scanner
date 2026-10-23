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

This tool answers that in ~10 minutes instead of a week of manual probing. It
does not replace deep analysis — it tells you where to look first.

> Scan only systems you are authorized to test.

## What it does

The scanner sends a fixed set of well-known attack probes to the endpoint and
judges each response. All six categories from the spec are implemented:

| Probe | Question it answers |
|---|---|
| **Prompt extraction** | Will the model reveal its system prompt? |
| **Direct injection** | Does "ignore previous instructions" work? |
| **Indirect injection** | Can instructions hide inside a submitted document? |
| **Role escape** | Will the support bot write poems and solve math for free? |
| **Data leakage** | Do responses contain other users' data, secrets, or internals? |
| **Missing limits** | Is there rate limiting? An input length cap? |

### Detection is layered (Spec §6)

Deciding *from the response* whether an attack worked is the core problem.
The scanner applies its detection layers in reliability order, and every
verdict in the report records which layer produced it and with what
confidence:

1. **Canary markers** — a unique per-run token embedded in the probe; if it
   comes back, the injected instruction was executed (confidence 1.0).
2. **Leakage patterns** — secret-looking strings (API keys, JWTs, private key
   blocks) in the response are direct evidence for the data-leakage category.
3. **Refusal heuristics** — an explicit refusal means the attack failed.
4. **Baseline comparison** — large unexplained divergence from a neutral
   control prompt is a low-confidence signal.

Verdicts: `success` / `failed` / `inconclusive`, each with a confidence score
and a human-readable reason. Detection beyond canary markers is probabilistic:
false positives and false negatives are expected.

### Reports

Every scan produces two reports from the same run:

- **JSON** — for automation. Per probe: category, payload sent, response
  received (verbatim evidence), verdict, confidence, detection method,
  severity. Header: target, timestamp, scanner version, config hash, duration.
- **Markdown** — for humans. Overall verdict, a "look here first" triage list
  ordered by severity, a summary table, then per-finding detail with
  request/response excerpts.

Secrets (env-var credentials) never appear in reports, logs, or error
messages — only header *names* are ever printed.

## Quick start

```bash
pip install -e ".[dev]"

# 1. scan the bundled vulnerable mock endpoint
python examples/mock_server.py &
llm-scan scan examples/config.mock.yaml

# 2. contrast with the hardened mock
MODE=hardened python examples/mock_server.py &
llm-scan scan examples/config.mock.hardened.yaml
```

Comparing the two reports shows what a vulnerable vs. a defended endpoint
looks like. To scan a real service, describe its endpoint in YAML:

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
  max_retries: 3                # retries on timeouts, 5xx and 429
  retry_backoff_seconds: 1.0    # exponential backoff base
  max_retry_delay_seconds: 30   # cap for backoff and Retry-After

report:
  json_path: report.json
  markdown_path: report.md
```

```bash
export LLM_SCAN_TOKEN=...
llm-scan scan my-service.yaml
```

Any JSON request body shape works — the `{{INPUT}}` marker marks the injection
point, and `response_path` is a dotted path (with list indices) to the model's
answer. Invalid configs fail fast, before any request is sent. See
[examples/config.openai.yaml](examples/config.openai.yaml) for an
OpenAI-compatible template.

## CLI reference

```text
llm-scan scan CONFIG [--dry-run] [--fail-on never|success|inconclusive]
                     [--include NAME]... [--exclude NAME]... [--max-requests N]
llm-scan --version
```

- `--dry-run` — print the exact scan plan (endpoint, limits, every selected
  probe with its payload size and request count, budget-skipped probes with
  reasons) without sending anything.
- `--fail-on` — exit code 1 when the overall verdict reaches the given level;
  use it to gate CI pipelines. Config errors always exit 2.
- `--include NAME` — run only the named categories and/or probes. Repeatable
  and comma-separated (`--include role_escape --include data_leakage` or
  `--include role_escape,data_leakage`). Cannot be combined with `--exclude`.
- `--exclude NAME` — skip the named categories and/or probes; everything else
  runs. Cannot be combined with `--include`.
- `--max-requests N` — hard request budget for the whole scan. The single
  baseline control prompt counts against the budget (it always runs first).
  A probe runs only if all its repetitions fit; probes that do not fit are
  recorded in the report as skipped with a reason and are excluded from the
  summary, the overall verdict, triage, and `--fail-on`. The budget is never
  exceeded.

Unknown names in `--include`/`--exclude` fail fast with exit 2, before any
request is sent. Examples:

```bash
# fast CI gate: two categories only, capped at 20 requests
llm-scan scan staging.yaml --include direct_injection,prompt_extraction \
    --max-requests 20 --fail-on success

# everything except the burst/rate-limit probes
llm-scan scan staging.yaml --exclude missing_limits

# review the plan before enabling the gate
llm-scan scan staging.yaml --include role_escape --max-requests 3 --dry-run
```

## Safety

- The scanner respects the configured `max_requests_per_second` for all
  traffic **except** the FR-6 burst probe, whose entire purpose is to test
  server-side rate limiting; the burst is hard-capped at 10 requests.
- Transient failures — timeouts, connection errors, HTTP 429 and 5xx — are
  retried with exponential backoff, honoring the `Retry-After` header and
  capped by `max_retry_delay_seconds`. The FR-6 burst probe never retries: a
  429 there is the signal it measures, not a failure.
- Secrets are resolved from environment variables at request time and are
  never written to reports, logs, or error messages (NFR-2).
- Reports record the scanner version and a SHA-256 hash of the config for
  reproducibility (NFR-5).

## How it differs from garak / PyRIT / promptfoo

Those tools test the **model** — you give them access to the model or provider.
This scanner tests the **application**: the endpoint, behind which there may be
RAG, agents, filters, and glue code. That is usually where the vulnerability
lives. And connecting an internal service costs a YAML file, not a code
adapter. Full rationale: [Spec.md §9](Spec.md#9-comparison-with-existing-tools).

## Limitations

Detection beyond canary markers is heuristic; both false positives and false
negatives occur. A determined defender can evade heuristics, and a determined
attacker needs only one payload the scanner does not yet know. Interactions
are single-turn. Results depend on model nondeterminism: rerunning the same
scan may produce different verdicts. **A clean report is not proof of
safety.** See [Spec.md §10](Spec.md#10-limitations).

## Development

```bash
pip install -e ".[dev]"
pre-commit install        # ruff check --fix and ruff format on every commit

python -m pytest -q       # run the test suite
ruff check .              # lint
ruff format --check .     # formatting
```

The test suite covers config validation, HTTP transport, every detection
layer, the probe packs, both report formats, the CLI, and an end-to-end run
against the mock server in both modes.

Adding a new attack category means creating one small class in
`src/llm_endpoint_scanner/probes/` and appending it to `ALL_CATEGORIES` — the
runner, judges, and reports pick it up without changes (NFR-3).

CI runs on every push to `main` and every pull request:

- **Tests** — pytest on Python 3.10–3.13
- **Semgrep** — secrets detection (`p/secrets` ruleset)
- **TruffleHog** — verified secret scanning over full git history

## Documentation

- [Spec.md](Spec.md) — full specification, requirements, milestone plan
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [examples/](examples) — mock server (vulnerable/hardened) and config templates

## License

[MIT](LICENSE)
