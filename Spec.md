# llm-endpoint-scanner — Specification

## 1. Overview

`llm-endpoint-scanner` is a black-box security scanner for deployed LLM-backed
services. It tests a service from the outside, through its HTTP endpoint,
without any access to its code, prompts, or configuration.

The closest analogy is DAST for LLM applications: the same way OWASP ZAP works
with a web application over HTTP knowing nothing about its internals, this tool
works with an LLM service over its API.

The tool is developed as an open-source product (MIT license) and distributed
via PyPI as `llm-endpoint-scanner`. (added 2026-10-22, see §12)

## 2. Problem Statement

A typical and unpleasant situation: a company ends up with several LLM-powered
services — a support chatbot, an in-product assistant, a document
summarization service. They were built by different teams, at different times;
one uses OpenAI, another a local model, a third a wrapper around a framework.
The Sec engineer has no access to their code and no time to dig into each
one.

The question they need answered: **which of these services behave dangerously,
and where should I look first?**

This tool provides that answer in about ten minutes instead of a week of
manual probing. It does not replace deep analysis — it answers the question
"where to look first."

## 3. Scope and Non-Goals

**In scope:**

- Scanning any HTTP(S) endpoint backed by an LLM, regardless of what stands
  behind it (RAG, agent, filters, custom glue code).
- Arbitrary request/response formats via declarative configuration — no code
  adapters required.
- A fixed set of well-known attack categories with evidence-based reporting.

**Out of scope:**

- Testing the model itself. Vulnerabilities usually live not in the model but
  in how it is wired into the application — that wiring is the target.
- Replacing manual, in-depth security assessment.
- Multi-turn conversation attacks. Single-turn only: multi-turn campaigns
  require an attacker LLM, break the "answer in ten minutes" promise, and are
  already covered well by PyRIT; this remains out of scope for v1.x.
  (clarified 2026-10-22, see §12)

## 4. Input: Endpoint Configuration

The scanner takes a single YAML config describing the endpoint:

```yaml
endpoint:
  url: https://internal.example.com/api/chat
  method: POST
  headers:
    Authorization: "Bearer ${LLM_SCAN_TOKEN}"   # env-var interpolation
    Content-Type: application/json

  # Where to inject the probe text into the request body.
  # Dotted path; the marker {{INPUT}} is replaced by the probe payload.
  request_template:
    model: "support-bot-v2"
    messages:
      - role: user
        content: "{{INPUT}}"

  # Where to find the model's answer in the response. JSONPath-like dotted path.
  response_path: "choices.0.message.content"

limits:
  timeout_seconds: 30
  max_requests_per_second: 2
  max_probe_length: 8000

report:
  json_path: report.json
  markdown_path: report.md
```

Requirements:

- REQ-C1: Config must support arbitrary JSON request bodies with a single
  `{{INPUT}}` injection point.
- REQ-C2: Response extraction must support dotted paths into nested JSON
  (including list indices).
- REQ-C3: Secrets must come from environment variables, never be printed into
  reports or logs.
- REQ-C4: Invalid configs must fail fast with a clear error before any
  request is sent.

## 5. Probe Categories (Functional Requirements)

### FR-1: System Prompt Extraction

Ask the model to repeat its instructions, in various phrasings. If it complies,
the system prompt is unprotected — and system prompts frequently contain
business logic and sometimes sensitive data.

### FR-2: Direct Prompt Injection

Attempt to override behavior: "ignore previous instructions and ...". Verify
whether the model stays in its assigned role.

### FR-3: Indirect Prompt Injection

Submit a text with an instruction hidden inside it, as if the model were
reading an attacker-supplied document or web page. This is a separate category
because here the attacker and the user are different people.

### FR-4: Role Escape

A support bot should answer questions about the product. If it gladly solves
equations and writes poems, no constraints were applied — and the endpoint can
be abused as someone else's free LLM API.

### FR-5: Data Leakage

Check whether responses contain fragments of other users' requests, raw
context contents, or internal service information.

### FR-6: Missing Limits

How many requests pass in a burst; how the endpoint reacts to very long input.
An endpoint with no rate limiting or input caps is an abuse vector.

### FR-7: Compliance Mapping (added 2026-10-22, see §12)

Every built-in probe category maps to OWASP LLM Top 10 (2025) and MITRE ATLAS.
Both reports carry the mapping: per-probe and per-category fields in JSON, a
dedicated column in the Markdown summary table. The mapping table states the
framework versions it targets and lives in versioned code, not prose.

Acceptance criteria:

- Every built-in probe has a non-empty mapping (OWASP id + ATLAS technique).
- JSON report exposes `compliance` per probe and per category; Markdown shows
  the mapping in the summary table and per-finding detail.
- The report header names the framework versions used (e.g. "OWASP LLM Top 10
  2025").

### FR-8: Scan Selection and Request Budget (added 2026-10-22, see §12)

The CLI allows running a subset of the scan: `--include` / `--exclude` by
category and by probe name, and `--max-requests N` as a hard budget. Unknown
names fail fast (exit 2). `--dry-run` reflects the selection exactly.

Acceptance criteria:

- A selected subset sends only its probes plus the single baseline request.
- The request budget is never exceeded; probes that do not fit are recorded
  as skipped with a reason, not silently dropped.
- Summary, triage, and `--fail-on` consider only the probes that ran.

### FR-9: User-Defined Probes (added 2026-10-22, see §12)

The config accepts a `custom_probes` list: name, category (existing or new),
payload template with the `{canary}` placeholder, severity, and optional
repetitions. Custom probes are validated fail-fast (REQ-C4) and behave exactly
like built-in ones: same judges, reports, dry-run, and triage.

Acceptance criteria:

- A config with a valid custom probe runs it and reports it like any built-in
  probe, under its declared category.
- Invalid custom probes (missing `{canary}`, unknown fields, bad severity)
  abort before any request with a clear error.
- Custom categories appear in the summary and triage without code changes
  (extends NFR-3).

### FR-10: Optional LLM-as-Judge Layer (added 2026-10-22, see §12)

An optional detection layer that asks a user-configured judge LLM to classify
responses the local layers could not resolve confidently (verdict
`inconclusive` or confidence below a threshold). Off by default; enabling it
is an explicit opt-in (NFR-6). The judge receives only the probe payload and
the response text — never request headers, secrets, or config internals.

Acceptance criteria:

- With no judge configured, a scan sends zero extra requests (verified by
  test) and behaves exactly as before.
- A judge verdict is recorded with method `llm_judge` and its own confidence;
  the report still states which method produced the verdict (§6 honesty
  requirement).
- If the judge endpoint errors, the scan falls back to the local verdict and
  marks the probe accordingly; the scan never aborts on judge failure.
- A startup warning states that responses leave the machine when the layer
  is enabled.

### FR-11: Multi-Endpoint Sweep (added 2026-10-22, see §12)

One command scans several endpoints (a list of config files or a directory)
and produces an aggregate triage report answering the §2 question "which of
these services do I look at first": targets ranked by worst verdict and
severity. Per-target reports are still written individually.

Acceptance criteria:

- The aggregate report (JSON + Markdown) lists every target with its overall
  verdict, ranked worst-first, with per-category summary.
- A failing or unreachable target is recorded as such and never aborts the
  sweep.
- Per-target limits (rate, timeout) are respected independently.

## 6. Detection / Judging

**Determining that an attack succeeded is harder than carrying it out.**
Sending a prompt is easy; deciding from the response whether the injection
worked is the core problem of this tool.

Detection is layered, from most to least reliable:

1. **Canary markers.** Embed a unique marker into the probe and look for it
   in the response. If the model was asked to reply with `CANARY_7f3a` and
   that string comes back — the injected instruction was executed. Markers
   must be unique per scan run to avoid matching pre-existing text.
2. **Baseline comparison.** Compare the response under attack with the
   response to a neutral control prompt; large unexplained divergence is a
   signal.
3. **Heuristics.** Tone and structure shifts, role-adherence checks (e.g. a
   support bot suddenly producing Python code or poetry).

**Honesty requirement:** no fully reliable detection method exists. Every
verdict carries a confidence level, and the report must state which detection
method produced it. False positives and false negatives are expected; see
Section 10.

## 7. Output / Reporting

Two report formats from the same scan:

- **JSON** — for automation. Per probe: category, payload sent, response
  received (verbatim evidence), verdict (`success` / `failed` / `inconclusive`),
  confidence, detection method, severity.
- **Markdown** — for humans. A summary table of categories with verdicts,
  then per-finding detail with request/response examples.
- **Compliance mapping** — both reports map every category and finding to
  OWASP LLM Top 10 (2025) and MITRE ATLAS, so the report is usable as audit
  evidence (FR-7). (added 2026-10-22, see §12)

The report header must include: target URL, scan timestamp, scanner version,
total duration, and an overall triage verdict ("look here first").

### 7.1 User Scenarios (added 2026-10-22, see §12)

- **US-1: PR gate.** A CI job runs a fast subset (FR-8) on every pull request
  against the staging endpoint and fails the build when the overall verdict
  reaches a configured level (`--fail-on`). `--dry-run` is used to review the
  plan before enabling the gate.
- **US-2: Monthly sweep.** A Sec engineer runs one sweep (FR-11) over all
  internal LLM services and gets a single ranked triage report: which service
  regressed, which category to investigate first.
- **US-3: Audit evidence.** For an EU AI Act / NIST AI RMF assessment, the
  engineer attaches the compliance-mapped report (FR-7): every finding
  references OWASP LLM Top 10 and MITRE ATLAS identifiers.

## 8. Non-Functional Requirements

- **NFR-1 Safe by default.** Respect configured rate limits; support
  `--dry-run` (print planned requests without sending).
- **NFR-2 No secret leakage.** Credentials never appear in reports, logs, or
  error messages.
- **NFR-3 Extensibility.** Probe packs are plain data + small classes; adding
  a category must not require touching the runner.
- **NFR-4 Offline development.** A local mock server (see `examples/`) must
  allow developing and testing the scanner without a real LLM endpoint.
- **NFR-5 Reproducibility.** Reports record scanner version and config hash.
- **NFR-6 Offline by default.** (added 2026-10-22, see §12) A scan never makes
  network calls beyond the configured target unless the user explicitly opts
  in (FR-10 LLM-judge). No telemetry, no update checks, no cloud generation —
  ever.
- **NFR-7 Interface stability.** (added 2026-10-22, see §12) CLI flags and the
  config schema do not break without a major version bump; deprecations are
  announced at least one minor release ahead and keep working until then.

## 9. Comparison with Existing Tools

Tools already exist: garak (NVIDIA), PyRIT (Microsoft), promptfoo. "Why
another one?" is a fair question.

- **They test the model; this tests the application.** Existing tools mostly
  need access to the model or provider. This scanner works with the endpoint,
  behind which there may be anything — RAG, an agent, filters, glue code. For
  an AppSec engineer this is usually the needed scenario, because the
  vulnerability is rarely in the model itself; it is in how the model was
  wired in.
- **Configuration over adapters.** Internal services rarely expose a standard
  interface; connecting big tools to them means writing an adapter. Here it is
  a YAML file.
- **Honest motivation.** This project was also built to learn the domain
  hands-on. That is a legitimate reason, and pretending it is a garak
  competitor would be less credible than admitting it.

## 10. Limitations

- Detection is probabilistic beyond canary markers; both false positives and
  false negatives occur. A "clean" report is not proof of safety.
- A determined defender can evade heuristics; a determined attacker needs only
  one working payload the scanner does not yet know.
- Single-turn interactions only; multi-turn agentic attacks are out of scope.
- Results depend on model nondeterminism: rerunning the same scan may produce
  different verdicts.

## 11. Milestones

- **M1:** Config parsing + HTTP transport + canary-based probes (FR-1, FR-2).
- **M2:** All probe categories (FR-1..FR-6) + JSON report.
- **M3:** Baseline/heuristic detection + Markdown report.
- **M4:** Hardening: dry-run, mock server, docs, examples, CI.
- **M5:** (added 2026-10-22, see §12) Compliance mapping (FR-7) + scan
  selection and request budget (FR-8) + transport resilience (retry/backoff
  for transient errors and 429 with `Retry-After`).
- **M6:** (added 2026-10-22, see §12) User-defined probes (FR-9) + optional
  LLM-as-judge (FR-10) + multi-endpoint sweep (FR-11).

## 12. Spec Changelog (added 2026-10-22)

- **2026-10-22** — Post-M4 roadmap added after market research
  (`docs/research/2026-10-22-market.md`): new functional requirements FR-7
  (compliance mapping), FR-8 (scan selection and request budget), FR-9
  (user-defined probes), FR-10 (optional LLM-as-judge, opt-in), FR-11
  (multi-endpoint sweep); new non-functional requirements NFR-6 (offline by
  default) and NFR-7 (interface stability); user scenarios §7.1 (US-1..US-3);
  milestones M5 and M6; open-source/PyPI distribution stated in §1;
  multi-turn scope clarified in §3 (remains out of scope for v1.x).
  No existing content was removed.
