# llm-endpoint-scanner

Black-box security scanner for deployed LLM services — DAST for LLM apps.
It probes an HTTP endpoint from the outside, with no access to code, prompts,
or configuration, and tells you which services behave dangerously and where to
look first.

See [Spec.md](Spec.md) for the full specification.

## What it checks

- System prompt extraction
- Direct prompt injection
- Indirect prompt injection
- Role escape
- Data leakage in responses
- Missing rate / input limits

Reports are produced as JSON (for automation) and Markdown (for humans).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Limitations

Detecting whether an attack succeeded is harder than carrying it out. Beyond
canary-marker checks, detection relies on heuristics and can produce both
false positives and false negatives. A clean report is not proof of safety —
this tool answers "where to look first," not "is it secure." See
[Spec.md §10](Spec.md#10-limitations).
