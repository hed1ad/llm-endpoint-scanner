# Contributing to llm-endpoint-scanner

Thanks for your interest. This document explains how to get started and what
the ground rules are.

## Before you start

Read [Spec.md](Spec.md) first. It defines what the tool is (a black-box DAST
scanner for LLM endpoints), what it deliberately is not (a model tester like
garak or PyRIT), and the milestone plan (M1–M4). Contributions should move a
milestone forward, not expand the scope.

## Ground rules

- **Safety first (NFR-1, NFR-2).** The scanner must respect configured rate
  limits and must never write credentials into reports, logs, or errors. PRs
  that leak secrets will not be merged.
- **Honest detection (Spec.md §6).** Every verdict states which detection
  method produced it and its confidence. Do not add detection logic that
  presents heuristic guesses as certain results.
- **Config over code (Spec.md §9).** Supporting a new endpoint shape should
  never require an adapter — extend the config format instead.
- **Extensible probes (NFR-3).** New probe categories plug into `probes/`
  without touching the runner.
- Match the existing code style; keep comments minimal.

## Testing

- Every change to `judges/` or `probes/` needs tests in `tests/`.
- Use the mock server (`examples/`) for integration-style checks — never run
  the scanner against third-party endpoints without authorization.

## Local checks

Install the dev extras and enable the pre-commit hooks:

```bash
pip install -e ".[dev]"
pre-commit install
```

The hooks run `ruff check --fix` and `ruff format` on every commit. Run them
against the whole tree at any time with `pre-commit run --all-files`.

Before opening a PR, make sure these pass:

```bash
python -m pytest -q
ruff check .
ruff format --check .
```

## CI

Every push to `main` and every pull request runs the full pipeline
(`.github/workflows/ci.yml`):

- **Tests** — pytest on Python 3.10–3.13.
- **Semgrep** — secrets detection using the `p/secrets` ruleset.
- **TruffleHog** — scans the full git history for verified leaked secrets.

All three jobs must pass for a PR to be merged.

## Pull requests

- One concern per PR; reference the milestone or requirement ID (e.g. FR-2,
  REQ-C4) it addresses.
- Describe how you verified the change (tests run, mock-server scan output).
