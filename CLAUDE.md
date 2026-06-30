# CLAUDE.md

The full project spec, architecture, guardrails, and roadmap live in
[`AGENTS.md`](./AGENTS.md). Read it before making changes.

## Quick reference

- **Run:** `python3 -m cti_tracker.cli run`
- **Inspect:** `python3 -m cti_tracker.cli show --limit 15`
- **Digest:** `python3 -m cti_tracker.cli digest --since 2026-06-01T00:00:00Z`
- **Dashboard:** `python3 -m cti_tracker.cli serve`
- **STIX export:** `python3 -m cti_tracker.cli export-stix --output bundle.json --pretty`
- **Analyze:** `python3 -m cti_tracker.cli analyze`
- **List actors:** `python3 -m cti_tracker.cli actors`
- **Test:** `pytest -q`

## Hard rules (see AGENTS.md "Scope & guardrails")

- Passive collection only — never scan, probe, or connect to suspected
  attacker infrastructure.
- Secrets via environment / `.env` only; never hardcode or commit keys.
- Collectors must skip cleanly (with a note) when an API key is missing, and
  must never crash the run.
- Keep `cti_tracker/config.py::ACTORS` the single source of truth for the
  tracked actor set.

## Where things go

- New data source → `cti_tracker/agents/<name>_collector.py` subclassing
  `CollectorAgent`, then register in `orchestrator.default_agents()`.
- New analysis step → a new `Agent` (e.g. `EnrichmentAgent`, `CorrelationAgent`).
- LLM-assisted analysis → fill in `cti_tracker/agents/analyst.py` (Phase 5).
