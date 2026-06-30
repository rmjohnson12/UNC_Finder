# cti-tracker

A small, **agent-shaped** cyber threat intelligence (CTI) suite for tracking the
Russian state-linked groups **UNC5792** and **UNC4221** — the actors behind the
2026 Signal/WhatsApp phishing spree — from **publicly reported** sources only.

Built as a cybersecurity projects-class deliverable. It continuously collects,
normalizes (STIX-lite), de-duplicates, correlates, and summarizes the actors'
published footprint. **Passive collection only** — it never touches suspected
attacker infrastructure. See [`AGENTS.md`](./AGENTS.md) for the full design.

## Quick start

```bash
git clone https://github.com/rmjohnson12/UNC_Finder.git
cd UNC_Finder
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Runs end-to-end on the first try — if the live CISA feed isn't reachable,
# it falls back to a bundled sample feed so you always get output.
python3 -m cti_tracker.cli run

python3 -m cti_tracker.cli show --limit 15
python3 -m cti_tracker.cli digest --since 2026-06-01T00:00:00Z
python3 -m cti_tracker.cli actors
python3 -m cti_tracker.cli serve
pytest -q
```

Open `http://127.0.0.1:8080` for the local read-only dashboard. To track a
different actor set, copy `actor-config.example.json`, edit the actors,
aliases, and keywords, then add `--actor-config your-actors.json` before the
subcommand:

```bash
python3 -m cti_tracker.cli --actor-config your-actors.json actors
python3 -m cti_tracker.cli --actor-config your-actors.json run
```

Optional: copy `.env.example` to `.env` and add free API keys to enable
keyed collectors (e.g. ThreatFox).

## How it works

Every unit of work is an **Agent** with one job and a `run(ctx) -> AgentResult`.
Collectors pull from a source and emit STIX-lite objects; the orchestrator
persists them to SQLite (de-duplicating by deterministic id and tracking how
often each is seen); the analyst agent summarizes. Adding capability means
adding an agent — see the recipe in `AGENTS.md`.

```
collectors → orchestrator → SQLite store → analyst/output
```

## Roadmap

1. **Phase 1:** CISA collector + SQLite + CLI — runnable spine.
2. **Phase 2 (in progress):** CERT-UA collection, IOC extraction, change digest,
   more collectors (OTX, CISA KEV), and STIX polish.
3. **Phase 3:** enrichment + infrastructure correlation (WHOIS/ASN/passive DNS, crt.sh).
4. **Phase 4:** Sigma/Suricata rule generation + change digests.
5. **Phase 5:** LLM analyst (Anthropic API) for narrative + pivot suggestions.

## Working with an AI assistant

This repo is set up for Claude Code / Codex: `AGENTS.md` (canonical) and
`CLAUDE.md` describe the architecture, guardrails, conventions, and a list of
good first tasks. Point your assistant at those and it can extend the suite
safely.

## Disclaimer

Educational/defensive use only. Verify all source URLs and respect each
provider's terms and rate limits. Attribution is cited from public reporting,
not independently established.
