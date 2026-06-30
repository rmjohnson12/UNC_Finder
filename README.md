# UNC Finder

A small, **agent-shaped** cyber threat intelligence (CTI) suite for tracking the
Russian state-linked groups **UNC5792** and **UNC4221** — the actors behind the
2026 Signal/WhatsApp phishing spree — from **publicly reported** sources only.

Built as a cybersecurity projects-class deliverable. Each run collects,
normalizes (STIX-lite), de-duplicates, and summarizes the actors' published
footprint. **Passive collection only** — it never touches suspected attacker
infrastructure. See [`AGENTS.md`](./AGENTS.md) for the full design.

## Quick start

```bash
git clone https://github.com/rmjohnson12/UNC_Finder.git
cd UNC_Finder
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Collect from the configured public sources and persist to cti_tracker.db.
python3 -m cti_tracker.cli run

# Limit or disable third-party passive enrichment per run.
python3 -m cti_tracker.cli run --enrichment-limit 3
python3 -m cti_tracker.cli run --enrichment-limit 0

# Inspect the results from the terminal.
python3 -m cti_tracker.cli show --limit 15
python3 -m cti_tracker.cli digest --since 2026-06-01T00:00:00Z
python3 -m cti_tracker.cli actors

# Export an interoperable, validated STIX 2.1 bundle.
python3 -m cti_tracker.cli export-stix --output unc-finder-bundle.json --pretty

# Draft an evidence-grounded analysis when Anthropic credentials are configured.
python3 -m cti_tracker.cli analyze

# Start the local read-only dashboard.
python3 -m cti_tracker.cli serve
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080) while the dashboard is
running. Press `Ctrl+C` to stop it.

On Windows PowerShell, activate the environment with
`.venv\Scripts\Activate.ps1`. To verify the installation on any platform:

```bash
pytest -q
```

The CISA collector falls back to a bundled sample if its live feed is
unavailable. ThreatFox skips cleanly unless `THREATFOX_API_KEY` is configured.

## What it does today

- Collects actor-relevant public reporting from CISA and CERT-UA.
- Optionally collects matching ThreatFox IOCs with an API key.
- Extracts and normalizes hashes, URLs, domains, and IPv4 indicators.
- Converts common defanged values such as `hxxps://example[.]com` without
  connecting to them.
- Stores deterministic STIX-lite objects in SQLite, de-duplicating repeated
  observations and tracking first seen, last seen, and times seen.
- Produces terminal listings, change digests, and a local read-only dashboard.
- Exports validated STIX 2.1 bundles for downstream CTI tools.
- Passively enriches a bounded number of domains/IPs through RDAP.org and
  crt.sh, then correlates indicators only on shared published evidence.
- Optionally drafts cited analysis through Anthropic's Messages API.

## Track other actors

UNC5792 and UNC4221 are the built-in profile, but the engine is not limited to
them. Copy `actor-config.example.json`, edit its names, aliases, and keywords,
then place `--actor-config` before the subcommand:

```bash
python3 -m cti_tracker.cli --actor-config your-actors.json actors
python3 -m cti_tracker.cli --actor-config your-actors.json run
```

Optional: copy `.env.example` to `.env` and add free API keys to enable
keyed collectors (e.g. ThreatFox). LLM analysis requires both
`ANTHROPIC_API_KEY` and an explicit `ANTHROPIC_MODEL`; without them, the
analyst skips cleanly and still prints deterministic store totals.

## How it works

Every unit of work is an **Agent** with one job and a `run(ctx) -> AgentResult`.
Collectors pull from a source and emit STIX-lite objects. The orchestrator
persists them to SQLite, de-duplicating by deterministic ID and tracking how
often each object is seen. The current analyst reports store totals. Adding a
capability means adding an agent; see the recipe in `AGENTS.md`.

```
public sources → collector agents → IOC extraction/tagging
               → SQLite store → digest/dashboard/analyst
```

## Next milestones

1. Add more passive sources and confidence scoring for correlations.
2. Add analyst review/export workflows for generated narratives.

## Working with an AI assistant

This repo is set up for Claude Code / Codex: `AGENTS.md` (canonical) and
`CLAUDE.md` describe the architecture, guardrails, conventions, and a list of
good first tasks. Point your assistant at those and it can extend the suite
safely.

## Disclaimer

Educational/defensive use only. Verify all source URLs and respect each
provider's terms and rate limits. Attribution is cited from public reporting,
not independently established.
