# AGENTS.md — context for AI coding assistants (Claude Code / Codex)

> This file is the canonical spec for the project. `CLAUDE.md` points here.
> Read this fully before making changes.

## Mission

A small, **agent-shaped** cyber threat intelligence (CTI) suite that helps a
student analyst **track Russian state-linked threat groups UNC5792 and UNC4221**
(the actors behind the 2026 Signal/WhatsApp phishing spree) by continuously
collecting, normalizing, de-duplicating, correlating, and summarizing their
**publicly reported** footprint.

This is a cybersecurity *projects-class* deliverable. Optimize for clarity,
legibility, and a clean design story over feature count.

## Scope & guardrails (do not violate)

- **Passive collection only.** Consume published advisories, IOC feeds, and
  third-party enrichment datasets. **Never** add code that scans, probes,
  connects to, or otherwise touches suspected attacker infrastructure. No
  active recon against targets.
- **Attribution is cited, not claimed.** The suite aggregates what GTIG, the
  FBI/CISA, and CERT-UA have published. It does not "unmask" individuals.
- **Respect source terms & rate limits.** Use official APIs, honor auth and
  rate limits, cache where possible.
- **Secrets via env only.** API keys come from environment / `.env`
  (git-ignored). Never hardcode or commit keys.

## Architecture

```
cti_tracker/
  config.py        # tracked actors (UNC5792/UNC4221 + aliases) and source URLs
  ioc.py           # passive IOC extraction and defang normalization
  stix_export.py   # validated STIX 2.1 bundle conversion/export
  models.py        # STIX-lite dataclasses (Indicator/ThreatActor/Report/Relationship)
  tagging.py       # keyword correlation: free text -> actor names
  store.py         # SQLite persistence with upsert + times_seen tracking
  orchestrator.py  # builds context, runs agents in order, returns results
  cli.py           # `python3 -m cti_tracker.cli run|show|digest|export-stix|actors|serve`
  web.py           # local read-only HTML dashboard + JSON endpoints
  agents/
    base.py            # Agent ABC, CollectorAgent base, AgentContext, AgentResult
    cisa_collector.py  # WORKING, keyless collector (with offline sample fallback)
    certua_collector.py  # official CERT-UA search/article collector
    threatfox_collector.py  # EXAMPLE keyed collector (skips without API key)
    analyst.py         # summary agent; Phase 5 LLM hook lives here
  data/sample_cisa_feed.xml  # offline fixture so the suite always runs
tests/
actor-config.example.json  # template for tracking other documented actors
```

**Core idea:** every unit of work is an `Agent` with one responsibility and a
`run(ctx) -> AgentResult`. Collectors subclass `CollectorAgent` and implement
`collect(ctx) -> list[StixObject]` (pure, no I/O persistence — the base class
handles persistence and counting). Adding capability = adding an agent; the
orchestrator never needs rewiring.

**Data model:** STIX-lite. Objects get **deterministic ids** (uuid5 over their
identity — IOC value, advisory URL, actor name), so the same real-world thing
always yields the same id. That is what makes de-duplication and "seen this
before / it reappeared" tracking work. Stay STIX-compatible so we can export to
OpenCTI/MISP/ATT&CK later.

## Coding conventions

- Python 3.10+, standard library first. Current third-party deps: `requests`,
  `feedparser` (runtime), `pytest` (dev), `python-dotenv` (optional).
- `from __future__ import annotations` at the top of modules; type-hint
  everything.
- Collectors must never crash the run — `CollectorAgent.run` already wraps
  `collect` in try/except. Surface problems via `self._run_notes` / result
  errors, not exceptions that bubble up.
- New keyed sources: import the network library lazily inside `collect` and
  **skip cleanly with a note** when the key is absent (see ThreatFox).
- Keep `config.ACTORS` as the default catalog; a JSON profile may override it at
  runtime through `--actor-config` so the engine can track other groups.
- Add/extend tests for any new model logic or store behavior.

## How to add a new collector (the recipe)

1. Create `agents/<source>_collector.py` with a class subclassing
   `CollectorAgent`; set `name` and `description`.
2. Implement `collect(self, ctx) -> list[StixObject]`. Read keys via
   `os.getenv(...)` / `ctx.config`. Map source records to `Indicator` /
   `Report` / `Relationship`. Tag with `tagging.tag_text(...)`. Keep only
   actor-relevant items in Phase 1.
3. Register it in `orchestrator.default_agents()` (collectors before the
   analyst).
4. Add a test that feeds a sample payload and asserts the produced objects.

## Roadmap (phases) and good first tasks

- **Phase 1 (current):** end-to-end skeleton — CISA collector + SQLite + CLI. ✅
- **Phase 2 (current):** CERT-UA collection, IOC extraction, change digest,
  configurable actor profiles, local dashboard, STIX 2.1 bundle export,
  and more collectors (AlienVault OTX, CISA KEV JSON).
- **Phase 3:** enrichment + correlation — for each new domain/IP, pull WHOIS,
  ASN, passive DNS, and **certificate transparency via crt.sh** (keyless);
  build an `EnrichmentAgent` and a `CorrelationAgent` that links infrastructure
  by shared certs/registrants.
- **Phase 4:** detection output — generate **Sigma**/Suricata rules from
  collected IOCs and TTPs; emit a periodic digest/alert on new indicators.
- **Phase 5:** LLM analyst — replace `AnalystAgent.run` body with an Anthropic
  API call (key via `ANTHROPIC_API_KEY`) that drafts a narrative summary and
  proposes new collector queries/pivots.

**Good first tasks for an assistant:** add the CISA KEV JSON collector; add a
crt.sh enrichment lookup for indicators of type `domain-name`; add a `digest`
CLI subcommand that prints what changed since a given timestamp; expand
`config.ACTORS` with associated malware families as labels; add a Sigma-rule
emitter for collected domains.

## Candidate data sources (free tiers; verify endpoints/terms before use)

- abuse.ch **ThreatFox / URLhaus / MalwareBazaar** (free Auth-Key)
- **AlienVault OTX** (free API key; subscribe to pulses by actor/keyword)
- **CISA** advisories (RSS) and **KEV** catalog (plain JSON)
- **CERT-UA** (cert.gov.ua) — primary source for UAC-0185 / UAC-0195
- **MITRE ATT&CK** STIX data (`mitre-attack/attack-stix-data`) for TTP mapping
- **crt.sh** (certificate transparency, keyless) for infra pivoting
- **urlscan.io**, **VirusTotal** (free, rate-limited) for URL/domain/hash enrichment

## Actor reference

| Group | Aliases | Notes |
|-------|---------|-------|
| UNC5792 | UAC-0195 | FSB-linked; abuses Signal device-linking via spoofed group-invite pages. |
| UNC4221 | UAC-0185 | Russian military-linked; Signal phishing kit mimicking Kropyva; PINPOINT geolocation payload; associated tooling incl. STALECOOKIE, TINYWHALE. |

Primary reporting: GTIG "Signals of Trouble" (Feb 2025), GTIG Defense
Industrial Base report (Feb 2026), FBI/CISA advisory PSA I-062626-PSA, U.S.
State Dept. Rewards for Justice announcement (Jun 2026).
