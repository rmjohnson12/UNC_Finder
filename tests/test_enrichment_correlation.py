from cti_tracker.agents.base import AgentContext
from cti_tracker.agents.correlation import CorrelationAgent
from cti_tracker.agents.enrichment import EnrichmentAgent
from cti_tracker.models import Indicator
from cti_tracker.store import Store


def test_passive_enrichment_drives_evidence_based_correlation(monkeypatch):
    store = Store(":memory:")
    for value in ("one.example", "two.example"):
        store.upsert(
            Indicator(
                value=value,
                ioc_type="domain-name",
                source="test",
                labels=["EXAMPLE-GROUP"],
            )
        )

    agent = EnrichmentAgent()
    requested: list[str] = []

    def fake_get_json(url, params=None):
        requested.append(url)
        if url.startswith("https://rdap.org/"):
            return {"handle": "DOMAIN", "entities": [{"handle": "REG-1", "roles": ["registrant"]}]}
        return [{"id": 42, "name_value": "one.example\ntwo.example"}]

    monkeypatch.setattr(agent, "_get_json", fake_get_json)
    monkeypatch.setattr(agent, "_pause", lambda: None)
    ctx = AgentContext(store=store, config={"enrichment_limit": 2})
    try:
        enriched = agent.run(ctx)
        correlated = CorrelationAgent().run(ctx)
        notes = store.all_of_type("note")
        relationships = store.all_of_type("relationship")
    finally:
        store.close()

    assert enriched.new_count == 2
    assert correlated.new_count == 1
    assert len(notes) == 2
    assert len(relationships) == 1
    evidence = relationships[0]["raw"]["correlation_evidence"]
    assert "shared-certificate:42" in evidence
    assert "shared-registrant:REG-1" in evidence
    assert all(url.startswith(("https://rdap.org/", "https://crt.sh/")) for url in requested)


def test_enrichment_limit_bounds_attempts_when_providers_fail(monkeypatch):
    store = Store(":memory:")
    for value in ("one.example", "two.example"):
        store.upsert(Indicator(value=value, ioc_type="domain-name"))
    agent = EnrichmentAgent()
    calls = []

    def fail(url, params=None):
        calls.append(url)
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(agent, "_get_json", fail)
    monkeypatch.setattr(agent, "_pause", lambda: None)
    try:
        result = agent.run(AgentContext(store=store, config={"enrichment_limit": 1}))
    finally:
        store.close()

    assert result.new_count == 0
    assert len(calls) == 2  # one domain, one RDAP + one crt.sh attempt
