from cti_tracker.agents.analyst import AnalystAgent
from cti_tracker.agents.base import AgentContext
from cti_tracker.models import Report
from cti_tracker.store import Store


def test_analyst_skips_cleanly_without_credentials(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    store = Store(":memory:")
    try:
        result = AnalystAgent().run(AgentContext(store=store))
    finally:
        store.close()
    assert any("LLM skipped" in note for note in result.notes)
    assert result.errors == []


def test_analyst_sends_bounded_source_backed_evidence(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_MODEL", "test-model")
    store = Store(":memory:")
    store.upsert(
        Report(
            name="Published report",
            description="Source-backed description",
            published="2026-01-01T00:00:00Z",
            url="https://example.invalid/report",
            labels=["EXAMPLE-GROUP"],
        )
    )
    captured = {}
    agent = AnalystAgent()

    def fake_analyze(api_key, model, evidence):
        captured.update({"api_key": api_key, "model": model, "evidence": evidence})
        return "Cited draft"

    monkeypatch.setattr(agent, "_analyze", fake_analyze)
    try:
        result = agent.run(AgentContext(store=store))
    finally:
        store.close()

    assert captured["model"] == "test-model"
    assert captured["evidence"]["reports"][0]["url"] == "https://example.invalid/report"
    assert any("Cited draft" in note for note in result.notes)
