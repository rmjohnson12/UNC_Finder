"""Orchestrator — runs the agents in order and collects their results.

Phase 1 runs synchronously on demand. Later you can schedule this (cron /
systemd timer / GitHub Action) for continuous tracking, or fan collectors out
concurrently. The contract stays: build a context, run each agent, return
results.
"""
from __future__ import annotations

from .agents.analyst import AnalystAgent
from .agents.base import Agent, AgentContext, AgentResult
from .agents.cisa_collector import CISAAdvisoryCollector
from .agents.threatfox_collector import ThreatFoxCollector
from .store import Store


def default_agents() -> list[Agent]:
    """Collectors first, analyst last so the run ends with a summary."""
    return [
        CISAAdvisoryCollector(),
        ThreatFoxCollector(),
        AnalystAgent(),
    ]


class Orchestrator:
    def __init__(
        self,
        store: Store,
        agents: list[Agent] | None = None,
        config: dict | None = None,
    ) -> None:
        self.store = store
        self.agents = agents if agents is not None else default_agents()
        self.config = config or {}

    def run(self, dry_run: bool = False) -> list[AgentResult]:
        ctx = AgentContext(store=self.store, config=self.config, dry_run=dry_run)
        return [agent.run(ctx) for agent in self.agents]
