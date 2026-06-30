"""Analyst agent — summarizes current state.

Phase 1: prints object counts so every run ends with a readable status line.
Phase 5: swap the body for an LLM call (Claude via the Anthropic API) that
drafts a narrative summary and proposes new pivots/queries for the collectors.
The Agent shape stays the same; only the body changes.
"""
from __future__ import annotations

from .base import Agent, AgentContext, AgentResult


class AnalystAgent(Agent):
    name = "analyst"
    description = "Summarizes the store. Phase 5: wire in an LLM to draft analysis."

    def run(self, ctx: AgentContext) -> AgentResult:
        result = AgentResult(agent=self.name)
        counts = ctx.store.counts_by_type()
        summary = ", ".join(f"{k}={v}" for k, v in counts.items()) or "empty"
        result.notes.append(f"store contents: {summary}")
        result.notes.append("LLM analysis not yet wired — see AGENTS.md (Phase 5).")
        return result
