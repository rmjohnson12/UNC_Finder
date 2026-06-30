"""Agent framework.

Every unit of work is an Agent with one job and a `run(ctx) -> AgentResult`
method. Collectors pull from a source; the analyst summarizes; future agents
(enrichment, correlation) follow the same shape. The Orchestrator wires them
together, so adding capability = adding an agent, not rewiring the pipeline.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..models import StixObject
from ..store import Store


@dataclass
class AgentContext:
    """Everything an agent needs to do its job for one run."""

    store: Store
    config: dict = field(default_factory=dict)
    dry_run: bool = False


@dataclass
class AgentResult:
    agent: str
    produced: list[StixObject] = field(default_factory=list)
    new_count: int = 0
    seen_count: int = 0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class Agent(ABC):
    name: str = "agent"
    description: str = ""

    @abstractmethod
    def run(self, ctx: AgentContext) -> AgentResult:  # pragma: no cover
        ...


class CollectorAgent(Agent):
    """Base for source collectors.

    Subclasses implement `collect(ctx) -> list[StixObject]` and stay pure
    (no persistence), which makes them trivial to unit test. The base `run`
    handles persistence, counting, and never letting a collector crash the
    whole suite.
    """

    def __init__(self) -> None:
        self._run_notes: list[str] = []

    def collect(self, ctx: AgentContext) -> list[StixObject]:  # pragma: no cover
        raise NotImplementedError

    def run(self, ctx: AgentContext) -> AgentResult:
        result = AgentResult(agent=self.name)
        self._run_notes = []
        try:
            objects = self.collect(ctx)
        except Exception as exc:  # collectors must never take down the run
            result.errors.append(f"{type(exc).__name__}: {exc}")
            result.notes.extend(self._run_notes)
            return result
        result.produced = objects
        result.notes.extend(self._run_notes)
        if ctx.dry_run:
            result.notes.append("dry-run: nothing persisted")
            return result
        for obj in objects:
            if ctx.store.upsert(obj):
                result.new_count += 1
            else:
                result.seen_count += 1
        return result
