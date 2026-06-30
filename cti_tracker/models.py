"""STIX-lite data model.

We model everything as small dataclasses that mirror a subset of STIX 2.1
(Indicator, Threat Actor, Report, Relationship). This keeps the project
interoperable with real CTI tooling later (OpenCTI / MISP / ATT&CK) without
pulling in a heavy dependency for Phase 1.

Identity rule: each object gets a *deterministic* id derived from the thing it
represents (an IOC value, an advisory URL, an actor name). That means the same
real-world thing always produces the same id across runs, which is what makes
de-duplication and "have I seen this before?" tracking work.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# Stable namespace for uuid5. Any fixed UUID works; do not change it once you
# have data, or ids for existing objects will shift.
_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(stix_type: str, *parts: str) -> str:
    """Deterministic STIX-style id, e.g. indicator--<uuid5>."""
    return f"{stix_type}--{uuid.uuid5(_NS, '|'.join(parts))}"


@dataclass
class StixObject:
    """Base for all objects. Subclasses set a stable id in __post_init__."""

    type: str = "stix-object"
    id: str = ""
    created: str = field(default_factory=_now)
    modified: str = field(default_factory=_now)
    source: str = "unknown"            # which agent produced this
    labels: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)  # original payload, for provenance

    def __post_init__(self) -> None:
        if not self.id:
            self.id = f"{self.type}--{uuid.uuid4()}"

    def dedup_key(self) -> str:
        # ids are deterministic per identity, so id is a safe dedup key.
        return self.id

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Indicator(StixObject):
    type: str = "indicator"
    value: str = ""          # the observable, e.g. "evil.example.com"
    ioc_type: str = ""       # domain-name | ipv4-addr | url | file:hashes.'SHA-256'
    pattern: str = ""        # STIX pattern string
    valid_from: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.ioc_type and self.value:
            if not self.pattern:
                self.pattern = f"[{self.ioc_type} = '{self.value}']"
            self.id = stable_id("indicator", self.ioc_type, self.value.lower())


@dataclass
class ThreatActor(StixObject):
    type: str = "threat-actor"
    name: str = ""
    aliases: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.name:
            self.id = stable_id("threat-actor", self.name.lower())


@dataclass
class Report(StixObject):
    type: str = "report"
    name: str = ""
    description: str = ""
    published: str = ""
    url: str = ""
    object_refs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__post_init__()
        ident = self.url or self.name
        if ident:
            self.id = stable_id("report", ident)


@dataclass
class Relationship(StixObject):
    type: str = "relationship"
    relationship_type: str = "related-to"
    source_ref: str = ""
    target_ref: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        self.id = stable_id(
            "relationship", self.relationship_type, self.source_ref, self.target_ref
        )
