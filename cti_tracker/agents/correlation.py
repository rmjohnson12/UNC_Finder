"""Evidence-based correlation over stored passive enrichment notes."""
from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from typing import Any

from ..models import Relationship, StixObject
from .base import AgentContext, CollectorAgent


class CorrelationAgent(CollectorAgent):
    name = "correlation"
    description = "Links indicators that share certificate or registration evidence."

    def collect(self, ctx: AgentContext) -> list[StixObject]:
        evidence: dict[tuple[str, str], set[str]] = defaultdict(set)
        labels: dict[str, set[str]] = defaultdict(set)
        for note in ctx.store.all_of_type("note"):
            raw = note.get("raw") or {}
            if raw.get("kind") != "passive-enrichment":
                continue
            target = str(raw.get("target_ref", ""))
            if not target:
                continue
            labels[target].update(
                label for label in note.get("labels", []) if label != "passive-enrichment"
            )
            providers: dict[str, Any] = raw.get("providers") or {}
            for certificate_id in providers.get("crt.sh", {}).get("certificate_ids", []):
                evidence[("shared-certificate", str(certificate_id))].add(target)
            rdap = providers.get("rdap", {})
            for handle in rdap.get("entity_handles", []):
                evidence[("shared-registrant", str(handle))].add(target)
            if rdap.get("network_handle"):
                evidence[("shared-network", str(rdap["network_handle"]))].add(target)

        pair_reasons: dict[tuple[str, str], set[str]] = defaultdict(set)
        for (kind, value), targets in evidence.items():
            for left, right in combinations(sorted(targets), 2):
                pair_reasons[(left, right)].add(f"{kind}:{value}")

        relationships: list[StixObject] = []
        for (left, right), reasons in sorted(pair_reasons.items()):
            relationships.append(
                Relationship(
                    relationship_type="related-to",
                    source_ref=left,
                    target_ref=right,
                    source=self.name,
                    labels=sorted(labels[left] | labels[right]),
                    raw={"correlation_evidence": sorted(reasons)[:50]},
                )
            )
        self._run_notes.append(f"created {len(relationships)} evidence-backed link(s)")
        return relationships
