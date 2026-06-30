"""Evidence-grounded analyst with an optional Anthropic Messages API call."""
from __future__ import annotations

import os
import json
from typing import Any

from .base import Agent, AgentContext, AgentResult


class AnalystAgent(Agent):
    name = "analyst"
    description = "Summarizes stored evidence and optionally drafts cited LLM analysis."

    def run(self, ctx: AgentContext) -> AgentResult:
        result = AgentResult(agent=self.name)
        counts = ctx.store.counts_by_type()
        summary = ", ".join(f"{k}={v}" for k, v in counts.items()) or "empty"
        result.notes.append(f"store contents: {summary}")
        api_key = os.getenv("ANTHROPIC_API_KEY") or ctx.config.get("anthropic_api_key")
        model = os.getenv("ANTHROPIC_MODEL") or ctx.config.get("anthropic_model")
        if not api_key or not model:
            result.notes.append(
                "LLM skipped: set ANTHROPIC_API_KEY and ANTHROPIC_MODEL to enable cited analysis"
            )
            return result
        try:
            text = self._analyze(str(api_key), str(model), self._evidence(ctx))
            result.notes.append(f"LLM draft (verify before use):\n{text}")
        except Exception as exc:
            result.errors.append(f"LLM analysis failed: {type(exc).__name__}: {exc}")
        return result

    def _evidence(self, ctx: AgentContext) -> dict[str, Any]:
        reports = ctx.store.paged(25, stix_type="report")
        indicators = ctx.store.paged(50, stix_type="indicator")
        notes = ctx.store.paged(25, stix_type="note")
        relationships = ctx.store.paged(50, stix_type="relationship")
        return {
            "reports": [
                {
                    "name": item.get("name"),
                    "description": item.get("description"),
                    "published": item.get("published"),
                    "url": item.get("url"),
                    "actors": item.get("labels", []),
                }
                for item in reports
            ],
            "indicators": [
                {
                    "value": item.get("value"),
                    "type": item.get("ioc_type"),
                    "actors": item.get("labels", []),
                    "source": item.get("source"),
                }
                for item in indicators
            ],
            "enrichment": [
                {
                    "abstract": item.get("abstract"),
                    "content": item.get("content"),
                    "object_refs": item.get("object_refs", []),
                }
                for item in notes
                if (item.get("raw") or {}).get("kind") == "passive-enrichment"
            ],
            "correlations": [
                {
                    "source_ref": item.get("source_ref"),
                    "target_ref": item.get("target_ref"),
                    "evidence": (item.get("raw") or {}).get("correlation_evidence", []),
                }
                for item in relationships
                if item.get("source") == "correlation"
            ],
        }

    def _analyze(self, api_key: str, model: str, evidence: dict[str, Any]) -> str:
        import requests

        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "content-type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": model,
                "max_tokens": 1200,
                "system": (
                    "You are a defensive CTI analyst. Use only the supplied evidence. "
                    "Cite report URLs for factual claims, distinguish source claims from "
                    "inference, state gaps, and propose passive collection pivots only. "
                    "Never claim attribution beyond the cited sources."
                ),
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Draft a concise intelligence summary with sections: Findings, "
                            "Evidence, Correlations, Gaps, and Passive Next Pivots. Evidence:\n"
                            f"{json.dumps(evidence, ensure_ascii=False, sort_keys=True)}"
                        ),
                    }
                ],
            },
            timeout=90,
        )
        response.raise_for_status()
        payload = response.json()
        blocks = payload.get("content") or []
        text = "\n".join(str(block.get("text", "")) for block in blocks if block.get("type") == "text")
        if not text.strip():
            raise ValueError("Anthropic response contained no text")
        return text.strip()
