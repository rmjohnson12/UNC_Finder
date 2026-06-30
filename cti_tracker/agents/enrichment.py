"""Bounded passive enrichment through third-party CT and RDAP services."""
from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import quote

from ..models import Note, StixObject
from .base import AgentContext, CollectorAgent


class EnrichmentAgent(CollectorAgent):
    name = "passive-enrichment"
    description = "Enriches stored domains/IPs via crt.sh and RDAP.org only."

    def collect(self, ctx: AgentContext) -> list[StixObject]:
        limit = max(0, int(ctx.config.get("enrichment_limit", 3)))
        if limit == 0:
            self._run_notes.append("skipped: enrichment_limit is 0")
            return []

        candidates = [
            item
            for item in ctx.store.all_of_type("indicator")
            if item.get("ioc_type") in {"domain-name", "ipv4-addr"}
        ]
        notes: list[StixObject] = []
        requests_made = 0
        attempted = 0
        for item in candidates:
            note = self._note(item, {})
            if ctx.store.contains(note.id):
                continue
            attempted += 1
            providers: dict[str, Any] = {}
            try:
                if requests_made:
                    self._pause()
                requests_made += 1
                providers["rdap"] = self._rdap(str(item["ioc_type"]), str(item["value"]))
            except Exception as exc:  # one provider must not cancel the run
                self._run_notes.append(f"RDAP {item['value']}: {type(exc).__name__}")
            if item.get("ioc_type") == "domain-name":
                try:
                    if requests_made:
                        self._pause()
                    requests_made += 1
                    providers["crt.sh"] = self._crtsh(str(item["value"]))
                except Exception as exc:
                    self._run_notes.append(f"crt.sh {item['value']}: {type(exc).__name__}")
            if providers:
                notes.append(self._note(item, providers))
            if attempted >= limit:
                break

        self._run_notes.append(f"enriched {len(notes)} indicator(s) with {requests_made} request(s)")
        return notes

    def _rdap(self, ioc_type: str, value: str) -> dict[str, Any]:
        resource_type = "domain" if ioc_type == "domain-name" else "ip"
        payload = self._get_json(f"https://rdap.org/{resource_type}/{quote(value, safe='')}")
        entities = payload.get("entities") or []
        return {
            "handle": payload.get("handle"),
            "name": payload.get("name") or payload.get("ldhName"),
            "country": payload.get("country"),
            "network_handle": payload.get("handle") if resource_type == "ip" else None,
            "entity_handles": sorted(
                {
                    str(entity.get("handle"))
                    for entity in entities
                    if entity.get("handle") and "registrant" in (entity.get("roles") or [])
                }
            ),
        }

    def _crtsh(self, domain: str) -> dict[str, Any]:
        rows = self._get_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
        if not isinstance(rows, list):
            return {"certificate_ids": [], "names": []}
        return {
            "certificate_ids": sorted({str(row["id"]) for row in rows if row.get("id")})[:100],
            "names": sorted(
                {
                    name.strip().lower()
                    for row in rows
                    for name in str(row.get("name_value", "")).splitlines()
                    if name.strip()
                }
            )[:100],
        }

    def _get_json(self, url: str, params: dict[str, str] | None = None) -> Any:
        import requests

        response = requests.get(
            url,
            params=params,
            headers={"User-Agent": "UNC-Finder/0.2 (passive CTI research)"},
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _pause() -> None:
        time.sleep(1.1)

    def _note(self, indicator: dict[str, Any], providers: dict[str, Any]) -> Note:
        value = str(indicator["value"])
        return Note(
            abstract=f"Passive enrichment for {value}",
            content=json.dumps(providers, sort_keys=True),
            object_refs=[str(indicator["id"])],
            source=self.name,
            labels=sorted(set(indicator.get("labels", [])) | {"passive-enrichment"}),
            raw={
                "kind": "passive-enrichment",
                "target_ref": indicator["id"],
                "value": value,
                "ioc_type": indicator["ioc_type"],
                "providers": providers,
            },
        )
