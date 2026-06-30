"""ThreatFox collector — EXAMPLE of a keyed IOC source.

abuse.ch ThreatFox returns structured IOCs (domains, IPs, URLs, hashes). It
requires a free Auth-Key. Without a key this collector cleanly skips, so the
suite still runs. Use this file as the template for any keyed source
(AlienVault OTX, VirusTotal, urlscan, ...).

Flow: query recent IOCs -> keep rows whose tags/malware match a tracked actor
keyword -> emit Indicator objects. Phase 1 keeps the query broad and filters
client-side; refine the query once you confirm ThreatFox tag coverage.
"""
from __future__ import annotations

import os

from ..config import ACTORS, THREATFOX_API, actor_keywords
from ..models import Indicator
from ..tagging import tag_text
from .base import AgentContext, CollectorAgent

# ThreatFox ioc_type -> STIX-ish pattern type
_TYPE_MAP = {
    "domain": "domain-name",
    "ip:port": "ipv4-addr",
    "url": "url",
    "sha256_hash": "file:hashes.'SHA-256'",
    "md5_hash": "file:hashes.MD5",
}


class ThreatFoxCollector(CollectorAgent):
    name = "threatfox"
    description = "Queries abuse.ch ThreatFox for IOCs (requires free Auth-Key)."

    def collect(self, ctx: AgentContext):
        api_key = os.getenv("THREATFOX_API_KEY") or ctx.config.get("threatfox_api_key")
        if not api_key:
            self._run_notes.append(
                "skipped: set THREATFOX_API_KEY to enable (see .env.example)"
            )
            return []

        import requests  # imported lazily so the suite runs without it installed

        resp = requests.post(
            THREATFOX_API,
            json={"query": "get_iocs", "days": 7},
            headers={"Auth-Key": api_key},
            timeout=30,
        )
        resp.raise_for_status()
        rows = (resp.json() or {}).get("data") or []

        actors = tuple(ctx.config.get("actors", ACTORS))
        wanted = set(actor_keywords(actors))
        objects: list = []
        for row in rows:
            tags = [str(t).lower() for t in (row.get("tags") or [])]
            blob = " ".join(
                tags + [str(row.get("malware_printable", "")), str(row.get("ioc", ""))]
            ).lower()
            if not any(w in blob for w in wanted):
                continue
            ioc_type = _TYPE_MAP.get(row.get("ioc_type", ""))
            if not ioc_type:
                continue
            objects.append(
                Indicator(
                    value=str(row.get("ioc", "")),
                    ioc_type=ioc_type,
                    source=self.name,
                    labels=tag_text(blob, actors),
                    raw=row,
                )
            )

        self._run_notes.append(f"matched {len(objects)} actor-relevant IOC(s)")
        return objects
