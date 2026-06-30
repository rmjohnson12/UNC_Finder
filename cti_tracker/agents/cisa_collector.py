"""CISA advisories collector — the working Phase 1 collector (no API key).

Pulls the CISA cybersecurity advisories feed, keeps only entries that mention a
tracked actor (or associated tooling), and emits Report + Relationship objects
plus the ThreatActor objects they point at.

Robustness: if the live feed can't be fetched or is empty, it falls back to a
bundled sample feed so the suite always produces output on first run. Replace
the feed URL via config `cisa_feed_url` once you've verified the live endpoint.
"""
from __future__ import annotations

from pathlib import Path

import feedparser

from ..config import ACTORS, CISA_ADVISORIES_FEED
from ..models import Relationship, Report, ThreatActor
from ..tagging import tag_text
from .base import AgentContext, CollectorAgent

_SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_cisa_feed.xml"


class CISAAdvisoryCollector(CollectorAgent):
    name = "cisa-advisories"
    description = (
        "Pulls CISA cybersecurity advisories (RSS/Atom) relevant to tracked actors."
    )

    def collect(self, ctx: AgentContext):
        feed_url = ctx.config.get("cisa_feed_url", CISA_ADVISORIES_FEED)
        feed = self._load(feed_url)

        objects: list = []

        # Emit the tracked actors so relationships have valid targets. Stable
        # ids mean these upsert as "seen" on later runs rather than duplicate.
        actor_id = {}
        for actor in ACTORS:
            ta = ThreatActor(
                name=actor.primary, aliases=list(actor.aliases), source=self.name
            )
            actor_id[actor.primary] = ta.id
            objects.append(ta)

        kept = 0
        for entry in getattr(feed, "entries", []):
            title = getattr(entry, "title", "")
            summary = getattr(entry, "summary", "")
            link = getattr(entry, "link", "")
            published = getattr(entry, "published", "") or getattr(entry, "updated", "")

            actors_hit = tag_text(f"{title} {summary}")
            if not actors_hit:
                continue  # Phase 1: keep only actor-relevant advisories
            kept += 1

            report = Report(
                name=title,
                description=summary[:1000],
                published=published,
                url=link,
                source=self.name,
                labels=actors_hit,
                raw={"title": title, "link": link},
            )
            objects.append(report)
            for actor in actors_hit:
                objects.append(
                    Relationship(
                        relationship_type="related-to",
                        source_ref=report.id,
                        target_ref=actor_id.get(actor, actor),
                        source=self.name,
                        labels=[actor],
                    )
                )

        self._run_notes.append(f"kept {kept} actor-relevant advisory(ies)")
        return objects

    def _load(self, feed_url: str):
        try:
            feed = feedparser.parse(feed_url)
            if getattr(feed, "entries", None):
                self._run_notes.append(
                    f"loaded {len(feed.entries)} entries from live feed"
                )
                return feed
        except Exception as exc:  # noqa: BLE001
            self._run_notes.append(f"live fetch error: {type(exc).__name__}: {exc}")
        # Fallback keeps the skeleton runnable end-to-end.
        self._run_notes.append(
            "FELL BACK to bundled sample feed — verify cisa_feed_url in config.py"
        )
        return feedparser.parse(str(_SAMPLE))
