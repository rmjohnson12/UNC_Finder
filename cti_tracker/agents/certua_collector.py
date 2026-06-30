"""CERT-UA collector for public reports about the configured actor aliases.

The collector queries the same public search/article API used by cert.gov.ua,
downloads only matching published reports, and extracts IOCs from their
explicit indicator sections. It never connects to an extracted IOC.
"""
from __future__ import annotations

import html
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from ..config import ACTORS, CERT_UA_API
from ..ioc import extract_iocs
from ..models import Indicator, Relationship, Report, StixObject, ThreatActor
from ..tagging import tag_text
from .base import AgentContext, CollectorAgent

_IOC_HEADING_RE = re.compile(
    r"(?i)(індикатори кіберзагроз|indicators? of compromise|\biocs?\b)"
)


def _plain_text(value: str) -> str:
    decoded = html.unescape(html.unescape(value or ""))
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", decoded)).strip()


def _published_date(value: str) -> str:
    try:
        return datetime.strptime(value, "%d.%m.%Y").replace(
            tzinfo=timezone.utc
        ).isoformat()
    except ValueError:
        return value


class CERTUACollector(CollectorAgent):
    name = "cert-ua"
    description = "Collects public CERT-UA reports for configured UAC aliases."

    def collect(self, ctx: AgentContext) -> list[StixObject]:
        configured_actors = tuple(ctx.config.get("actors", ACTORS))
        api_base = str(ctx.config.get("certua_api_url", CERT_UA_API)).rstrip("/")
        article_hits: dict[str, set[str]] = {}

        searched_aliases = 0
        for actor in configured_actors:
            for alias in actor.aliases:
                if not alias.upper().startswith("UAC-"):
                    continue
                if searched_aliases:
                    self._pause()
                payload = self._get(
                    f"{api_base}/articles/search",
                    params={"name": alias, "type": 1, "page": 0, "cache_key": alias},
                )
                for article_id in self.parse_search(payload):
                    article_hits.setdefault(article_id, set()).add(actor.primary)
                searched_aliases += 1

        objects: list[StixObject] = []
        emitted_actors: set[str] = set()
        report_count = 0
        indicator_count = 0

        for article_id in article_hits:
            payload = self._get(
                f"{api_base}/articles/byId",
                params={"id": article_id, "cache_key": article_id},
            )
            article = self.parse_article(payload)
            combined = f"{article['title']} {article['description']} {article['text']}"
            actors = tag_text(combined, configured_actors)
            if not actors:
                continue

            indicator_text = self.indicator_section(article["text"])
            indicators = [
                Indicator(
                    value=value,
                    ioc_type=ioc_type,
                    source=self.name,
                    labels=actors,
                    raw={"certua_article_id": article_id},
                )
                for ioc_type, value in extract_iocs(indicator_text)
            ]
            report = Report(
                name=article["title"],
                description=article["description"][:1000],
                published=_published_date(article["date"]),
                url=f"https://cert.gov.ua/article/{article_id}",
                source=self.name,
                labels=actors,
                object_refs=[indicator.id for indicator in indicators],
                raw={"certua_article_id": article_id},
            )
            objects.append(report)
            objects.extend(indicators)
            report_count += 1
            indicator_count += len(indicators)

            for actor_name in actors:
                actor = next(a for a in configured_actors if a.primary == actor_name)
                threat_actor = ThreatActor(
                    name=actor.primary,
                    aliases=list(actor.aliases),
                    source=self.name,
                )
                if actor_name not in emitted_actors:
                    objects.append(threat_actor)
                    emitted_actors.add(actor_name)
                objects.append(
                    Relationship(
                        relationship_type="related-to",
                        source_ref=report.id,
                        target_ref=threat_actor.id,
                        source=self.name,
                        labels=[actor_name],
                    )
                )

        self._run_notes.append(
            f"collected {report_count} report(s) and {indicator_count} indicator(s)"
        )
        return objects

    @staticmethod
    def _pause() -> None:
        """Pace searches; CERT-UA can cache back-to-back query results."""
        time.sleep(1.1)

    def _get(self, url: str, params: dict[str, Any]) -> str:
        import requests

        response = requests.get(
            url,
            params=params,
            headers={"User-Agent": "UNC-Finder/0.1 (passive CTI research)"},
            timeout=30,
        )
        response.raise_for_status()
        return response.text

    @staticmethod
    def parse_search(payload: str) -> list[str]:
        root = ET.fromstring(payload)
        article_ids: list[str] = []
        for item in root.iter("items"):
            article_id = item.findtext("id", "").strip()
            if article_id:
                article_ids.append(article_id)
        return article_ids

    @staticmethod
    def parse_article(payload: str) -> dict[str, str]:
        root = ET.fromstring(payload)
        return {
            "id": root.findtext("id", "").strip(),
            "title": _plain_text(root.findtext("title", "")),
            "description": _plain_text(root.findtext("description", "")),
            "text": _plain_text(root.findtext("text", "")),
            "date": root.findtext("date", "").strip(),
        }

    @staticmethod
    def indicator_section(text: str) -> str:
        match = _IOC_HEADING_RE.search(text)
        return text[match.end() :] if match else ""
