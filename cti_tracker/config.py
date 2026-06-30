"""Configuration: who we track and where we look.

Actor naming follows Google Threat Intelligence Group (GTIG) plus CERT-UA
aliases. Keep this file as the single source of truth for the actor set so
collectors and correlation logic stay in sync.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Actor:
    primary: str
    aliases: tuple[str, ...] = ()
    note: str = ""
    keywords: tuple[str, ...] = ()

    @property
    def all_names(self) -> tuple[str, ...]:
        return (self.primary, *self.aliases)


# Tracked actors. Sources: GTIG "Signals of Trouble" (Feb 2025), GTIG DIB
# report (Feb 2026), FBI/CISA advisory PSA I-062626-PSA. Verify and expand.
ACTORS: tuple[Actor, ...] = (
    Actor(
        "UNC5792",
        ("UAC-0195",),
        "FSB-linked; abuses Signal device-linking via spoofed group-invite pages.",
    ),
    Actor(
        "UNC4221",
        ("UAC-0185",),
        "Russian military-linked; Signal phishing kit mimicking Kropyva; PINPOINT geolocation payload.",
        ("stalecookie", "pinpoint", "tinywhale", "kropyva"),
    ),
)


def actor_keywords(actors: tuple[Actor, ...] = ACTORS) -> dict[str, str]:
    """Lowercase keyword/alias -> primary actor name, for correlation."""
    out: dict[str, str] = {}
    for actor in actors:
        for name in (*actor.all_names, *actor.keywords):
            out[name.lower()] = actor.primary
    return out


def load_actors(path: str) -> tuple[Actor, ...]:
    """Load an actor catalog from a small JSON profile."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    records = payload.get("actors")
    if not isinstance(records, list) or not records:
        raise ValueError("actor config must contain a non-empty 'actors' list")
    actors: list[Actor] = []
    for record in records:
        if not isinstance(record, dict) or not str(record.get("primary", "")).strip():
            raise ValueError("every actor requires a non-empty 'primary' name")
        actors.append(
            Actor(
                primary=str(record["primary"]).strip(),
                aliases=tuple(str(value).strip() for value in record.get("aliases", [])),
                note=str(record.get("note", "")).strip(),
                keywords=tuple(str(value).strip() for value in record.get("keywords", [])),
            )
        )
    return tuple(actors)


# --- Source feed configuration -------------------------------------------------
# NOTE: verify these URLs before relying on them; vendors move endpoints.
# The CISA collector falls back to a bundled sample feed if the live fetch
# fails, so the suite always runs end-to-end on first try.
CISA_ADVISORIES_FEED = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
CERT_UA_API = "https://cert.gov.ua/api"
