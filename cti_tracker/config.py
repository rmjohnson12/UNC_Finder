"""Configuration: who we track and where we look.

Actor naming follows Google Threat Intelligence Group (GTIG) plus CERT-UA
aliases. Keep this file as the single source of truth for the actor set so
collectors and correlation logic stay in sync.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Actor:
    primary: str
    aliases: tuple[str, ...] = ()
    note: str = ""

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
    ),
)

# Extra keywords associated with the actors (malware/tooling/themes) used to
# correlate incoming data. Map keyword -> primary actor name.
_EXTRA_KEYWORDS: dict[str, str] = {
    "stalecookie": "UNC4221",
    "pinpoint": "UNC4221",
    "tinywhale": "UNC4221",
    "kropyva": "UNC4221",
}


def actor_keywords() -> dict[str, str]:
    """Lowercase keyword/alias -> primary actor name, for correlation."""
    out: dict[str, str] = {}
    for actor in ACTORS:
        for name in actor.all_names:
            out[name.lower()] = actor.primary
    out.update(_EXTRA_KEYWORDS)
    return out


# --- Source feed configuration -------------------------------------------------
# NOTE: verify these URLs before relying on them; vendors move endpoints.
# The CISA collector falls back to a bundled sample feed if the live fetch
# fails, so the suite always runs end-to-end on first try.
CISA_ADVISORIES_FEED = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
