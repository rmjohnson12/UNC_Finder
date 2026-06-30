"""Correlation: tag free text to tracked actors by keyword match.

Phase 1 uses simple substring matching against the keyword set in config.
This is deliberately dumb and easy to reason about. Phase 3/5 can replace or
augment this with infrastructure pivoting and LLM-assisted entity extraction.
"""
from __future__ import annotations

from .config import ACTORS, Actor, actor_keywords


def tag_text(text: str, actors: tuple[Actor, ...] = ACTORS) -> list[str]:
    """Return sorted primary actor names whose keywords appear in `text`."""
    lowered = (text or "").lower()
    hits = {actor for kw, actor in actor_keywords(actors).items() if kw in lowered}
    return sorted(hits)
