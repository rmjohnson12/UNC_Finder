"""Persistence layer: a thin SQLite store.

One table holds every object as JSON keyed by its dedup_key. Upsert bumps
last_seen / times_seen instead of duplicating, which gives you free "this
indicator reappeared" tracking over time.

Swap this out for OpenCTI/MISP later by writing an alternate Store with the
same interface; nothing else in the suite needs to change.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from .models import StixObject

DEFAULT_DB = "cti_tracker.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
    dedup_key  TEXT PRIMARY KEY,
    id         TEXT NOT NULL,
    type       TEXT NOT NULL,
    source     TEXT,
    json       TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_objects_type ON objects(type);
CREATE INDEX IF NOT EXISTS idx_objects_source ON objects(source);
"""


class Store:
    def __init__(self, path: str = DEFAULT_DB) -> None:
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def upsert(self, obj: StixObject) -> bool:
        """Insert if new, else bump last_seen/times_seen.

        Returns True if newly inserted, False if already known.
        """
        key = obj.dedup_key()
        now = datetime.now(timezone.utc).isoformat()
        row = self.conn.execute(
            "SELECT 1 FROM objects WHERE dedup_key = ?", (key,)
        ).fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO objects "
                "(dedup_key, id, type, source, json, first_seen, last_seen, times_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (key, obj.id, obj.type, obj.source, json.dumps(obj.to_dict()), now, now),
            )
            self.conn.commit()
            return True
        self.conn.execute(
            "UPDATE objects SET last_seen = ?, times_seen = times_seen + 1 "
            "WHERE dedup_key = ?",
            (now, key),
        )
        self.conn.commit()
        return False

    def counts_by_type(self) -> dict[str, int]:
        cur = self.conn.execute(
            "SELECT type, COUNT(*) AS c FROM objects GROUP BY type ORDER BY type"
        )
        return {r["type"]: r["c"] for r in cur.fetchall()}

    def recent(self, limit: int = 20) -> list[dict]:
        cur = self.conn.execute(
            "SELECT json, first_seen, last_seen, times_seen "
            "FROM objects ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        )
        out: list[dict] = []
        for r in cur.fetchall():
            d = json.loads(r["json"])
            d["_first_seen"] = r["first_seen"]
            d["_last_seen"] = r["last_seen"]
            d["_times_seen"] = r["times_seen"]
            out.append(d)
        return out

    def all_of_type(self, stix_type: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT json FROM objects WHERE type = ?", (stix_type,)
        )
        return [json.loads(r["json"]) for r in cur.fetchall()]

    def close(self) -> None:
        self.conn.close()
