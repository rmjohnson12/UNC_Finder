import os
import tempfile
from datetime import datetime, timedelta, timezone

from cti_tracker.models import Indicator
from cti_tracker.store import Store


def _store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return Store(path), path


def test_upsert_new_then_seen():
    store, path = _store()
    try:
        ind = Indicator(value="evil.example.com", ioc_type="domain-name", source="test")
        assert store.upsert(ind) is True   # first time -> new
        assert store.upsert(ind) is False  # second time -> seen, not duplicated
        assert store.counts_by_type().get("indicator") == 1
    finally:
        store.close()
        os.unlink(path)


def test_times_seen_increments():
    store, path = _store()
    try:
        ind = Indicator(value="1.2.3.4", ioc_type="ipv4-addr", source="test")
        store.upsert(ind)
        store.upsert(ind)
        store.upsert(ind)
        rows = store.recent()
        assert rows[0]["_times_seen"] == 3
    finally:
        store.close()
        os.unlink(path)


def test_changed_since_distinguishes_new_and_reseen():
    store, path = _store()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=1)
        new_indicator = Indicator(value="new.example", ioc_type="domain-name")
        old_indicator = Indicator(value="old.example", ioc_type="domain-name")
        store.upsert(new_indicator)
        store.upsert(old_indicator)
        store.conn.execute(
            "UPDATE objects SET first_seen = ? WHERE id = ?",
            ((cutoff - timedelta(days=1)).isoformat(), old_indicator.id),
        )
        store.conn.commit()

        changes = store.changed_since(cutoff.isoformat())
        by_value = {item["value"]: item["_change"] for item in changes}
        assert by_value == {"new.example": "new", "old.example": "re-seen"}
        assert store.change_counts_since(cutoff.isoformat()) == (1, 1)
    finally:
        store.close()
        os.unlink(path)


def test_all_returns_every_object_in_stable_order():
    store, path = _store()
    try:
        store.upsert(Indicator(value="b.example", ioc_type="domain-name"))
        store.upsert(Indicator(value="a.example", ioc_type="domain-name"))
        rows = store.all()
        assert len(rows) == 2
        assert [row["id"] for row in rows] == sorted(row["id"] for row in rows)
    finally:
        store.close()
        os.unlink(path)


def test_paged_and_count_support_type_filters():
    store, path = _store()
    try:
        for value in ("a.example", "b.example", "c.example"):
            store.upsert(Indicator(value=value, ioc_type="domain-name"))
        assert store.count() == 3
        assert store.count("indicator") == 3
        assert len(store.paged(limit=2, offset=0)) == 2
        assert len(store.paged(limit=2, offset=2)) == 1
        assert store.paged(stix_type="report") == []
    finally:
        store.close()
        os.unlink(path)
