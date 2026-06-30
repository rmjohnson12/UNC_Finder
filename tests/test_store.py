import os
import tempfile

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
