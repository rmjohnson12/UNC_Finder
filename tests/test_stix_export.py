import json
import re

from stix2 import parse

from cti_tracker.models import Indicator, Relationship, Report, ThreatActor
from cti_tracker.stix_export import build_bundle, write_bundle
from cti_tracker.store import Store


def _populated_store():
    store = Store(":memory:")
    actor = ThreatActor(name="EXAMPLE-GROUP", aliases=["Example Bear"], source="test")
    indicator = Indicator(
        value="44d88612fea8a8f36de82e1278abb02f",
        ioc_type="file:hashes.MD5",
        labels=[actor.name],
        source="test",
    )
    report = Report(
        name="Example threat report",
        description="A source-backed report.",
        published="Mon, 30 Jun 2026 12:00:00 GMT",
        url="https://example.invalid/report",
        labels=[actor.name],
        object_refs=[indicator.id],
        source="test",
    )
    relationship = Relationship(
        relationship_type="related-to",
        source_ref=report.id,
        target_ref=actor.id,
        labels=[actor.name],
        source="test",
    )
    for obj in (actor, indicator, report, relationship):
        store.upsert(obj)
    return store, actor, indicator, report


def test_build_bundle_produces_valid_stix_21_objects():
    store, actor, indicator, report = _populated_store()
    try:
        bundle = build_bundle(store)
    finally:
        store.close()

    parsed = parse(bundle, allow_custom=False)
    assert parsed.type == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert len(bundle["objects"]) == 4

    by_id = {obj["id"]: obj for obj in bundle["objects"]}
    exported_indicator = by_id[indicator.id]
    assert exported_indicator["spec_version"] == "2.1"
    assert exported_indicator["pattern"] == (
        "[file:hashes.'MD5' = '44d88612fea8a8f36de82e1278abb02f']"
    )
    assert exported_indicator["pattern_type"] == "stix"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T.*\.\d{3}Z", exported_indicator["created"])

    exported_report = by_id[report.id]
    assert exported_report["report_types"] == ["threat-report"]
    assert set(exported_report["object_refs"]) == {actor.id, indicator.id}
    assert exported_report["external_references"][0]["url"] == (
        "https://example.invalid/report"
    )


def test_write_bundle_outputs_parseable_json(tmp_path):
    store, _, _, _ = _populated_store()
    output = tmp_path / "bundle.json"
    try:
        count = write_bundle(store, str(output), pretty=True)
    finally:
        store.close()

    payload = json.loads(output.read_text(encoding="utf-8"))
    parse(payload, allow_custom=False)
    assert count == 4
    assert payload["type"] == "bundle"


def test_empty_store_exports_valid_objectless_bundle():
    store = Store(":memory:")
    try:
        bundle = build_bundle(store)
    finally:
        store.close()

    parse(bundle, allow_custom=False, version="2.1")
    assert "objects" not in bundle
