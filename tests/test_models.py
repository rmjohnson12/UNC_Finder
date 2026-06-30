from cti_tracker.models import Indicator, Report, ThreatActor
from cti_tracker.tagging import tag_text


def test_stable_ids_are_deterministic():
    a = Indicator(value="Evil.Example.com", ioc_type="domain-name")
    b = Indicator(value="evil.example.com", ioc_type="domain-name")
    # case-insensitive identity -> same id -> dedups correctly
    assert a.id == b.id


def test_indicator_builds_pattern():
    ind = Indicator(value="evil.example.com", ioc_type="domain-name")
    assert ind.pattern == "[domain-name = 'evil.example.com']"


def test_report_id_keys_on_url():
    r1 = Report(name="A", url="https://x.invalid/a")
    r2 = Report(name="B different title", url="https://x.invalid/a")
    assert r1.id == r2.id  # same advisory URL -> same object


def test_tagging_matches_aliases_and_tooling():
    assert tag_text("phishing attributed to UAC-0195") == ["UNC5792"]
    assert "UNC4221" in tag_text("PINPOINT payload seen alongside Kropyva lure")
    assert tag_text("unrelated ransomware note") == []


def test_threat_actor_id_stable():
    assert ThreatActor(name="UNC5792").id == ThreatActor(name="unc5792").id
