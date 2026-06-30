from cti_tracker.agents.base import AgentContext
from cti_tracker.agents.certua_collector import CERTUACollector
from cti_tracker.store import Store

_SEARCH_HIT = """
<SearchResponseArticleRecommendationDTO>
  <items><items><id>6281632</id><title>UAC-0185 report</title></items></items>
</SearchResponseArticleRecommendationDTO>
"""
_SEARCH_EMPTY = "<SearchResponseArticleRecommendationDTO><items/></SearchResponseArticleRecommendationDTO>"
_ARTICLE = """
<FullArticleDTO>
  <id>6281632</id>
  <title>UAC-0185 activity associated with UNC4221</title>
  <description>&lt;p&gt;Published CERT-UA report.&lt;/p&gt;</description>
  <text>&lt;p&gt;Overview with benign.example&lt;/p&gt;
    &lt;p&gt;Indicators of compromise&lt;/p&gt;
    &lt;pre&gt;hxxps://bad[.]example/path 192[.]0[.]2[.]4
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&lt;/pre&gt;
  </text>
  <date>07.12.2024</date>
</FullArticleDTO>
"""


def test_certua_collector_maps_reports_and_indicator_section(monkeypatch):
    collector = CERTUACollector()

    def fake_get(url, params):
        if url.endswith("/articles/search"):
            return _SEARCH_HIT if params["name"] == "UAC-0185" else _SEARCH_EMPTY
        return _ARTICLE

    monkeypatch.setattr(collector, "_get", fake_get)
    monkeypatch.setattr(collector, "_pause", lambda: None)
    store = Store(":memory:")
    try:
        objects = collector.collect(AgentContext(store=store))
    finally:
        store.close()

    reports = [obj for obj in objects if obj.type == "report"]
    indicators = [obj for obj in objects if obj.type == "indicator"]
    assert len(reports) == 1
    assert reports[0].labels == ["UNC4221"]
    assert reports[0].published == "2024-12-07T00:00:00+00:00"
    assert {indicator.value for indicator in indicators} >= {
        "https://bad.example/path",
        "bad.example",
        "192.0.2.4",
        "a" * 64,
    }
    assert "benign.example" not in {indicator.value for indicator in indicators}
    assert set(reports[0].object_refs) == {indicator.id for indicator in indicators}


def test_certua_parsers_handle_empty_search():
    assert CERTUACollector.parse_search(_SEARCH_EMPTY) == []
