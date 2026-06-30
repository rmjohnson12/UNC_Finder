from cti_tracker.models import Indicator, Report
from cti_tracker.store import Store
from cti_tracker.web import render_dashboard


def test_dashboard_renders_counts_and_escapes_source_content():
    store = Store(":memory:")
    try:
        store.upsert(
            Report(
                name="<script>alert(1)</script>",
                url="https://example.invalid/report",
                labels=["EXAMPLE-GROUP"],
            )
        )
        page = render_dashboard(store)
    finally:
        store.close()

    assert "UNC Finder CTI Dashboard" in page
    assert "EXAMPLE-GROUP" in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<script>alert(1)</script>" not in page


def test_dashboard_pagination_makes_every_object_reachable():
    store = Store(":memory:")
    try:
        for index in range(105):
            store.upsert(Indicator(value=f"host-{index}.example", ioc_type="domain-name"))
        second_page = render_dashboard(store, page=2)
    finally:
        store.close()

    assert "Showing 101–105 of 105" in second_page
    assert "page 2 of 2" in second_page
    assert "← previous" in second_page
