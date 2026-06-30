from cti_tracker.models import Report
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
