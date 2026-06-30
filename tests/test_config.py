import json

from cti_tracker.config import Actor, load_actors
from cti_tracker.tagging import tag_text


def test_load_custom_actor_catalog(tmp_path):
    path = tmp_path / "actors.json"
    path.write_text(
        json.dumps(
            {
                "actors": [
                    {
                        "primary": "EXAMPLE-GROUP",
                        "aliases": ["Example Bear"],
                        "keywords": ["ExampleWare"],
                        "note": "Test actor",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    actors = load_actors(str(path))
    assert actors == (
        Actor(
            "EXAMPLE-GROUP",
            ("Example Bear",),
            "Test actor",
            ("ExampleWare",),
        ),
    )
    assert tag_text("ExampleWare campaign", actors) == ["EXAMPLE-GROUP"]


def test_load_custom_actor_catalog_requires_records(tmp_path):
    path = tmp_path / "actors.json"
    path.write_text('{"actors": []}', encoding="utf-8")

    try:
        load_actors(str(path))
    except ValueError as exc:
        assert "non-empty" in str(exc)
    else:
        raise AssertionError("empty actor catalog should fail")
