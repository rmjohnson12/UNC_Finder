import argparse

import pytest

from cti_tracker.cli import parse_since


def test_parse_since_normalizes_to_utc():
    assert parse_since("2026-06-01T01:00:00+01:00") == "2026-06-01T00:00:00+00:00"


def test_parse_since_rejects_non_timestamp():
    with pytest.raises(argparse.ArgumentTypeError):
        parse_since("yesterday")
