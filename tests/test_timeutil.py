"""Tests for UTC ISO-8601 formatting used in credentials and envelopes."""

from datetime import datetime, timezone

from swarmsec.crypto.timeutil import format_utc, parse_iso8601, utc_now_iso


def test_format_utc_uses_zulu_not_offset_plus_z():
    dt = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert format_utc(dt) == "2026-01-02T03:04:05Z"
    assert not format_utc(dt).endswith("+00:00Z")


def test_utc_now_iso_is_parseable():
    stamp = utc_now_iso()
    parsed = parse_iso8601(stamp)
    assert parsed.tzinfo is not None
    assert stamp.endswith("Z")


def test_isoformat_plus_z_is_invalid_and_not_produced():
    naive_bug = datetime.now(timezone.utc).isoformat() + "Z"
    assert naive_bug.endswith("+00:00Z") or naive_bug.endswith("Z")
    good = utc_now_iso()
    assert "+00:00Z" not in good
