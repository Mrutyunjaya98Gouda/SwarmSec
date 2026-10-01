"""UTC timestamp helpers for STIX and SwarmSec envelopes.

Aware datetimes already include an offset in ``isoformat()``. Appending a
literal ``Z`` produces invalid values such as ``2026-01-01T00:00:00+00:00Z``.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now_iso() -> str:
    """Return the current UTC time as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return format_utc(datetime.now(timezone.utc))


def format_utc(dt: datetime) -> str:
    """Format a timezone-aware datetime as a Zulu ISO 8601 string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso8601(value: str) -> datetime:
    """Parse an ISO 8601 timestamp, accepting a trailing ``Z``."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
