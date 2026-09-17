"""RFC 8785 JSON Canonicalization Scheme (JCS).

Every signature in SwarmSec signs the canonicalized form of a dict/object,
never the raw JSON string. This prevents signature-verification failures
caused by two serializations of the same object differing in key order,
whitespace, or number formatting.

AGENTS.md hard constraint:
    "Canonicalize before signing, always — RFC 8785 JSON Canonicalization
     on the envelope before Ed25519 signing. Not optional."
"""

from __future__ import annotations

from typing import Any

import jcs


def canonicalize(obj: dict[str, Any] | list[Any]) -> bytes:
    """Produce deterministic canonical bytes for the given object per RFC 8785.

    The output is valid UTF-8 JSON with:
    - Sorted keys (lexicographic by Unicode code point)
    - No insignificant whitespace
    - Deterministic number formatting
    - Deterministic Unicode escaping

    This is the ONLY function that should be used to prepare data for signing
    or hash-chaining anywhere in the system.
    """
    return jcs.canonicalize(obj)
