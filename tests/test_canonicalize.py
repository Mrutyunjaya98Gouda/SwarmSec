"""Tests for swarmsec.crypto.canonicalize — RFC 8785 JSON Canonicalization."""

from swarmsec.crypto.canonicalize import canonicalize
from swarmsec.crypto.keys import generate_keypair, sign, verify


class TestCanonicalizeDeterminism:
    """Same logical object always produces identical canonical bytes."""

    def test_key_order_irrelevant(self):
        """Different insertion order for the same keys → same canonical output."""
        obj_a = {"zebra": 1, "alpha": 2, "middle": 3}
        obj_b = {"alpha": 2, "middle": 3, "zebra": 1}
        assert canonicalize(obj_a) == canonicalize(obj_b)

    def test_nested_key_order_irrelevant(self):
        obj_a = {"outer": {"z": 1, "a": 2}}
        obj_b = {"outer": {"a": 2, "z": 1}}
        assert canonicalize(obj_a) == canonicalize(obj_b)

    def test_identical_input_identical_output(self):
        obj = {"key": "value", "number": 42}
        assert canonicalize(obj) == canonicalize(obj)


class TestCanonicalizeFormat:
    """Output is valid UTF-8 JSON with no insignificant whitespace."""

    def test_output_is_bytes(self):
        result = canonicalize({"a": 1})
        assert isinstance(result, bytes)

    def test_output_is_valid_utf8(self):
        result = canonicalize({"emoji": "🔐", "text": "hello"})
        decoded = result.decode("utf-8")
        assert "emoji" in decoded

    def test_no_trailing_whitespace(self):
        result = canonicalize({"key": "value"})
        assert not result.endswith(b" ")
        assert not result.endswith(b"\n")

    def test_no_spaces_around_separators(self):
        """RFC 8785: no spaces after ':' or ','."""
        result = canonicalize({"a": 1, "b": 2})
        decoded = result.decode("utf-8")
        assert ": " not in decoded
        assert ", " not in decoded


class TestCanonicalizeWithSigning:
    """Canonicalization integrates correctly with Ed25519 signing.

    This is the critical integration test — it proves that signing the
    canonical form and verifying against the same canonical form works,
    and that signing canonical but verifying non-canonical fails (which
    is the exact bug RFC 8785 prevents).
    """

    def test_sign_canonical_verify_canonical(self):
        priv, pub = generate_keypair()
        obj = {"z_last": "value", "a_first": "value"}
        canonical_bytes = canonicalize(obj)
        sig = sign(priv, canonical_bytes)
        assert verify(pub, canonical_bytes, sig)

    def test_sign_canonical_verify_non_canonical_fails(self):
        """This is the bug that RFC 8785 exists to prevent.

        Two different JSON serializations of the same logical object
        would produce different bytes, causing signature verification
        to fail. By always canonicalizing first, this never happens
        in the real system — but this test proves *why* it's necessary.
        """
        priv, pub = generate_keypair()
        obj = {"b": 2, "a": 1}
        canonical_bytes = canonicalize(obj)
        sig = sign(priv, canonical_bytes)

        # A non-canonical serialization of the same object
        import json
        non_canonical = json.dumps(obj, sort_keys=False).encode("utf-8")

        # If canonical == non_canonical, the test is meaningless —
        # the objects must differ in byte representation
        if canonical_bytes != non_canonical:
            assert not verify(pub, non_canonical, sig)

    def test_different_key_order_same_signature(self):
        """Two dicts with the same data but different key order produce
        the same canonical bytes, and therefore the same signature."""
        priv, pub = generate_keypair()
        obj_a = {"z": 1, "a": 2}
        obj_b = {"a": 2, "z": 1}
        sig_a = sign(priv, canonicalize(obj_a))
        sig_b = sign(priv, canonicalize(obj_b))
        assert sig_a == sig_b  # Ed25519 is deterministic
