"""Tests for swarmsec.crypto.keys — Ed25519 keypair generation, signing, verification."""

import tempfile
from pathlib import Path

from swarmsec.crypto.keys import (
    deserialize_private_key,
    deserialize_public_key,
    generate_keypair,
    load_private_key,
    load_public_key,
    parse_ed25519_public_key_b64,
    save_keypair,
    serialize_private_key,
    serialize_public_key,
    sign,
    verify,
)


class TestKeypairGeneration:
    """Ed25519 keypair generation produces valid, distinct keys."""

    def test_generate_returns_keypair(self):
        priv, pub = generate_keypair()
        assert priv is not None
        assert pub is not None

    def test_two_keypairs_are_distinct(self):
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        assert serialize_public_key(pub1) != serialize_public_key(pub2)


class TestSignAndVerify:
    """Ed25519 signing and verification round-trip."""

    def test_sign_verify_roundtrip(self):
        priv, pub = generate_keypair()
        data = b"canonical payload bytes"
        sig = sign(priv, data)
        assert verify(pub, data, sig)

    def test_tampered_data_fails_verification(self):
        priv, pub = generate_keypair()
        data = b"original data"
        sig = sign(priv, data)
        assert not verify(pub, b"tampered data", sig)

    def test_tampered_signature_fails_verification(self):
        priv, pub = generate_keypair()
        data = b"some data"
        sig = sign(priv, data)
        tampered_sig = bytearray(sig)
        tampered_sig[0] ^= 0xFF
        assert not verify(pub, data, bytes(tampered_sig))

    def test_wrong_key_fails_verification(self):
        priv1, _ = generate_keypair()
        _, pub2 = generate_keypair()
        data = b"signed by key 1"
        sig = sign(priv1, data)
        assert not verify(pub2, data, sig)

    def test_deterministic_signature(self):
        """Ed25519 signatures are deterministic — same key + data = same sig."""
        priv, _ = generate_keypair()
        data = b"deterministic test"
        sig1 = sign(priv, data)
        sig2 = sign(priv, data)
        assert sig1 == sig2

    def test_signature_is_64_bytes(self):
        priv, _ = generate_keypair()
        sig = sign(priv, b"data")
        assert len(sig) == 64


class TestSerialization:
    """Public key serialization and deserialization."""

    def test_serialize_deserialize_roundtrip(self):
        priv, pub = generate_keypair()
        raw = serialize_public_key(pub)
        assert len(raw) == 32
        restored = deserialize_public_key(raw)
        assert serialize_public_key(restored) == raw

    def test_sign_with_original_verify_with_deserialized(self):
        priv, pub = generate_keypair()
        data = b"cross-check serialization"
        sig = sign(priv, data)
        raw = serialize_public_key(pub)
        restored_pub = deserialize_public_key(raw)
        assert verify(restored_pub, data, sig)

    def test_private_key_serialization(self):
        priv, _ = generate_keypair()
        raw = serialize_private_key(priv)
        assert len(raw) == 32


class TestFileIO:
    """Keypair save/load from PEM files."""

    def test_save_load_roundtrip(self):
        priv, pub = generate_keypair()
        data = b"file IO test"
        sig = sign(priv, data)

        with tempfile.TemporaryDirectory() as tmpdir:
            priv_path, pub_path = save_keypair(priv, tmpdir)

            assert priv_path.exists()
            assert pub_path.exists()

            loaded_priv = load_private_key(priv_path)
            loaded_pub = load_public_key(pub_path)

            # Verify signature made with original key using loaded key
            assert verify(loaded_pub, data, sig)

            # Sign with loaded key, verify with original key
            sig2 = sign(loaded_priv, data)
            assert verify(pub, data, sig2)

    def test_private_key_file_permissions(self):
        """Private key file should have restricted permissions (0o600)."""
        priv, _ = generate_keypair()

        with tempfile.TemporaryDirectory() as tmpdir:
            priv_path, _ = save_keypair(priv, tmpdir)
            mode = priv_path.stat().st_mode & 0o777
            assert mode == 0o600


class TestParseEd25519PublicKeyB64:
    def test_roundtrip(self):
        _, pub = generate_keypair()
        b64 = __import__("base64").b64encode(serialize_public_key(pub)).decode("ascii")
        restored = parse_ed25519_public_key_b64(b64)
        assert serialize_public_key(restored) == serialize_public_key(pub)

    def test_invalid_base64(self):
        import pytest

        with pytest.raises(ValueError):
            parse_ed25519_public_key_b64("%%%not-base64%%%")

    def test_wrong_length(self):
        import pytest
        import base64

        with pytest.raises(ValueError):
            parse_ed25519_public_key_b64(base64.b64encode(b"short").decode("ascii"))

    def test_deserialize_private_key_roundtrip(self):
        priv, pub = generate_keypair()
        restored = deserialize_private_key(serialize_private_key(priv))
        data = b"raw private key"
        assert verify(pub, data, sign(restored, data))
