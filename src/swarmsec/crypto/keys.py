"""Ed25519 keypair generation, signing, and verification.

Every pseudonym identity in SwarmSec is an Ed25519 keypair. The registrar
also has its own Ed25519 keypair used to sign credentials.

All signing in the system operates on canonicalized bytes (see
swarmsec.crypto.canonicalize), never on raw JSON strings.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 private/public keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign arbitrary bytes with an Ed25519 private key.

    The caller is responsible for canonicalizing the data before signing.
    Ed25519 signatures are deterministic — same key + same data always
    produces the same 64-byte signature.
    """
    return private_key.sign(data)


def verify(public_key: Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature against a public key.

    Returns True if valid, False if the signature does not match.
    """
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False


def serialize_public_key(public_key: Ed25519PublicKey) -> bytes:
    """Export a public key as raw 32 bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def deserialize_public_key(raw: bytes) -> Ed25519PublicKey:
    """Import a public key from raw 32 bytes."""
    return Ed25519PublicKey.from_public_bytes(raw)


def serialize_private_key(private_key: Ed25519PrivateKey) -> bytes:
    """Export a private key as raw 32 bytes (the seed)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(raw: bytes) -> Ed25519PrivateKey:
    """Import a private key from raw 32 bytes (the seed)."""
    return Ed25519PrivateKey.from_private_bytes(raw)


def save_keypair(
    private_key: Ed25519PrivateKey,
    directory: str | Path,
    *,
    private_name: str = "pseudonym.key",
    public_name: str = "pseudonym.pub",
) -> tuple[Path, Path]:
    """Save a keypair to PEM files in the given directory.

    Returns (private_key_path, public_key_path).
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    priv_path = directory / private_name
    pub_path = directory / public_name

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write private key with restricted permissions
    priv_path.write_bytes(priv_pem)
    os.chmod(priv_path, 0o600)

    pub_path.write_bytes(pub_pem)

    return priv_path, pub_path


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    pem_data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519 private key, got {type(key).__name__}")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""
    pem_data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(pem_data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"Expected Ed25519 public key, got {type(key).__name__}")
    return key
