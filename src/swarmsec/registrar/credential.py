"""Credential issuance, verification, and status management.

The registrar issues credentials by signing the canonical form of a
credential's signable fields with its Ed25519 key. Any peer can verify
a credential offline using the registrar's public key.

Per AGENTS.md: the registrar knows the org-to-pseudonym mapping and
signs with ordinary Ed25519. No blind signatures.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from swarmsec.crypto.canonicalize import canonicalize
from swarmsec.crypto.keys import sign, verify
from swarmsec.registrar.models import (
    Credential,
    CredentialStatusUpdate,
)

# Default credential validity: 365 days
DEFAULT_VALIDITY_DAYS = 365


def issue_credential(
    pseudonym_public_key_b64: str,
    registrar_private_key: Ed25519PrivateKey,
    *,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
) -> Credential:
    """Issue a new credential for a pseudonym public key.

    Creates a Credential, canonicalizes its signable fields per RFC 8785,
    and signs the canonical bytes with the registrar's Ed25519 key.

    Args:
        pseudonym_public_key_b64: Base64-encoded raw 32-byte Ed25519 public key.
        registrar_private_key: The registrar's Ed25519 signing key.
        validity_days: How long the credential is valid (default 365 days).

    Returns:
        A signed Credential.
    """
    now = datetime.now(UTC)
    expires = now + timedelta(days=validity_days)

    cred = Credential(
        pseudonym_public_key=pseudonym_public_key_b64,
        status="active",
        issued_at=now.isoformat(),
        expires_at=expires.isoformat(),
    )

    # Canonicalize the signable fields, then sign
    canonical_bytes = canonicalize(cred.signable_fields())
    signature = sign(registrar_private_key, canonical_bytes)
    cred.registrar_signatures.append(base64.b64encode(signature).decode("ascii"))

    return cred


def verify_credential(
    credential: Credential,
    registrar_public_keys: list[Ed25519PublicKey],
) -> bool:
    """Verify that a credential's signatures are valid (2-of-3 threshold).

    Args:
        credential: The credential to verify.
        registrar_public_keys: The registrar's 3 Ed25519 public keys.

    Returns:
        True if the signatures are valid and meet threshold, False otherwise.
    """
    if len(credential.registrar_signatures) < 2:
        return False

    canonical_bytes = canonicalize(credential.signable_fields())
    
    valid_sigs = 0
    for sig_b64 in credential.registrar_signatures:
        try:
            signature = base64.b64decode(sig_b64)
            for pub in registrar_public_keys:
                if verify(pub, canonical_bytes, signature):
                    valid_sigs += 1
                    break
        except Exception:
            pass
            
    return valid_sigs >= 2


def update_status(
    credential_id: str,
    new_status: str,
    registrar_private_key: Ed25519PrivateKey,
) -> CredentialStatusUpdate:
    """Create a signed status update for an existing credential.

    Args:
        credential_id: The ID of the credential being updated.
        new_status: The new status ("active" or "revoked").
        registrar_private_key: The registrar's Ed25519 signing key.

    Returns:
        A signed CredentialStatusUpdate.
    """
    now = datetime.now(UTC)

    update = CredentialStatusUpdate(
        credential_id=credential_id,
        new_status=new_status,
        updated_at=now.isoformat(),
        registrar_signatures=[],
    )

    canonical_bytes = canonicalize(update.signable_fields())
    signature = sign(registrar_private_key, canonical_bytes)
    update.registrar_signatures.append(base64.b64encode(signature).decode("ascii"))

    return update


def verify_status_update(
    update: CredentialStatusUpdate,
    registrar_public_keys: list[Ed25519PublicKey],
) -> bool:
    """Verify the signature on a credential status update.

    Args:
        update: The status update to verify.
        registrar_public_keys: The registrar's Ed25519 public keys.

    Returns:
        True if the signature is valid, False otherwise.
    """
    if len(update.registrar_signatures) < 2:
        return False

    canonical_bytes = canonicalize(update.signable_fields())
    
    valid_sigs = 0
    for sig_b64 in update.registrar_signatures:
        try:
            signature = base64.b64decode(sig_b64)
            for pub in registrar_public_keys:
                if verify(pub, canonical_bytes, signature):
                    valid_sigs += 1
                    break
        except Exception:
            pass
            
    return valid_sigs >= 2


def is_credential_expired(credential: Credential) -> bool:
    """Check if a credential has passed its expiry time."""
    if not credential.expires_at:
        return False
    expires = datetime.fromisoformat(credential.expires_at)
    return datetime.now(UTC) > expires
