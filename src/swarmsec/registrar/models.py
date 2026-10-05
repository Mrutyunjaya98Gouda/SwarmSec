"""Pydantic data models for the registrar service.

These define the core data structures for credentials, registration
requests/responses, transparency log entries, and status updates.

The registrar knows the org-to-pseudonym mapping — this is intentional
per AGENTS.md, not an oversight to "fix" with blind signatures.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Return the current UTC time (timezone-aware)."""
    return datetime.now(UTC)


def _new_credential_id() -> str:
    """Generate a unique credential identifier."""
    return str(uuid4())


class RegistrationRequest(BaseModel):
    """An org's request to register a pseudonym with the registrar.

    The org_id is the real-world identifier checked against the allowlist.
    The pseudonym_public_key is the org's Ed25519 public key (base64-encoded
    raw 32 bytes).
    """
    org_id: str
    pseudonym_public_key: str  # base64-encoded raw 32-byte Ed25519 public key


class Credential(BaseModel):
    """A registrar-issued credential binding a pseudonym key to a verified org.

    The registrar signs the canonical form of the signable fields
    (credential_id, pseudonym_public_key, status, issued_at, expires_at)
    with its Ed25519 key.
    """
    credential_id: str = Field(default_factory=_new_credential_id)
    pseudonym_public_key: str  # base64-encoded raw 32 bytes
    status: Literal["active", "revoked"] = "active"
    issued_at: str = ""  # ISO 8601 UTC string
    expires_at: str = ""  # ISO 8601 UTC string
    registrar_signature: str = ""  # base64-encoded 64-byte Ed25519 signature

    def signable_fields(self) -> dict:
        """Return only the fields that are covered by the registrar signature.

        The signature itself is excluded — it's computed over these fields.
        """
        return {
            "credential_id": self.credential_id,
            "pseudonym_public_key": self.pseudonym_public_key,
            "status": self.status,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


class CredentialStatusUpdate(BaseModel):
    """A signed status change for an existing credential.

    Appended to the transparency log when a credential is revoked.
    """
    credential_id: str
    new_status: Literal["active", "revoked"]
    updated_at: str  # ISO 8601 UTC string
    registrar_signature: str  # base64-encoded 64-byte Ed25519 signature

    def signable_fields(self) -> dict:
        """Return only the fields covered by the signature."""
        return {
            "credential_id": self.credential_id,
            "new_status": self.new_status,
            "updated_at": self.updated_at,
        }


class TransparencyLogEntry(BaseModel):
    """A single entry in the hash-chained transparency log.

    Each entry hashes to: SHA-256(prev_hash || canonical(payload)).
    The payload is the canonical bytes of the credential or status update.
    """
    index: int
    payload_canonical: str  # base64-encoded canonical bytes of the credential
    prev_hash: str  # hex-encoded SHA-256 of the previous entry (or "0" * 64 for genesis)
    entry_hash: str  # hex-encoded SHA-256(prev_hash_bytes || payload_canonical_bytes)


class RegistrationResponse(BaseModel):
    """Response returned after successful registration."""
    credential: Credential
    log_entry: TransparencyLogEntry
