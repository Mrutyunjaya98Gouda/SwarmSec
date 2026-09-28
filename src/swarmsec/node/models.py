"""Pydantic models for SwarmSec node messages and STIX 2.1 objects."""

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

# -------------------------------------------------------------------------
# Constrained STIX 2.1 Models
# -------------------------------------------------------------------------

class TLPMarking(str, Enum):
    CLEAR = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
    # AMBER and RED are explicitly forbidden in this build per AGENTS.md


class StixExternalReference(BaseModel):
    """External reference for STIX objects, used for independence checking."""
    source_name: str
    url: Optional[str] = None
    external_id: Optional[str] = None


class StixIndicator(BaseModel):
    """A minimal STIX 2.1 Indicator object."""
    type: str = "indicator"
    id: str = Field(default_factory=lambda: f"indicator--{uuid4()}")
    created: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    modified: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    name: Optional[str] = None
    pattern: str  # e.g., "[ipv4-addr:value = '198.51.100.1']"
    pattern_type: str = "stix"
    valid_from: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    object_marking_refs: List[TLPMarking]
    external_references: List[StixExternalReference] = Field(default_factory=list)

# -------------------------------------------------------------------------
# SwarmSec Transport Envelope
# -------------------------------------------------------------------------

class SignableEnvelopeFields(BaseModel):
    """The fields of the envelope that are canonicalized and signed."""
    credential_id: str
    sequence_number: int
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    message_id: str = Field(default_factory=lambda: str(uuid4()))
    payload_hash: str  # SHA-256 of the canonicalized STIX payload

    def model_dump_for_signature(self) -> Dict[str, Any]:
        """Return a dictionary ready for RFC 8785 canonicalization."""
        return self.model_dump(mode="json")


class SwarmSecMessage(BaseModel):
    """
    The top-level message structure sent over gossip.
    Maintains strict separation between the CTI content and the transport envelope.
    """
    envelope: SignableEnvelopeFields
    signature: str = ""  # Base64 Ed25519 signature over canonicalized envelope
    payload: StixIndicator

    def compute_payload_hash(self) -> str:
        """Compute the SHA-256 hash of the canonicalized payload."""
        from swarmsec.crypto.canonicalize import canonicalize
        payload_bytes = canonicalize(self.payload.model_dump(mode="json"))
        return hashlib.sha256(payload_bytes).hexdigest()
