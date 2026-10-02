"""FastAPI registrar service.

Exposes endpoints for registration, credential retrieval, revocation,
and transparency log verification.
"""

import base64
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from swarmsec.crypto.keys import (
    generate_keypair,
    serialize_public_key,
)
from swarmsec.registrar.allowlist import is_allowed
from swarmsec.registrar.credential import (
    issue_credential,
    update_status,
)
from swarmsec.registrar.models import (
    Credential,
    CredentialStatusUpdate,
    RegistrationRequest,
    RegistrationResponse,
    TransparencyLogEntry,
)
from swarmsec.registrar.transparency_log import TransparencyLog

# Global state for the demo registrar
_REGISTRAR_PRIVATE_KEY = None
_REGISTRAR_PUBLIC_KEY = None
_TRANSPARENCY_LOG = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    global _REGISTRAR_PRIVATE_KEY, _REGISTRAR_PUBLIC_KEY, _TRANSPARENCY_LOG
    
    # Generate a fresh keypair for the registrar on startup
    # In production, this would be loaded from secure storage (e.g., HSM)
    _REGISTRAR_PRIVATE_KEY, _REGISTRAR_PUBLIC_KEY = generate_keypair()
    
    # Initialize the transparency log (in-memory for tests, or file-backed if configured)
    log_file = os.environ.get("SWARMSEC_LOG_FILE")
    _TRANSPARENCY_LOG = TransparencyLog(log_file)
    
    yield
    
    # Cleanup (none needed)


app = FastAPI(title="SwarmSec Registrar", lifespan=lifespan)


class VerificationResult(BaseModel):
    is_valid: bool
    message: str


@app.get("/health")
def health_check():
    """Simple health check endpoint."""
    return {"status": "ok"}


@app.get("/pubkey")
def get_public_key():
    """Return the registrar's public key (needed by peers for verification)."""
    raw_pubkey = serialize_public_key(_REGISTRAR_PUBLIC_KEY)
    return {"public_key_b64": base64.b64encode(raw_pubkey).decode("ascii")}


@app.post("/register", response_model=RegistrationResponse)
def register(request: RegistrationRequest):
    """Register a pseudonym and receive a credential."""
    if not is_allowed(request.org_id):
        raise HTTPException(status_code=403, detail="Organization not in allowlist.")

    try:
        # Validate that the provided key is valid base64
        base64.b64decode(request.pseudonym_public_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 pseudonym key.")

    # Issue credential (registrar signs it)
    cred = issue_credential(request.pseudonym_public_key, _REGISTRAR_PRIVATE_KEY)
    
    # Append to transparency log
    log_entry = _TRANSPARENCY_LOG.append(cred.signable_fields())
    
    return RegistrationResponse(credential=cred, log_entry=log_entry)


@app.get("/credential/{credential_id}", response_model=Credential)
def get_credential(credential_id: str):
    """Retrieve an issued credential from the log."""
    import json

    for entry in _TRANSPARENCY_LOG.get_all_entries():
        payload = json.loads(base64.b64decode(entry.payload_canonical).decode("utf-8"))
        if payload.get("credential_id") == credential_id:
            return Credential(
                credential_id=payload["credential_id"],
                pseudonym_public_key=payload["pseudonym_public_key"],
                status=payload.get("status", "active"),
                issued_at=payload.get("issued_at", ""),
                expires_at=payload.get("expires_at", ""),
                registrar_signature=entry.signature,
            )

    raise HTTPException(status_code=404, detail="Credential not found")


@app.post("/credential/{credential_id}/revoke", response_model=CredentialStatusUpdate)
def revoke_credential(credential_id: str):
    """Revoke a credential and append the status update to the log."""
    update = update_status(credential_id, "revoked", _REGISTRAR_PRIVATE_KEY)
    _TRANSPARENCY_LOG.append(update.signable_fields())
    return update


@app.get("/log", response_model=list[TransparencyLogEntry])
def get_log():
    """Return the full transparency log."""
    return _TRANSPARENCY_LOG.get_all_entries()


@app.get("/log/verify", response_model=VerificationResult)
def verify_log():
    """Verify the integrity of the transparency log."""
    is_valid, msg = _TRANSPARENCY_LOG.verify_chain()
    return VerificationResult(is_valid=is_valid, message=msg)
