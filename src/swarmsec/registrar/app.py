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
_REGISTRAR_PRIVATE_KEYS = []
_REGISTRAR_PUBLIC_KEYS = []
_TRANSPARENCY_LOG = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    global _REGISTRAR_PRIVATE_KEYS, _REGISTRAR_PUBLIC_KEYS, _TRANSPARENCY_LOG
    
    from swarmsec.crypto.keys import load_private_key, save_keypair, generate_keypair
    
    for i in range(1, 4):
        key_file = os.environ.get(f"SWARMSEC_REGISTRAR_KEY_FILE_{i}", f"registrar_{i}.key")
        if os.path.exists(key_file):
            priv = load_private_key(key_file)
            _REGISTRAR_PRIVATE_KEYS.append(priv)
            _REGISTRAR_PUBLIC_KEYS.append(priv.public_key())
        else:
            priv, pub = generate_keypair()
            _REGISTRAR_PRIVATE_KEYS.append(priv)
            _REGISTRAR_PUBLIC_KEYS.append(pub)
            dir_name = os.path.dirname(key_file) or "."
            base_name = os.path.basename(key_file)
            save_keypair(
                priv, 
                directory=dir_name, 
                private_name=base_name, 
                public_name=base_name + ".pub"
            )
    
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


@app.get("/pubkeys")
def get_public_keys():
    """Return the registrar's public keys (needed by peers for 2-of-3 verification)."""
    return {
        "public_keys_b64": [base64.b64encode(serialize_public_key(pub)).decode("ascii") for pub in _REGISTRAR_PUBLIC_KEYS]
    }


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

    # Issue credential (registrar signs it with 2 keys to satisfy threshold)
    # Using keys 0 and 1 for the 2-of-3 threshold
    cred = issue_credential(request.pseudonym_public_key, _REGISTRAR_PRIVATE_KEYS[0])
    # The issue_credential creates it with 1 signature, we add the second
    from swarmsec.crypto.canonicalize import canonicalize
    from swarmsec.crypto.keys import sign
    
    signable_bytes = canonicalize(cred.signable_fields())
    sig2 = sign(_REGISTRAR_PRIVATE_KEYS[1], signable_bytes)
    cred.registrar_signatures.append(base64.b64encode(sig2).decode("ascii"))
    
    # Append to transparency log
    log_entry = _TRANSPARENCY_LOG.append(cred.model_dump(mode="json"))
    
    return RegistrationResponse(credential=cred, log_entry=log_entry)


@app.get("/credential/{credential_id}", response_model=Credential)
def get_credential(credential_id: str):
    """Retrieve an issued credential from the log, including any revocations."""
    import json
    
    cred_data = None
    
    for entry in _TRANSPARENCY_LOG.get_all_entries():
        payload = json.loads(base64.b64decode(entry.payload_canonical).decode("utf-8"))
        if payload.get("credential_id") == credential_id:
            if cred_data is None:
                # Issuance
                cred_data = {
                    "credential_id": payload["credential_id"],
                    "pseudonym_public_key": payload["pseudonym_public_key"],
                    "status": payload.get("status", "active"),
                    "issued_at": payload.get("issued_at", ""),
                    "expires_at": payload.get("expires_at", ""),
                    "registrar_signatures": payload.get("registrar_signatures", []),
                }
            elif "new_status" in payload:
                # Revocation update
                cred_data["status"] = payload["new_status"]
                
    if cred_data:
        return Credential(**cred_data)

    raise HTTPException(status_code=404, detail="Credential not found")


@app.post("/credential/{credential_id}/revoke", response_model=CredentialStatusUpdate)
def revoke_credential(credential_id: str):
    """Revoke a credential and append the status update to the log."""
    update = update_status(credential_id, "revoked", _REGISTRAR_PRIVATE_KEYS[0])
    from swarmsec.crypto.canonicalize import canonicalize
    from swarmsec.crypto.keys import sign
    signable_bytes = canonicalize(update.signable_fields())
    sig2 = sign(_REGISTRAR_PRIVATE_KEYS[1], signable_bytes)
    update.registrar_signatures.append(base64.b64encode(sig2).decode("ascii"))
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


@app.get("/log/root")
def get_log_root():
    """Get the cryptographic root of the Merkle tree."""
    root = _TRANSPARENCY_LOG.get_merkle_root()
    if not root:
        return {"merkle_root": None, "tree_size": 0}
    return {"merkle_root": root, "tree_size": len(_TRANSPARENCY_LOG)}


@app.get("/log/proof/{index}")
def get_log_proof(index: int):
    """Retrieve an inclusion proof for the entry at the given index."""
    proof = _TRANSPARENCY_LOG.get_inclusion_proof(index)
    if not proof:
        raise HTTPException(status_code=404, detail="Entry index out of bounds")
    return proof

