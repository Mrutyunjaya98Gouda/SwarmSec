"""FastAPI registrar service.

Exposes endpoints for registration, credential retrieval, revocation,
and transparency log verification.

Peers must fetch a complete Credential from GET /credential/{id} and call
verify_credential() against /pubkey. Unsigned transparency-log fields are
not a substitute for a registrar signature.
"""

from __future__ import annotations

import base64
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from swarmsec.crypto.keys import parse_ed25519_public_key_b64, serialize_public_key
from swarmsec.registrar.allowlist import is_allowed
from swarmsec.registrar.credential import issue_credential, update_status
from swarmsec.registrar.models import (
    CredentialLookupResponse,
    CredentialStatusUpdate,
    RegistrationRequest,
    RegistrationResponse,
    TransparencyLogEntry,
)
from swarmsec.registrar.state import RegistrarState


class VerificationResult(BaseModel):
    is_valid: bool
    message: str


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.registrar = RegistrarState.from_env()
        yield

    application = FastAPI(title="SwarmSec Registrar", lifespan=lifespan)

    def _state(request: Request) -> RegistrarState:
        return request.app.state.registrar

    @application.get("/health")
    def health_check():
        """Simple health check endpoint."""
        return {"status": "ok"}

    @application.get("/pubkey")
    def get_public_key(request: Request):
        """Return the registrar's public key (needed by peers for verification)."""
        raw_pubkey = serialize_public_key(_state(request).public_key)
        return {"public_key_b64": base64.b64encode(raw_pubkey).decode("ascii")}

    @application.post("/register", response_model=RegistrationResponse)
    def register(request_body: RegistrationRequest, request: Request):
        """Register a pseudonym and receive a signed credential."""
        if not is_allowed(request_body.org_id):
            raise HTTPException(status_code=403, detail="Organization not in allowlist.")

        try:
            parse_ed25519_public_key_b64(request_body.pseudonym_public_key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        state = _state(request)
        cred = issue_credential(request_body.pseudonym_public_key, state.private_key)
        log_entry = state.store_credential(cred)
        return RegistrationResponse(credential=cred, log_entry=log_entry)

    @application.get("/credential/{credential_id}", response_model=CredentialLookupResponse)
    def get_credential(credential_id: str, request: Request):
        """Return the issued signed credential and resolved status."""
        state = _state(request)
        cred = state.get_credential(credential_id)
        if cred is None:
            raise HTTPException(status_code=404, detail="Credential not found")
        resolved, latest = state.resolve_status(credential_id)
        return CredentialLookupResponse(
            credential=cred,
            resolved_status=resolved,
            latest_status_update=latest,
        )

    @application.post(
        "/credential/{credential_id}/revoke",
        response_model=CredentialStatusUpdate,
    )
    def revoke_credential(credential_id: str, request: Request):
        """Revoke a known credential and append a signed status update."""
        state = _state(request)
        if state.get_credential(credential_id) is None:
            raise HTTPException(status_code=404, detail="Credential not found")
        update = update_status(credential_id, "revoked", state.private_key)
        state.store_status_update(update)
        return update

    @application.get("/log", response_model=list[TransparencyLogEntry])
    def get_log(request: Request):
        """Return the full transparency log."""
        return _state(request).log.get_all_entries()

    @application.get("/log/verify", response_model=VerificationResult)
    def verify_log(request: Request):
        """Verify the integrity of the transparency log."""
        is_valid, msg = _state(request).log.verify_chain()
        return VerificationResult(is_valid=is_valid, message=msg)

    return application


app = create_app()
