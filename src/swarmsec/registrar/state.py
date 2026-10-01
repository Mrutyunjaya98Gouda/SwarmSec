"""In-process registrar state: keys, log, and credential index.

The demo registrar is single-process. Set SWARMSEC_REGISTRAR_KEY_FILE and
SWARMSEC_LOG_FILE to persist across restarts; otherwise keys and credentials
are ephemeral.
"""

from __future__ import annotations

import os
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from swarmsec.crypto.keys import load_or_create_keypair
from swarmsec.registrar.credential import verify_status_update
from swarmsec.registrar.models import Credential, CredentialStatusUpdate
from swarmsec.registrar.transparency_log import TransparencyLog

RECORD_CREDENTIAL = "credential"
RECORD_STATUS_UPDATE = "status_update"


def log_record(record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap a signed object for hashing into the transparency log."""
    return {"record_type": record_type, "record": payload}


class RegistrarState:
    """Credential index plus the hash-chained log."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
        log: TransparencyLog,
    ):
        self.private_key = private_key
        self.public_key = public_key
        self.log = log
        self.credentials: dict[str, Credential] = {}
        self.status_updates: dict[str, list[CredentialStatusUpdate]] = {}
        self._rebuild_index()

    @classmethod
    def from_env(cls) -> "RegistrarState":
        key_path = os.environ.get("SWARMSEC_REGISTRAR_KEY_FILE")
        log_path = os.environ.get("SWARMSEC_LOG_FILE")
        private_key, public_key = load_or_create_keypair(key_path)
        return cls(private_key, public_key, TransparencyLog(log_path))

    def _rebuild_index(self) -> None:
        import base64
        import json

        self.credentials.clear()
        self.status_updates.clear()
        for entry in self.log.get_all_entries():
            payload = json.loads(base64.b64decode(entry.payload_canonical).decode("utf-8"))
            self._ingest_payload(payload)

    def _ingest_payload(self, payload: dict[str, Any]) -> None:
        record_type = payload.get("record_type")
        record = payload.get("record", payload)
        if record_type == RECORD_STATUS_UPDATE or (
            record_type is None and "new_status" in record
        ):
            update = CredentialStatusUpdate(**record)
            self.status_updates.setdefault(update.credential_id, []).append(update)
            return
        if "pseudonym_public_key" in record and "credential_id" in record:
            cred = Credential(**record)
            self.credentials[cred.credential_id] = cred

    def store_credential(self, cred: Credential):
        entry = self.log.append(
            log_record(RECORD_CREDENTIAL, cred.model_dump())
        )
        self.credentials[cred.credential_id] = cred
        return entry

    def store_status_update(self, update: CredentialStatusUpdate):
        entry = self.log.append(
            log_record(RECORD_STATUS_UPDATE, update.model_dump())
        )
        self.status_updates.setdefault(update.credential_id, []).append(update)
        return entry

    def get_credential(self, credential_id: str) -> Credential | None:
        return self.credentials.get(credential_id)

    def resolve_status(self, credential_id: str) -> tuple[str, CredentialStatusUpdate | None]:
        cred = self.credentials[credential_id]
        resolved = cred.status
        latest: CredentialStatusUpdate | None = None
        for update in self.status_updates.get(credential_id, []):
            if verify_status_update(update, self.public_key):
                resolved = update.new_status
                latest = update
        return resolved, latest
