"""Peer-side verification of gossip messages."""

import base64
import json
import logging

import httpx

from swarmsec.crypto.keys import deserialize_public_key, verify
from swarmsec.node.models import SwarmSecMessage
from swarmsec.node.rate_limit import RateLimiter
from swarmsec.registrar.credential import verify_credential
from swarmsec.registrar.models import Credential

logger = logging.getLogger(__name__)

class MessageVerifier:
    def __init__(self, registrar_url: str):
        self.registrar_url = registrar_url
        self.rate_limiter = RateLimiter()
        self.registrar_pubkey = None
        self._fetch_registrar_pubkey()

    def _fetch_registrar_pubkey(self):
        """Fetch the registrar's public key for credential verification."""
        try:
            resp = httpx.get(f"{self.registrar_url}/pubkey", timeout=10.0)
            resp.raise_for_status()
            b64_pub = resp.json()["public_key_b64"]
            self.registrar_pubkey = deserialize_public_key(base64.b64decode(b64_pub))
        except Exception as e:
            logger.error(f"Failed to fetch registrar pubkey: {e}")

    async def _get_credential_from_log(self, credential_id: str) -> dict:
        """Fetch the current state and public key of a credential from the log.

        Returns a dict with keys:
          - public_key: base64-encoded pseudonym public key (or None)
          - status: "active" | "revoked"
          - registrar_signature: base64-encoded registrar Ed25519 signature (or None)
          - credential: the full Credential payload dict (or None)
        """
        result = {
            "public_key": None,
            "status": "active",
            "registrar_signature": None,
            "credential": None,
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.registrar_url}/log", timeout=10.0)
                if resp.status_code != 200:
                    logger.error(f"Failed to fetch log: {resp.status_code}")
                    return result

                log_entries = resp.json()

                for entry in log_entries:
                    payload = json.loads(base64.b64decode(entry["payload_canonical"]).decode("utf-8"))

                    if payload.get("credential_id") == credential_id:
                        if "pseudonym_public_key" in payload:
                            result["public_key"] = payload["pseudonym_public_key"]
                        if "status" in payload:
                            result["status"] = payload["status"]
                        if "new_status" in payload:
                            # Revocation entry overrides status
                            result["status"] = payload["new_status"]
                        if "registrar_signature" in payload:
                            result["registrar_signature"] = payload["registrar_signature"]
                            result["credential"] = payload

        except Exception as e:
            logger.error(f"Error fetching log: {e}")

        return result

    async def verify(self, message: SwarmSecMessage) -> tuple[bool, str]:
        """
        Verify an incoming gossip message.

        Checks (in order):
          1. Payload hash matches envelope (tamper detection)
          2. Credential ID is known in the registrar's transparency log
          3. Registrar Ed25519 signature on the credential is valid
          4. Pseudonym's Ed25519 signature on the envelope is valid
          5. Credential is not revoked
          6. Rate limit is not exceeded
        """
        # 1. Verify payload hash matches envelope
        expected_hash = message.compute_payload_hash()
        if expected_hash != message.envelope.payload_hash:
            return False, "Payload hash mismatch"

        # 2. Fetch credential info from log
        cred_info = await self._get_credential_from_log(message.envelope.credential_id)
        if not cred_info.get("public_key"):
            return False, "Unknown credential ID"

        # 3. Verify the registrar's Ed25519 signature on the credential itself
        if self.registrar_pubkey and cred_info.get("credential"):
            try:
                cred = Credential(**cred_info["credential"])
                if not verify_credential(cred, self.registrar_pubkey):
                    return False, "Credential registrar signature invalid"
            except Exception as e:
                return False, f"Credential verification error: {e}"

        # 4. Verify pseudonym's Ed25519 signature on the envelope
        try:
            from swarmsec.crypto.canonicalize import canonicalize
            signable_bytes = canonicalize(message.envelope.model_dump_for_signature())
            pubkey_bytes = base64.b64decode(cred_info["public_key"])
            pubkey = deserialize_public_key(pubkey_bytes)

            if not verify(pubkey, signable_bytes, base64.b64decode(message.signature)):
                return False, "Invalid signature"
        except Exception as e:
            return False, f"Signature verification error: {e}"

        # 5. Verify credential status
        if cred_info.get("status") == "revoked":
            return False, "Credential revoked"

        # 6. Verify rate ticket (also prevents replay via message_id tracking)
        if not self.rate_limiter.check_and_consume(
            message.envelope.credential_id,
            message.envelope.timestamp,
            message_id=message.envelope.message_id,
        ):
            return False, "Rate limit exceeded"

        return True, "OK"
