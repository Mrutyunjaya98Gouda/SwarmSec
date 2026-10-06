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
        self.registrar_pubkeys = []
        self.credential_cache = {}
        self._fetch_registrar_pubkeys()

    def _fetch_registrar_pubkeys(self):
        """Fetch the registrar's public keys for threshold credential verification."""
        import os
        cert_path = os.environ.get("TLS_CERT_PATH")
        key_path = os.environ.get("TLS_KEY_PATH")
        ca_path = os.environ.get("TLS_CA_PATH")
        verify_ca = ca_path if ca_path else False
        cert = (cert_path, key_path) if cert_path and key_path else None
        
        try:
            with httpx.Client(verify=verify_ca, cert=cert) as client:
                resp = client.get(f"{self.registrar_url}/pubkeys", timeout=10.0)
            resp.raise_for_status()
            keys_b64 = resp.json()["public_keys_b64"]
            self.registrar_pubkeys = [deserialize_public_key(base64.b64decode(k)) for k in keys_b64]
        except Exception as e:
            logger.error(f"Failed to fetch registrar pubkeys: {e}")

    async def _get_credential_from_log(self, credential_id: str) -> dict:
        """Fetch the current state and public key of a credential.
        
        Uses a local cache to prevent DoS/Amplification attacks where parsing
        the entire transparency log for every gossip message halts the node.
        """
        if credential_id in self.credential_cache:
            return self.credential_cache[credential_id]

        result = {
            "public_key": None,
            "status": "active",
            "registrar_signatures": [],
            "credential": None,
        }
        try:
            import os
            cert_path = os.environ.get("TLS_CERT_PATH")
            key_path = os.environ.get("TLS_KEY_PATH")
            ca_path = os.environ.get("TLS_CA_PATH")
            verify_ca = ca_path if ca_path else False
            cert = (cert_path, key_path) if cert_path and key_path else None

            async with httpx.AsyncClient(verify=verify_ca, cert=cert) as client:
                resp = await client.get(f"{self.registrar_url}/credential/{credential_id}", timeout=10.0)
                if resp.status_code != 200:
                    logger.error(f"Failed to fetch credential: {resp.status_code}")
                    return result

                payload = resp.json()
                result["public_key"] = payload.get("pseudonym_public_key")
                result["status"] = payload.get("status", "active")
                result["registrar_signatures"] = payload.get("registrar_signatures", [])
                result["credential"] = payload
                
                self.credential_cache[credential_id] = result

        except Exception as e:
            logger.error(f"Error fetching credential: {e}")

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

        # 3. Verify the registrar's Ed25519 signatures on the credential itself
        if self.registrar_pubkeys and cred_info.get("credential"):
            try:
                cred = Credential(**cred_info["credential"])
                if not verify_credential(cred, self.registrar_pubkeys):
                    return False, "Credential registrar signatures invalid (threshold not met)"
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
