"""Tests for swarmsec.registrar.credential."""

import base64
from datetime import datetime, timedelta, timezone

from swarmsec.crypto.canonicalize import canonicalize
from swarmsec.crypto.keys import generate_keypair, serialize_public_key, sign
from swarmsec.registrar.credential import (
    is_credential_expired,
    issue_credential,
    update_status,
    verify_credential,
    verify_status_update,
)


class TestCredentialIssuance:
    def test_issue_and_verify_roundtrip(self):
        reg_priv, reg_pub = generate_keypair()
        _, pseudo_pub = generate_keypair()
        pseudo_b64 = base64.b64encode(serialize_public_key(pseudo_pub)).decode("ascii")

        cred = issue_credential(pseudo_b64, reg_priv)
        
        assert cred.pseudonym_public_key == pseudo_b64
        assert cred.status == "active"
        assert cred.registrar_signature != ""
        assert verify_credential(cred, reg_pub)

    def test_tampered_credential_fails_verification(self):
        reg_priv, reg_pub = generate_keypair()
        _, pseudo_pub = generate_keypair()
        pseudo_b64 = base64.b64encode(serialize_public_key(pseudo_pub)).decode("ascii")

        cred = issue_credential(pseudo_b64, reg_priv)
        assert verify_credential(cred, reg_pub)

        # Tamper with the status
        cred.status = "revoked"
        assert not verify_credential(cred, reg_pub)

    def test_wrong_registrar_key_fails_verification(self):
        reg_priv1, _ = generate_keypair()
        _, reg_pub2 = generate_keypair()
        _, pseudo_pub = generate_keypair()
        pseudo_b64 = base64.b64encode(serialize_public_key(pseudo_pub)).decode("ascii")

        cred = issue_credential(pseudo_b64, reg_priv1)
        assert not verify_credential(cred, reg_pub2)

    def test_invalid_signature_format(self):
        reg_priv, reg_pub = generate_keypair()
        _, pseudo_pub = generate_keypair()
        pseudo_b64 = base64.b64encode(serialize_public_key(pseudo_pub)).decode("ascii")

        cred = issue_credential(pseudo_b64, reg_priv)
        cred.registrar_signature = "not base64"
        assert not verify_credential(cred, reg_pub)


class TestCredentialStatusUpdate:
    def test_update_status_and_verify(self):
        reg_priv, reg_pub = generate_keypair()
        update = update_status("test-cred-123", "revoked", reg_priv)
        
        assert update.credential_id == "test-cred-123"
        assert update.new_status == "revoked"
        assert verify_status_update(update, reg_pub)

    def test_tampered_update_fails(self):
        reg_priv, reg_pub = generate_keypair()
        update = update_status("test-cred-123", "revoked", reg_priv)
        
        update.credential_id = "other-cred"
        assert not verify_status_update(update, reg_pub)


class TestCredentialExpiry:
    def test_active_credential_not_expired(self):
        reg_priv, _ = generate_keypair()
        _, pseudo_pub = generate_keypair()
        pseudo_b64 = base64.b64encode(serialize_public_key(pseudo_pub)).decode("ascii")

        cred = issue_credential(pseudo_b64, reg_priv, validity_days=10)
        assert not is_credential_expired(cred)

    def test_expired_credential(self):
        reg_priv, _ = generate_keypair()
        _, pseudo_pub = generate_keypair()
        pseudo_b64 = base64.b64encode(serialize_public_key(pseudo_pub)).decode("ascii")

        cred = issue_credential(pseudo_b64, reg_priv, validity_days=-1) # Issued yesterday
        assert is_credential_expired(cred)
