"""Tests for swarmsec.registrar.credential."""

import base64

from swarmsec.crypto.keys import generate_keypair, serialize_public_key
from swarmsec.registrar.credential import (
    is_credential_expired,
    issue_credential,
    update_status,
    verify_credential,
    verify_status_update,
)


class TestCredentialIssuance:
    def test_issue_and_verify_roundtrip(self):
        reg_keys = [generate_keypair() for _ in range(3)]
        reg_privs, reg_pubs = [k[0] for k in reg_keys], [k[1] for k in reg_keys]
        _, pseudo_pub = generate_keypair()
        pseudo_b64 = base64.b64encode(serialize_public_key(pseudo_pub)).decode("ascii")

        cred = issue_credential(pseudo_b64, reg_privs[0])
        # Add 2nd signature manually (as app.py does)
        from swarmsec.crypto.canonicalize import canonicalize
        from swarmsec.crypto.keys import sign
        sig2 = sign(reg_privs[1], canonicalize(cred.signable_fields()))
        cred.registrar_signatures.append(base64.b64encode(sig2).decode("ascii"))
        
        assert cred.pseudonym_public_key == pseudo_b64
        assert cred.status == "active"
        assert len(cred.registrar_signatures) == 2
        assert verify_credential(cred, reg_pubs)

    def test_tampered_credential_fails_verification(self):
        reg_keys = [generate_keypair() for _ in range(3)]
        reg_privs, reg_pubs = [k[0] for k in reg_keys], [k[1] for k in reg_keys]
        _, pseudo_pub = generate_keypair()
        pseudo_b64 = base64.b64encode(serialize_public_key(pseudo_pub)).decode("ascii")

        cred = issue_credential(pseudo_b64, reg_privs[0])
        from swarmsec.crypto.canonicalize import canonicalize
        from swarmsec.crypto.keys import sign
        sig2 = sign(reg_privs[1], canonicalize(cred.signable_fields()))
        cred.registrar_signatures.append(base64.b64encode(sig2).decode("ascii"))
        assert verify_credential(cred, reg_pubs)

        # Tamper with the status
        cred.status = "revoked"
        assert not verify_credential(cred, reg_pubs)

    def test_wrong_registrar_key_fails_verification(self):
        reg_keys = [generate_keypair() for _ in range(3)]
        wrong_keys = [generate_keypair() for _ in range(3)]
        reg_privs = [k[0] for k in reg_keys]
        wrong_pubs = [k[1] for k in wrong_keys]
        _, pseudo_pub = generate_keypair()
        pseudo_b64 = base64.b64encode(serialize_public_key(pseudo_pub)).decode("ascii")

        cred = issue_credential(pseudo_b64, reg_privs[0])
        from swarmsec.crypto.canonicalize import canonicalize
        from swarmsec.crypto.keys import sign
        sig2 = sign(reg_privs[1], canonicalize(cred.signable_fields()))
        cred.registrar_signatures.append(base64.b64encode(sig2).decode("ascii"))
        
        assert not verify_credential(cred, wrong_pubs)

    def test_invalid_signature_format(self):
        reg_keys = [generate_keypair() for _ in range(3)]
        reg_privs, reg_pubs = [k[0] for k in reg_keys], [k[1] for k in reg_keys]
        _, pseudo_pub = generate_keypair()
        pseudo_b64 = base64.b64encode(serialize_public_key(pseudo_pub)).decode("ascii")

        cred = issue_credential(pseudo_b64, reg_privs[0])
        from swarmsec.crypto.canonicalize import canonicalize
        from swarmsec.crypto.keys import sign
        sig2 = sign(reg_privs[1], canonicalize(cred.signable_fields()))
        cred.registrar_signatures.append(base64.b64encode(sig2).decode("ascii"))
        
        cred.registrar_signatures[1] = "not base64"
        assert not verify_credential(cred, reg_pubs)


class TestCredentialStatusUpdate:
    def test_update_status_and_verify(self):
        reg_keys = [generate_keypair() for _ in range(3)]
        reg_privs, reg_pubs = [k[0] for k in reg_keys], [k[1] for k in reg_keys]
        
        update = update_status("test-cred-123", "revoked", reg_privs[0])
        from swarmsec.crypto.canonicalize import canonicalize
        from swarmsec.crypto.keys import sign
        sig2 = sign(reg_privs[1], canonicalize(update.signable_fields()))
        update.registrar_signatures.append(base64.b64encode(sig2).decode("ascii"))
        
        assert update.credential_id == "test-cred-123"
        assert update.new_status == "revoked"
        assert verify_status_update(update, reg_pubs)

    def test_tampered_update_fails(self):
        reg_keys = [generate_keypair() for _ in range(3)]
        reg_privs, reg_pubs = [k[0] for k in reg_keys], [k[1] for k in reg_keys]
        
        update = update_status("test-cred-123", "revoked", reg_privs[0])
        from swarmsec.crypto.canonicalize import canonicalize
        from swarmsec.crypto.keys import sign
        sig2 = sign(reg_privs[1], canonicalize(update.signable_fields()))
        update.registrar_signatures.append(base64.b64encode(sig2).decode("ascii"))
        
        update.credential_id = "other-cred"
        assert not verify_status_update(update, reg_pubs)


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
