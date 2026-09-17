"""Tests for the FastAPI registrar service."""

import base64
from fastapi.testclient import TestClient
import pytest

from swarmsec.crypto.keys import generate_keypair, serialize_public_key
from swarmsec.registrar.app import app

client = TestClient(app)

@pytest.fixture
def pseudo_pubkey_b64():
    _, pub = generate_keypair()
    return base64.b64encode(serialize_public_key(pub)).decode("ascii")

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_get_pubkey():
    with client:
        response = client.get("/pubkey")
        assert response.status_code == 200
        data = response.json()
        assert "public_key_b64" in data
        assert len(base64.b64decode(data["public_key_b64"])) == 32

def test_register_success(pseudo_pubkey_b64):
    with client:
        response = client.post(
            "/register",
            json={"org_id": "org-a", "pseudonym_public_key": pseudo_pubkey_b64}
        )
        assert response.status_code == 200
        data = response.json()
        assert "credential" in data
        assert "log_entry" in data
        
        cred = data["credential"]
        assert cred["pseudonym_public_key"] == pseudo_pubkey_b64
        assert cred["status"] == "active"

def test_register_rejected_unknown_org(pseudo_pubkey_b64):
    with client:
        response = client.post(
            "/register",
            json={"org_id": "unknown-org", "pseudonym_public_key": pseudo_pubkey_b64}
        )
        assert response.status_code == 403
        assert "not in allowlist" in response.json()["detail"].lower()

def test_revoke_credential():
    with client:
        response = client.post("/credential/some-id/revoke")
        assert response.status_code == 200
        data = response.json()
        assert data["credential_id"] == "some-id"
        assert data["new_status"] == "revoked"

def test_log_verify():
    with client:
        # Do a registration to populate log
        _, pub = generate_keypair()
        b64_pub = base64.b64encode(serialize_public_key(pub)).decode("ascii")
        client.post("/register", json={"org_id": "org-b", "pseudonym_public_key": b64_pub})
        
        response = client.get("/log/verify")
        assert response.status_code == 200
        data = response.json()
        assert data["is_valid"] is True
