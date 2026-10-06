"""Tests for the FastAPI registrar service."""

import base64

import pytest
from fastapi.testclient import TestClient

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

def test_get_pubkeys():
    with client:
        response = client.get("/pubkeys")
        assert response.status_code == 200
        data = response.json()
        assert "public_keys_b64" in data
        assert len(data["public_keys_b64"]) == 3

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

def test_log_merkle_proofs():
    with client:
        # Get the root
        response = client.get("/log/root")
        assert response.status_code == 200
        root_data = response.json()
        assert "merkle_root" in root_data
        
        # Test proof
        if root_data["tree_size"] > 0:
            proof_resp = client.get("/log/proof/0")
            assert proof_resp.status_code == 200
            proof = proof_resp.json()
            assert proof["index"] == 0
            assert proof["merkle_root"] == root_data["merkle_root"]
            assert "audit_path" in proof
            
            # Invalid proof index
            bad_resp = client.get("/log/proof/9999")
            assert bad_resp.status_code == 404

def test_registrar_key_persists_across_restarts(tmp_path, monkeypatch, pseudo_pubkey_b64):
    import importlib
    import json

    from fastapi.testclient import TestClient

    import swarmsec.registrar.app as app_module

    for i in range(1, 4):
        monkeypatch.setenv(f"SWARMSEC_REGISTRAR_KEY_FILE_{i}", str(tmp_path / f"registrar_{i}.key"))
        
    log_file = tmp_path / "log.jsonl"
    monkeypatch.setenv("SWARMSEC_LOG_FILE", str(log_file))

    # First "start"
    importlib.reload(app_module)
    with TestClient(app_module.app) as first:
        pk1 = first.get("/pubkeys").json()["public_keys_b64"]
        created = first.post(
            "/register",
            json={"org_id": "org-a", "pseudonym_public_key": pseudo_pubkey_b64},
        ).json()
        cred_id = created["credential"]["credential_id"]

    # Second "start"
    importlib.reload(app_module)
    with TestClient(app_module.app) as second:
        pk2 = second.get("/pubkeys").json()["public_keys_b64"]
        assert pk1 == pk2  # Key persisted
        
        entries = second.get("/log").json()
        assert len(entries) == 1
        payload = json.loads(base64.b64decode(entries[0]["payload_canonical"]).decode("utf-8"))
        assert payload["credential_id"] == cred_id
        
    # Restore app module state to avoid breaking other tests
    for i in range(1, 4):
        monkeypatch.delenv(f"SWARMSEC_REGISTRAR_KEY_FILE_{i}", raising=False)
    monkeypatch.delenv("SWARMSEC_LOG_FILE", raising=False)
    importlib.reload(app_module)
