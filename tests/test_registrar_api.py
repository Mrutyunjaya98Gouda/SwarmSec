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

def test_registrar_key_persists_across_restarts(tmp_path, monkeypatch, pseudo_pubkey_b64):
    import importlib
    import json
    import swarmsec.registrar.app as app_module
    from fastapi.testclient import TestClient
    from swarmsec.registrar.models import Credential
    from swarmsec.crypto.keys import deserialize_public_key

    key_file = tmp_path / "registrar.key"
    log_file = tmp_path / "log.jsonl"
    monkeypatch.setenv("SWARMSEC_REGISTRAR_KEY_FILE", str(key_file))
    monkeypatch.setenv("SWARMSEC_LOG_FILE", str(log_file))

    # First "start"
    importlib.reload(app_module)
    with TestClient(app_module.app) as first:
        pk1 = first.get("/pubkey").json()["public_key_b64"]
        created = first.post(
            "/register",
            json={"org_id": "org-a", "pseudonym_public_key": pseudo_pubkey_b64},
        ).json()
        cred_id = created["credential"]["credential_id"]

    # Second "start"
    importlib.reload(app_module)
    with TestClient(app_module.app) as second:
        pk2 = second.get("/pubkey").json()["public_key_b64"]
        assert pk1 == pk2  # Key persisted
        
        # In the current sprint-6, there is no /credential/{id} lookup endpoint,
        # but the key persistence itself is tested above. We can verify log instead.
        entries = second.get("/log").json()
        assert len(entries) == 1
        payload = json.loads(base64.b64decode(entries[0]["payload_canonical"]).decode("utf-8"))
        assert payload["credential_id"] == cred_id
        
    # Restore app module state to avoid breaking other tests
    monkeypatch.delenv("SWARMSEC_REGISTRAR_KEY_FILE", raising=False)
    monkeypatch.delenv("SWARMSEC_LOG_FILE", raising=False)
    importlib.reload(app_module)
