"""Tests for the FastAPI registrar service."""

import base64

import pytest
from fastapi.testclient import TestClient

from swarmsec.crypto.keys import generate_keypair, serialize_public_key
from swarmsec.registrar.app import create_app
from swarmsec.registrar.credential import verify_credential
from swarmsec.registrar.models import Credential


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("SWARMSEC_LOG_FILE", raising=False)
    monkeypatch.delenv("SWARMSEC_REGISTRAR_KEY_FILE", raising=False)
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
def pseudo_pubkey_b64():
    _, pub = generate_keypair()
    return base64.b64encode(serialize_public_key(pub)).decode("ascii")


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_get_pubkey(client):
    response = client.get("/pubkey")
    assert response.status_code == 200
    data = response.json()
    assert "public_key_b64" in data
    assert len(base64.b64decode(data["public_key_b64"])) == 32


def test_register_success(client, pseudo_pubkey_b64):
    response = client.post(
        "/register",
        json={"org_id": "org-a", "pseudonym_public_key": pseudo_pubkey_b64},
    )
    assert response.status_code == 200
    data = response.json()
    cred = data["credential"]
    assert cred["pseudonym_public_key"] == pseudo_pubkey_b64
    assert cred["status"] == "active"
    assert cred["registrar_signature"]
    assert not cred["issued_at"].endswith("+00:00Z")
    assert cred["issued_at"].endswith("Z")


def test_register_rejected_unknown_org(client, pseudo_pubkey_b64):
    response = client.post(
        "/register",
        json={"org_id": "unknown-org", "pseudonym_public_key": pseudo_pubkey_b64},
    )
    assert response.status_code == 403
    assert "not in allowlist" in response.json()["detail"].lower()


def test_register_rejects_invalid_base64(client):
    response = client.post(
        "/register",
        json={"org_id": "org-a", "pseudonym_public_key": "%%%not-base64%%%"},
    )
    assert response.status_code == 400


def test_register_rejects_wrong_length_key(client):
    short = base64.b64encode(b"too-short").decode("ascii")
    response = client.post(
        "/register",
        json={"org_id": "org-a", "pseudonym_public_key": short},
    )
    assert response.status_code == 400


def test_register_accepts_any_32_byte_ed25519_encoding(client):
    """Ed25519 public keys are 32-byte strings; the library accepts any length-32 value."""
    raw = bytes(range(32))
    b64 = base64.b64encode(raw).decode("ascii")
    response = client.post(
        "/register",
        json={"org_id": "org-a", "pseudonym_public_key": b64},
    )
    assert response.status_code == 200


def test_get_credential_returns_signed_record(client, pseudo_pubkey_b64):
    created = client.post(
        "/register",
        json={"org_id": "org-a", "pseudonym_public_key": pseudo_pubkey_b64},
    ).json()
    cred_id = created["credential"]["credential_id"]
    response = client.get(f"/credential/{cred_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["resolved_status"] == "active"
    assert body["credential"]["registrar_signature"] == created["credential"]["registrar_signature"]
    assert body["latest_status_update"] is None


def test_get_unknown_credential_404(client):
    response = client.get("/credential/does-not-exist")
    assert response.status_code == 404


def test_revoke_unknown_credential_404(client):
    response = client.post("/credential/some-id/revoke")
    assert response.status_code == 404


def test_revoke_known_credential(client, pseudo_pubkey_b64):
    created = client.post(
        "/register",
        json={"org_id": "org-a", "pseudonym_public_key": pseudo_pubkey_b64},
    ).json()
    cred_id = created["credential"]["credential_id"]
    response = client.post(f"/credential/{cred_id}/revoke")
    assert response.status_code == 200
    assert response.json()["new_status"] == "revoked"
    lookup = client.get(f"/credential/{cred_id}").json()
    assert lookup["resolved_status"] == "revoked"
    assert lookup["credential"]["status"] == "active"
    assert lookup["latest_status_update"]["new_status"] == "revoked"


def test_log_stores_full_signed_credential(client, pseudo_pubkey_b64):
    created = client.post(
        "/register",
        json={"org_id": "org-a", "pseudonym_public_key": pseudo_pubkey_b64},
    ).json()
    entries = client.get("/log").json()
    import json

    payload = json.loads(base64.b64decode(entries[-1]["payload_canonical"]).decode("utf-8"))
    assert payload["record_type"] == "credential"
    assert payload["record"]["registrar_signature"] == created["credential"]["registrar_signature"]


def test_tampered_log_public_key_fails_verify_credential(client, pseudo_pubkey_b64):
    created = client.post(
        "/register",
        json={"org_id": "org-a", "pseudonym_public_key": pseudo_pubkey_b64},
    ).json()
    pubkey_b64 = client.get("/pubkey").json()["public_key_b64"]
    from swarmsec.crypto.keys import deserialize_public_key

    registrar_pub = deserialize_public_key(base64.b64decode(pubkey_b64))
    cred = Credential(**created["credential"])
    assert verify_credential(cred, registrar_pub)

    _, other_pub = generate_keypair()
    cred.pseudonym_public_key = base64.b64encode(serialize_public_key(other_pub)).decode("ascii")
    assert not verify_credential(cred, registrar_pub)

    cred = Credential(**created["credential"])
    cred.status = "revoked"
    assert not verify_credential(cred, registrar_pub)


def test_log_verify(client, pseudo_pubkey_b64):
    client.post(
        "/register",
        json={"org_id": "org-b", "pseudonym_public_key": pseudo_pubkey_b64},
    )
    response = client.get("/log/verify")
    assert response.status_code == 200
    assert response.json()["is_valid"] is True


def test_registrar_key_persists_across_restarts(tmp_path, monkeypatch, pseudo_pubkey_b64):
    key_file = tmp_path / "registrar.key"
    log_file = tmp_path / "log.jsonl"
    monkeypatch.setenv("SWARMSEC_REGISTRAR_KEY_FILE", str(key_file))
    monkeypatch.setenv("SWARMSEC_LOG_FILE", str(log_file))

    with TestClient(create_app()) as first:
        pk1 = first.get("/pubkey").json()["public_key_b64"]
        created = first.post(
            "/register",
            json={"org_id": "org-a", "pseudonym_public_key": pseudo_pubkey_b64},
        ).json()
        cred_id = created["credential"]["credential_id"]

    with TestClient(create_app()) as second:
        pk2 = second.get("/pubkey").json()["public_key_b64"]
        assert pk1 == pk2
        lookup = second.get(f"/credential/{cred_id}")
        assert lookup.status_code == 200
        from swarmsec.crypto.keys import deserialize_public_key

        registrar_pub = deserialize_public_key(base64.b64decode(pk2))
        cred = Credential(**lookup.json()["credential"])
        assert verify_credential(cred, registrar_pub)
