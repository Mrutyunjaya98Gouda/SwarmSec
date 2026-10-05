"""Tests for peer-side gossip verification."""

import base64
import json
from unittest.mock import Mock, patch, AsyncMock

import pytest
from httpx import Response

from swarmsec.crypto.keys import generate_keypair, serialize_public_key, sign, serialize_private_key
from swarmsec.node.models import (
    SignableEnvelopeFields,
    StixIndicator,
    StixOpinion,
    SwarmSecMessage,
    TLPMarking,
)
from swarmsec.registrar.credential import issue_credential
from swarmsec.node.verify import MessageVerifier


@pytest.fixture
def mock_keys():
    priv, pub = generate_keypair()
    b64_pub = base64.b64encode(serialize_public_key(pub)).decode("ascii")
    return priv, b64_pub


@pytest.fixture
def registrar_keys():
    """A fresh registrar keypair for credential issuance."""
    priv, pub = generate_keypair()
    return priv, pub


@pytest.fixture
def valid_message(mock_keys):
    priv, _ = mock_keys
    payload = StixIndicator(
        pattern="[ipv4-addr:value = '10.0.0.1']",
        object_marking_refs=[TLPMarking.CLEAR]
    )
    envelope = SignableEnvelopeFields(
        credential_id="test-cred-123",
        sequence_number=1,
        payload_hash=""
    )
    msg = SwarmSecMessage(envelope=envelope, payload=payload)
    msg.envelope.payload_hash = msg.compute_payload_hash()

    from swarmsec.crypto.canonicalize import canonicalize
    signable_bytes = canonicalize(msg.envelope.model_dump_for_signature())
    sig_bytes = sign(priv, signable_bytes)
    msg.signature = base64.b64encode(sig_bytes).decode("ascii")

    return msg


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def _build_mock_verifier(pseudonym_b64_pub: str, registrar_priv, registrar_pub,
                         credential_id: str = "test-cred-123") -> MessageVerifier:
    """Build a MessageVerifier with a properly signed credential in the mock log."""
    from swarmsec.registrar.credential import issue_credential
    from swarmsec.crypto.keys import deserialize_public_key, serialize_public_key

    cred = issue_credential(pseudonym_b64_pub, registrar_priv)
    cred.credential_id = credential_id

    # Re-sign with the correct credential_id
    from swarmsec.crypto.canonicalize import canonicalize
    from swarmsec.crypto.keys import sign as _sign
    canonical_bytes = canonicalize(cred.signable_fields())
    sig = _sign(registrar_priv, canonical_bytes)
    cred.registrar_signature = base64.b64encode(sig).decode("ascii")

    cred_dict = cred.model_dump(mode="json")

    with patch.object(MessageVerifier, '_fetch_registrar_pubkey'):
        verifier = MessageVerifier("http://mock-registrar")

    verifier.registrar_pubkey = registrar_pub

    verifier._get_credential_from_log = AsyncMock(return_value={
        "public_key": pseudonym_b64_pub,
        "status": "active",
        "registrar_signature": cred.registrar_signature,
        "credential": cred_dict,
    })

    return verifier


@pytest.fixture
def mock_verifier(mock_keys, registrar_keys):
    """A MessageVerifier with a properly-signed credential in the mock log."""
    _, b64_pub = mock_keys
    reg_priv, reg_pub = registrar_keys
    return _build_mock_verifier(b64_pub, reg_priv, reg_pub)


@pytest.mark.anyio
async def test_verify_valid_message(mock_verifier, valid_message):
    is_valid, reason = await mock_verifier.verify(valid_message)
    assert is_valid is True
    assert reason == "OK"


@pytest.mark.anyio
async def test_reject_bad_payload_hash(mock_verifier, valid_message):
    # Tamper with the payload hash
    valid_message.envelope.payload_hash = "0" * 64
    is_valid, reason = await mock_verifier.verify(valid_message)
    assert is_valid is False
    assert reason == "Payload hash mismatch"


@pytest.mark.anyio
async def test_reject_bad_signature(mock_verifier, valid_message):
    # Tamper with the envelope signature directly
    valid_message.signature = base64.b64encode(b"0" * 64).decode("ascii")

    is_valid, reason = await mock_verifier.verify(valid_message)
    assert is_valid is False
    assert reason == "Invalid signature"


@pytest.mark.anyio
async def test_reject_revoked_credential(mock_verifier, valid_message):
    mock_verifier._get_credential_from_log.return_value["status"] = "revoked"

    is_valid, reason = await mock_verifier.verify(valid_message)
    assert is_valid is False
    assert reason == "Credential revoked"


@pytest.mark.anyio
async def test_reject_invalid_registrar_signature(mock_keys, registrar_keys, valid_message):
    """A credential whose registrar_signature doesn't verify must be rejected."""
    _, b64_pub = mock_keys
    reg_priv, reg_pub = registrar_keys

    # Build a valid verifier, then corrupt just the registrar_signature
    verifier = _build_mock_verifier(b64_pub, reg_priv, reg_pub)
    cred_dict = dict(verifier._get_credential_from_log.return_value["credential"])
    cred_dict["registrar_signature"] = base64.b64encode(b"0" * 64).decode("ascii")
    verifier._get_credential_from_log.return_value["credential"] = cred_dict
    verifier._get_credential_from_log.return_value["registrar_signature"] = cred_dict["registrar_signature"]

    is_valid, reason = await verifier.verify(valid_message)
    assert is_valid is False
    assert "registrar" in reason.lower()


@pytest.mark.anyio
async def test_reject_exhausted_ticket(mock_verifier, mock_keys):
    """After MAX_MESSAGES_PER_EPOCH (5) distinct messages from the same credential,
    the next one must be rejected. Each message has a distinct message_id to avoid
    tripping the replay check."""
    priv, _ = mock_keys

    def _make_fresh_msg(seq: int) -> SwarmSecMessage:
        payload = StixIndicator(
            pattern=f"[ipv4-addr:value = '10.0.0.{seq}']",
            object_marking_refs=[TLPMarking.GREEN],
        )
        envelope = SignableEnvelopeFields(
            credential_id="test-cred-123",
            sequence_number=seq,
            payload_hash="",
        )
        msg = SwarmSecMessage(envelope=envelope, payload=payload)
        msg.envelope.payload_hash = msg.compute_payload_hash()
        from swarmsec.crypto.canonicalize import canonicalize
        sig_bytes = sign(priv, canonicalize(msg.envelope.model_dump_for_signature()))
        msg.signature = base64.b64encode(sig_bytes).decode("ascii")
        return msg

    # Send 5 distinct messages — each should be accepted
    for seq in range(1, 6):
        msg = _make_fresh_msg(seq)
        is_valid, reason = await mock_verifier.verify(msg)
        assert is_valid is True, f"Message {seq} should be accepted, got: {reason}"

    # The 6th message should be rejected (epoch rate limit exhausted)
    msg6 = _make_fresh_msg(6)
    is_valid, reason = await mock_verifier.verify(msg6)
    assert is_valid is False
    assert reason == "Rate limit exceeded"


@pytest.mark.anyio
async def test_reject_replayed_message_id(mock_verifier, mock_keys):
    """The same message_id sent twice must be rejected on the second attempt,
    even if it arrives within the same rate-limit epoch."""
    priv, b64_pub = mock_keys

    def _make_msg(pattern: str):
        payload = StixIndicator(
            pattern=pattern,
            object_marking_refs=[TLPMarking.GREEN],
        )
        envelope = SignableEnvelopeFields(
            credential_id="test-cred-123",
            sequence_number=1,
            payload_hash="",
        )
        msg = SwarmSecMessage(envelope=envelope, payload=payload)
        msg.envelope.payload_hash = msg.compute_payload_hash()
        from swarmsec.crypto.canonicalize import canonicalize
        sig_bytes = sign(priv, canonicalize(msg.envelope.model_dump_for_signature()))
        msg.signature = base64.b64encode(sig_bytes).decode("ascii")
        return msg

    msg1 = _make_msg("[ipv4-addr:value = '1.2.3.4']")

    # First delivery: accepted
    is_valid, reason = await mock_verifier.verify(msg1)
    assert is_valid is True, f"First delivery should be accepted, got: {reason}"

    # Second delivery (same message_id): must be rejected as replay
    is_valid, reason = await mock_verifier.verify(msg1)
    assert is_valid is False, "Replayed message_id should be rejected"
    assert reason == "Rate limit exceeded"  # replay is caught by check_and_consume


@pytest.mark.anyio
async def test_feedback_before_target_indicator_handled_gracefully(mock_verifier, mock_keys):
    """An Opinion message whose object_refs point to an unknown indicator must
    be accepted at the gossip layer (the scoring layer ignores unknown refs).
    This test confirms the verifier does not crash or wrongly reject it."""
    priv, _ = mock_keys

    feedback_payload = StixOpinion(
        opinion="agree",
        object_refs=["indicator--00000000-0000-0000-0000-000000000000"],
        object_marking_refs=[TLPMarking.GREEN],
    )
    envelope = SignableEnvelopeFields(
        credential_id="test-cred-123",
        sequence_number=1,
        payload_hash="",
    )
    msg = SwarmSecMessage(envelope=envelope, payload=feedback_payload)
    msg.envelope.payload_hash = msg.compute_payload_hash()
    from swarmsec.crypto.canonicalize import canonicalize
    sig_bytes = sign(priv, canonicalize(msg.envelope.model_dump_for_signature()))
    msg.signature = base64.b64encode(sig_bytes).decode("ascii")

    is_valid, reason = await mock_verifier.verify(msg)
    assert is_valid is True, (
        f"Feedback before target indicator should not be rejected at gossip layer, got: {reason}"
    )
