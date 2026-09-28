"""Tests for peer-side gossip verification."""

import base64
import json
from unittest.mock import Mock, patch

import pytest
from httpx import Response

from swarmsec.crypto.keys import generate_keypair, serialize_public_key, sign
from swarmsec.node.models import (
    SignableEnvelopeFields,
    StixIndicator,
    SwarmSecMessage,
    TLPMarking,
)
from swarmsec.node.verify import MessageVerifier


@pytest.fixture
def mock_keys():
    priv, pub = generate_keypair()
    b64_pub = base64.b64encode(serialize_public_key(pub)).decode("ascii")
    return priv, b64_pub


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

@pytest.fixture
def mock_verifier(mock_keys):
    """A MessageVerifier with mocked internal methods to avoid HTTP calls."""
    from unittest.mock import AsyncMock
    _, b64_pub = mock_keys
    
    with patch.object(MessageVerifier, '_fetch_registrar_pubkey'):
        verifier = MessageVerifier("http://mock-registrar")
        
    verifier._get_credential_from_log = AsyncMock(return_value={
        "public_key": b64_pub,
        "status": "active"
    })
    
    return verifier


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
    # Tamper with the signature directly
    valid_message.signature = base64.b64encode(b"0" * 64).decode("ascii")
    
    is_valid, reason = await mock_verifier.verify(valid_message)
    assert is_valid is False
    assert reason == "Invalid signature"


@pytest.mark.anyio
async def test_reject_revoked_credential(mock_verifier, valid_message):
    # Make the mock registrar return 'revoked'
    # For AsyncMock, we need to return the dict directly or handle it
    # But since _get_credential_from_log is mocked as a standard Mock, 
    # we should mock it as an AsyncMock to be safe, or just return an awaitable.
    # Actually, in mock_verifier, let's just make it an AsyncMock
    mock_verifier._get_credential_from_log.return_value["status"] = "revoked"
    
    is_valid, reason = await mock_verifier.verify(valid_message)
    assert is_valid is False
    assert reason == "Credential revoked"


@pytest.mark.anyio
async def test_reject_exhausted_ticket(mock_verifier, valid_message):
    # Send 5 messages (MAX_MESSAGES_PER_EPOCH)
    for _ in range(5):
        is_valid, _ = await mock_verifier.verify(valid_message)
        assert is_valid is True
        
    # The 6th message should be rejected
    is_valid, reason = await mock_verifier.verify(valid_message)
    assert is_valid is False
    assert reason == "Rate limit exceeded"
