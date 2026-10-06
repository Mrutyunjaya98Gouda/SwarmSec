"""Tests for trust scoring and corroboration."""

from datetime import UTC, datetime, timedelta

from swarmsec.node.models import (
    SignableEnvelopeFields,
    StixExternalReference,
    StixIndicator,
    SwarmSecMessage,
    TLPMarking,
)
from swarmsec.node.scoring import (
    compute_corroboration_score,
    get_pattern_entropy_weight,
)


def create_message(
    credential_id: str,
    pattern: str,
    minutes_offset: int = 0,
    feed_url: str = None
) -> SwarmSecMessage:
    ts = (datetime.now(UTC) + timedelta(minutes=minutes_offset)).isoformat() + "Z"
    
    ext_refs = []
    if feed_url:
        ext_refs.append(StixExternalReference(source_name="feed", url=feed_url))
        
    payload = StixIndicator(
        pattern=pattern,
        object_marking_refs=[TLPMarking.CLEAR],
        external_references=ext_refs
    )
    
    envelope = SignableEnvelopeFields(
        credential_id=credential_id,
        sequence_number=1,
        timestamp=ts,
        payload_hash="dummy"
    )
    
    return SwarmSecMessage(envelope=envelope, payload=payload, signature="dummy")


def test_entropy_weights():
    assert get_pattern_entropy_weight("[file:hashes.'SHA-256' = 'abc']") == 1.0
    assert get_pattern_entropy_weight("[url:value = 'http://example.com']") == 0.8
    assert get_pattern_entropy_weight("[ipv4-addr:value = '10.0.0.1']") == 0.5


def test_single_source_unconfirmed():
    msg = create_message("cred1", "[ipv4-addr:value = '10.0.0.1']")
    result = compute_corroboration_score([msg])
    
    assert result["status"] == "UNCONFIRMED — single source, awaiting corroboration"
    assert result["local_corroboration_score"] == 0.0
    assert result["independent_sources"] == 1
    assert result["flags"] == []


def test_independent_corroboration():
    # Two different credentials report the same IPv4
    msg1 = create_message("cred1", "[ipv4-addr:value = '10.0.0.1']", minutes_offset=0)
    msg2 = create_message("cred2", "[ipv4-addr:value = '10.0.0.1']", minutes_offset=1)
    
    result = compute_corroboration_score([msg1, msg2])
    
    assert result["status"] == "UNCONFIRMED — insufficient confidence score"
    # Base score 0 + 1 * 0.5 (IPv4 weight)
    assert result["local_corroboration_score"] == 0.5
    assert result["independent_sources"] == 2
    assert result["flags"] == ["missing_references_low_confidence"]


def test_high_entropy_corroboration():
    # Two different credentials report the same hash
    msg1 = create_message("cred1", "[file:hashes.'SHA-256' = 'abc']", minutes_offset=0)
    msg2 = create_message("cred2", "[file:hashes.'SHA-256' = 'abc']", minutes_offset=1)
    msg3 = create_message("cred3", "[file:hashes.'SHA-256' = 'abc']", minutes_offset=2)
    
    result = compute_corroboration_score([msg1, msg2, msg3])
    
    assert result["status"] == "CONFIRMED — high confidence"
    # Base score 0 + 2 * 1.0 (Hash weight)
    assert result["local_corroboration_score"] == 2.0
    assert result["independent_sources"] == 3


def test_feed_overlap_flagged():
    # Two credentials report the exact same feed URL
    msg1 = create_message(
        "cred1", "[ipv4-addr:value = '10.0.0.1']", 
        minutes_offset=0, feed_url="https://alienvault.com/pulse/1"
    )
    msg2 = create_message(
        "cred2", "[ipv4-addr:value = '10.0.0.1']", 
        minutes_offset=1, feed_url="https://alienvault.com/pulse/1"
    )
    
    result = compute_corroboration_score([msg1, msg2])
    
    assert result["status"] == "UNCONFIRMED — single source, awaiting corroboration"
    assert result["local_corroboration_score"] == 0.0
    assert result["independent_sources"] == 1
    assert "feed_overlap" in result["flags"]


def test_same_credential_deduplicated():
    # Same credential reporting twice doesn't add corroboration
    msg1 = create_message("cred1", "[ipv4-addr:value = '10.0.0.1']", minutes_offset=0)
    msg2 = create_message("cred1", "[ipv4-addr:value = '10.0.0.1']", minutes_offset=1)
    
    result = compute_corroboration_score([msg1, msg2])
    
    assert result["status"] == "UNCONFIRMED — single source, awaiting corroboration"
    assert result["local_corroboration_score"] == 0.0
    assert result["independent_sources"] == 1
