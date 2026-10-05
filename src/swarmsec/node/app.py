"""SwarmSec Node Daemon (FastAPI).

Provides the P2P gossip endpoints and the local query endpoints.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from swarmsec.node.models import SignableEnvelopeFields, StixIndicator, SwarmSecMessage
from swarmsec.node.verify import MessageVerifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# State
_PEERS = []
_MESSAGES = {}  # message_id -> SwarmSecMessage
_INDICATORS = {}  # indicator pattern -> list of message_ids (for corroboration tracking)
_FEEDBACKS = {}  # indicator_id -> list of message_ids (for feedback tracking)
_REVOKED_CREDENTIALS = set()
_SEQ_NUMS = {}  # credential_id -> int (highest sequence number seen)
_VERIFIER = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _PEERS, _VERIFIER
    
    registrar_url = os.environ.get("REGISTRAR_URL", "http://registrar:8000")
    _VERIFIER = MessageVerifier(registrar_url)
    
    peers_env = os.environ.get("PEERS", "")
    if peers_env:
        _PEERS = [p.strip() for p in peers_env.split(",") if p.strip()]
        
    logger.info(f"Node started. Peers: {_PEERS}")
    yield


app = FastAPI(title="SwarmSec Node", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PublishRequest(BaseModel):
    """Local request to publish a new indicator."""
    credential_id: str
    private_key_b64: str | None = None  # Loaded from env if not provided
    pattern: str


class PublishFeedbackRequest(BaseModel):
    """Local request to publish feedback (Opinion) on an existing indicator."""
    credential_id: str
    private_key_b64: str | None = None
    indicator_id: str
    opinion: str = "agree"


async def _gossip_to_peers(message: SwarmSecMessage):
    """Relay a message to all known peers."""
    async with httpx.AsyncClient() as client:
        for peer in _PEERS:
            try:
                # Fire and forget (in a real system, we'd handle retries and avoid loops)
                await client.post(f"{peer}/gossip", json=message.model_dump(), timeout=2.0)
            except Exception as e:
                logger.warning(f"Failed to gossip to {peer}: {e}")


@app.post("/gossip")
async def receive_gossip(message: SwarmSecMessage):
    """Receive a message from the P2P network."""
    if message.envelope.message_id in _MESSAGES:
        return {"status": "already_seen"}

    # 1. Peer-side verification
    is_valid, reason = await _VERIFIER.verify(message)
    if not is_valid:
        logger.warning(f"Message rejected: {reason}")
        raise HTTPException(status_code=400, detail=f"Rejected: {reason}")

    # 1.5 Sequence number check (prevent stale replay)
    current_seq = _SEQ_NUMS.get(message.envelope.credential_id, 0)
    if message.envelope.sequence_number <= current_seq:
        return {"status": "rejected_stale_sequence"}

    # 2. Store it locally and update sequence number
    _MESSAGES[message.envelope.message_id] = message
    _SEQ_NUMS[message.envelope.credential_id] = message.envelope.sequence_number
    
    if message.payload.type == "indicator":
        pattern = message.payload.pattern
        if pattern not in _INDICATORS:
            _INDICATORS[pattern] = []
        _INDICATORS[pattern].append(message.envelope.message_id)
    elif message.payload.type == "opinion":
        for target_id in message.payload.object_refs:
            if target_id not in _FEEDBACKS:
                _FEEDBACKS[target_id] = []
            _FEEDBACKS[target_id].append(message.envelope.message_id)

    # 3. Relay to other peers
    asyncio.create_task(_gossip_to_peers(message))

    return {"status": "accepted"}


@app.post("/gossip/revocation")
async def receive_revocation(update_data: dict):
    """Receive a credential revocation status update and gossip it."""
    from swarmsec.registrar.models import CredentialStatusUpdate
    try:
        update = CredentialStatusUpdate(**update_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid update: {e}")
        
    if update.credential_id in _REVOKED_CREDENTIALS:
        return {"status": "already_revoked"}
        
    # In a real implementation, we would verify the registrar's signature on the update here.
    # _VERIFIER.verify_status_update(update)
    
    _REVOKED_CREDENTIALS.add(update.credential_id)
    
    # Gossip to peers
    async with httpx.AsyncClient() as client:
        for peer in _PEERS:
            try:
                await client.post(f"{peer}/gossip/revocation", json=update_data, timeout=2.0)
            except Exception:
                pass
                
    return {"status": "revoked_locally"}


@app.post("/publish")
async def publish_local(req: PublishRequest):
    """Originate a new message from this node."""
    import base64

    from swarmsec.crypto.canonicalize import canonicalize
    from swarmsec.crypto.keys import deserialize_private_key, sign
    from swarmsec.node.models import TLPMarking

    # Create payload
    payload = StixIndicator(
        pattern=req.pattern,
        object_marking_refs=[TLPMarking.GREEN]
    )

    seq = _SEQ_NUMS.get(req.credential_id, 0) + 1
    
    # Create envelope
    envelope = SignableEnvelopeFields(
        credential_id=req.credential_id,
        sequence_number=seq,
        payload_hash=""  # Will be computed
    )
    
    msg = SwarmSecMessage(envelope=envelope, payload=payload)
    msg.envelope.payload_hash = msg.compute_payload_hash()
    
    # Sign envelope
    signable_bytes = canonicalize(msg.envelope.model_dump_for_signature())
    
    privkey_b64 = req.private_key_b64 or os.environ.get("NODE_PRIVATE_KEY_B64")
    if not privkey_b64:
        raise HTTPException(status_code=500, detail="Node private key not configured")
        
    privkey = deserialize_private_key(base64.b64decode(privkey_b64))
    signature_bytes = sign(privkey, signable_bytes)
    msg.signature = base64.b64encode(signature_bytes).decode("ascii")

    # Store locally and gossip
    _MESSAGES[msg.envelope.message_id] = msg
    _SEQ_NUMS[req.credential_id] = seq
    
    if req.pattern not in _INDICATORS:
        _INDICATORS[req.pattern] = []
    _INDICATORS[req.pattern].append(msg.envelope.message_id)
    
    asyncio.create_task(_gossip_to_peers(msg))
    
    return {
        "status": "published",
        "message_id": msg.envelope.message_id,
        "indicator_id": msg.payload.id,
    }


@app.post("/feedback")
async def publish_feedback(req: PublishFeedbackRequest):
    """Originate a new feedback (Opinion) message from this node."""
    import base64

    from swarmsec.crypto.canonicalize import canonicalize
    from swarmsec.crypto.keys import deserialize_private_key, sign
    from swarmsec.node.models import StixOpinion, TLPMarking

    payload = StixOpinion(
        opinion=req.opinion,
        object_refs=[req.indicator_id],
        object_marking_refs=[TLPMarking.GREEN]
    )

    seq = _SEQ_NUMS.get(req.credential_id, 0) + 1

    envelope = SignableEnvelopeFields(
        credential_id=req.credential_id,
        sequence_number=seq,
        payload_hash=""
    )
    
    msg = SwarmSecMessage(envelope=envelope, payload=payload)
    msg.envelope.payload_hash = msg.compute_payload_hash()
    
    signable_bytes = canonicalize(msg.envelope.model_dump_for_signature())
    
    privkey_b64 = req.private_key_b64 or os.environ.get("NODE_PRIVATE_KEY_B64")
    if not privkey_b64:
        raise HTTPException(status_code=500, detail="Node private key not configured")
        
    privkey = deserialize_private_key(base64.b64decode(privkey_b64))
    signature_bytes = sign(privkey, signable_bytes)
    msg.signature = base64.b64encode(signature_bytes).decode("ascii")

    _MESSAGES[msg.envelope.message_id] = msg
    _SEQ_NUMS[req.credential_id] = seq
    
    for target_id in payload.object_refs:
        if target_id not in _FEEDBACKS:
            _FEEDBACKS[target_id] = []
        _FEEDBACKS[target_id].append(msg.envelope.message_id)
    
    asyncio.create_task(_gossip_to_peers(msg))
    
    return {"status": "feedback_published", "message_id": msg.envelope.message_id}


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/query")
def query_indicator(pattern: str):
    """Query the local node for an indicator."""
    from swarmsec.node.scoring import compute_corroboration_score
    
    if pattern not in _INDICATORS:
        raise HTTPException(status_code=404, detail="Indicator not found")
        
    message_ids = _INDICATORS[pattern]
    messages = [_MESSAGES[mid] for mid in message_ids if mid in _MESSAGES]
    
    # Collect feedback (Opinion messages) targeting any indicator in these messages
    feedback_messages = []
    for msg in messages:
        for tid in (msg.payload.id, msg.envelope.message_id):
            if tid in _FEEDBACKS:
                for fb_mid in _FEEDBACKS[tid]:
                    if fb_mid in _MESSAGES and _MESSAGES[fb_mid] not in feedback_messages:
                        feedback_messages.append(_MESSAGES[fb_mid])
    
    result = compute_corroboration_score(
        messages,
        feedbacks=feedback_messages if feedback_messages else None,
        all_messages=_MESSAGES if feedback_messages else None
    )
    
    # Add sources for reference
    result["sources"] = message_ids
    result["pattern"] = pattern
    result["advisory_disclaimer"] = (
        "ADVISORY ONLY: SwarmSec computes local corroboration scores and trust rankings. "
        "This is NOT an automated block/allow decision; a human analyst must make that call."
    )
    return result


@app.get("/feed")
def get_feed(format: str = "json"):
    """Retrieve all indicators ranked by local corroboration score."""
    from uuid import uuid4
    
    if format.lower() == "stix":
        return {
            "type": "bundle",
            "id": f"bundle--{uuid4()}",
            "objects": [msg.payload.model_dump() for msg in _MESSAGES.values()]
        }
        
    from swarmsec.node.scoring import compute_corroboration_score

    items = []
    for pattern, message_ids in _INDICATORS.items():
        messages = [_MESSAGES[mid] for mid in message_ids if mid in _MESSAGES]
        if not messages:
            continue

        feedback_messages = []
        for msg in messages:
            for tid in (msg.payload.id, msg.envelope.message_id):
                if tid in _FEEDBACKS:
                    for fb_mid in _FEEDBACKS[tid]:
                        if fb_mid in _MESSAGES and _MESSAGES[fb_mid] not in feedback_messages:
                            feedback_messages.append(_MESSAGES[fb_mid])

        score_data = compute_corroboration_score(
            messages,
            feedbacks=feedback_messages if feedback_messages else None,
            all_messages=_MESSAGES if feedback_messages else None,
        )

        first_msg = min(messages, key=lambda m: m.envelope.timestamp)
        latest_msg = max(messages, key=lambda m: m.envelope.timestamp)

        item = {
            "pattern": pattern,
            "local_corroboration_score": score_data["local_corroboration_score"],
            "status": score_data["status"],
            "independent_sources": score_data["independent_sources"],
            "flags": score_data["flags"],
            "downweighted": "feedback_downweighted" in score_data["flags"],
            "reports_count": len(messages),
            "feedback_count": len(feedback_messages),
            "first_seen": first_msg.envelope.timestamp,
            "last_seen": latest_msg.envelope.timestamp,
            "sources": message_ids,
            "identities": list(set([m.envelope.credential_id for m in messages])),
        }
        items.append(item)

    # Sort descending by score, then latest_seen
    items.sort(key=lambda x: (x["local_corroboration_score"], x["last_seen"]), reverse=True)

    return {
        "ranked_indicators": items,
        "total_indicators": len(items),
        "total_messages": len(_MESSAGES),
        "advisory_disclaimer": (
            "ADVISORY ONLY: SwarmSec computes local corroboration scores and trust rankings. "
            "This is NOT an automated block/allow decision; a human analyst must make that call."
        ),
    }
