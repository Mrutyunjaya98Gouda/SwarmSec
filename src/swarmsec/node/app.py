"""SwarmSec Node Daemon (FastAPI).

Provides the P2P gossip endpoints and the local query endpoints.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from swarmsec.node.models import SwarmSecMessage, StixIndicator, SignableEnvelopeFields
from swarmsec.node.verify import MessageVerifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# State
_PEERS = []
_MESSAGES = {}  # message_id -> SwarmSecMessage
_INDICATORS = {}  # indicator pattern -> list of message_ids (for corroboration tracking)
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


class PublishRequest(BaseModel):
    """Local request to publish a new indicator."""
    credential_id: str
    private_key_b64: str  # In a real system, the daemon would hold this securely
    pattern: str


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

    # 2. Store it locally
    _MESSAGES[message.envelope.message_id] = message
    
    pattern = message.payload.pattern
    if pattern not in _INDICATORS:
        _INDICATORS[pattern] = []
    _INDICATORS[pattern].append(message.envelope.message_id)

    # 3. Relay to other peers
    asyncio.create_task(_gossip_to_peers(message))

    return {"status": "accepted"}


@app.post("/publish")
async def publish_local(req: PublishRequest):
    """Originate a new message from this node."""
    import base64
    from swarmsec.crypto.keys import deserialize_private_key, sign
    from swarmsec.crypto.canonicalize import canonicalize
    from swarmsec.node.models import TLPMarking

    # Create payload
    payload = StixIndicator(
        pattern=req.pattern,
        object_marking_refs=[TLPMarking.GREEN]
    )

    # Create envelope
    envelope = SignableEnvelopeFields(
        credential_id=req.credential_id,
        sequence_number=1,  # Hardcoded for demo
        payload_hash=""  # Will be computed
    )
    
    msg = SwarmSecMessage(envelope=envelope, payload=payload)
    msg.envelope.payload_hash = msg.compute_payload_hash()
    
    # Sign envelope
    signable_bytes = canonicalize(msg.envelope.model_dump_for_signature())
    privkey = deserialize_private_key(base64.b64decode(req.private_key_b64))
    signature_bytes = sign(privkey, signable_bytes)
    msg.signature = base64.b64encode(signature_bytes).decode("ascii")

    # Store locally and gossip
    _MESSAGES[msg.envelope.message_id] = msg
    if req.pattern not in _INDICATORS:
        _INDICATORS[req.pattern] = []
    _INDICATORS[req.pattern].append(msg.envelope.message_id)
    
    asyncio.create_task(_gossip_to_peers(msg))
    
    return {"status": "published", "message_id": msg.envelope.message_id}


@app.get("/query")
def query_indicator(pattern: str):
    """Query the local node for an indicator."""
    if pattern not in _INDICATORS:
        raise HTTPException(status_code=404, detail="Indicator not found")
        
    sources = _INDICATORS[pattern]
    if len(sources) == 1:
        return {
            "status": "UNCONFIRMED — single source, awaiting corroboration",
            "sources": sources
        }
    
    # In Sprint 3, this will compute a real score
    return {
        "status": "CONFIRMED",
        "score": len(sources),
        "sources": sources
    }
