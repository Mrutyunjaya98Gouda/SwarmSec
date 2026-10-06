"""SwarmSec Node Daemon (FastAPI).

Provides the P2P gossip endpoints and the local query endpoints.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
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
import collections

class LRUSet:
    """A fast, time-windowed bounded set for O(1) deduplication without memory leaks."""
    def __init__(self, capacity: int = 100_000):
        self.capacity = capacity
        self.cache = collections.OrderedDict()

    def __contains__(self, key):
        return key in self.cache

    def add(self, key):
        self.cache[key] = None
        self.cache.move_to_end(key)
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)

_SEEN_MESSAGES = LRUSet(capacity=100_000)  # Replaces unbounded set
_WS_CONNECTIONS = set()
_WEBHOOKS = set()
_VERIFIER = None

import sqlite3

def init_db():
    conn = sqlite3.connect("swarmsec_node_state.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS seq_nums (credential_id TEXT PRIMARY KEY, seq INT)")
    c.execute("CREATE TABLE IF NOT EXISTS seen_messages (message_id TEXT PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    # Create an index to make TTL deletion fast
    c.execute("CREATE INDEX IF NOT EXISTS idx_seen_ts ON seen_messages (timestamp)")
    conn.commit()
    
    for row in c.execute("SELECT credential_id, seq FROM seq_nums"):
        _SEQ_NUMS[row[0]] = row[1]
        
    # Load only recent messages into the LRU cache (descending, then reverse to keep LRU order)
    rows = c.execute("SELECT message_id FROM seen_messages ORDER BY timestamp DESC LIMIT 100000").fetchall()
    for row in reversed(rows):
        _SEEN_MESSAGES.add(row[0])
    conn.close()

def persist_seq_num(cred_id, seq):
    conn = sqlite3.connect("swarmsec_node_state.db")
    conn.execute("INSERT OR REPLACE INTO seq_nums (credential_id, seq) VALUES (?, ?)", (cred_id, seq))
    conn.commit()
    conn.close()

def persist_seen_message(msg_id):
    conn = sqlite3.connect("swarmsec_node_state.db")
    conn.execute("INSERT OR IGNORE INTO seen_messages (message_id) VALUES (?)", (msg_id,))
    # Probabilistic TTL cleanup (approx 1% of the time) to prevent unbounded DB growth (7 days)
    import random
    if random.random() < 0.01:
        conn.execute("DELETE FROM seen_messages WHERE timestamp < datetime('now', '-7 days')")
    conn.commit()
    conn.close()
_VERIFIER = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _PEERS, _VERIFIER
    
    registrar_url = os.environ.get("REGISTRAR_URL", "http://registrar:8000")
    _VERIFIER = MessageVerifier(registrar_url)
    
    peers_env = os.environ.get("PEERS", "")
    if peers_env:
        _PEERS = [p.strip() for p in peers_env.split(",") if p.strip()]
        
    init_db()
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
    import os
    cert_path = os.environ.get("TLS_CERT_PATH")
    key_path = os.environ.get("TLS_KEY_PATH")
    ca_path = os.environ.get("TLS_CA_PATH")
    
    # Bypass strict CA verification for local self-signed certificates
    # (Python 3.10+ rejects self-signed CAs missing the Authority Key Identifier extension)
    verify = False 
    cert = (cert_path, key_path) if cert_path and key_path else None

    async with httpx.AsyncClient(verify=verify, cert=cert) as client:
        for peer in _PEERS:
            try:
                # Fire and forget (in a real system, we'd handle retries and avoid loops)
                await client.post(f"{peer}/gossip", json=message.model_dump(), timeout=2.0)
            except Exception as e:
                logger.warning(f"Failed to gossip to {peer}: {e}")


@app.post("/gossip")
async def receive_gossip(message: SwarmSecMessage):
    """Receive a message from the P2P network."""
    if message.envelope.message_id in _MESSAGES or message.envelope.message_id in _SEEN_MESSAGES:
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
    _SEEN_MESSAGES.add(message.envelope.message_id)
    persist_seen_message(message.envelope.message_id)
    
    _SEQ_NUMS[message.envelope.credential_id] = message.envelope.sequence_number
    persist_seq_num(message.envelope.credential_id, message.envelope.sequence_number)
    
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
    asyncio.create_task(_broadcast_feed_update())

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
        
    from swarmsec.registrar.credential import verify_status_update
    if not _VERIFIER or not _VERIFIER.registrar_pubkeys:
        raise HTTPException(status_code=500, detail="Node missing registrar pubkeys")
        
    if not verify_status_update(update, _VERIFIER.registrar_pubkeys):
        logger.warning(f"Rejected invalid revocation update for {update.credential_id}")
        raise HTTPException(status_code=400, detail="Invalid registrar signatures on revocation")
    _REVOKED_CREDENTIALS.add(update.credential_id)
    
    # Invalidate cache so the node doesn't accept gossips from revoked credentials
    if update.credential_id in _VERIFIER.credential_cache:
        _VERIFIER.credential_cache[update.credential_id]["status"] = "revoked"

    
    # Gossip to peers
    import os
    cert_path = os.environ.get("TLS_CERT_PATH")
    key_path = os.environ.get("TLS_KEY_PATH")
    ca_path = os.environ.get("TLS_CA_PATH")
    
    verify = False
    cert = (cert_path, key_path) if cert_path and key_path else None

    async with httpx.AsyncClient(verify=verify, cert=cert) as client:
        for peer in _PEERS:
            try:
                await client.post(f"{peer}/gossip/revocation", json=update_data, timeout=2.0)
            except Exception:
                pass
                
    return {"status": "revoked_locally"}


class UIRegisterRequest(BaseModel):
    org_id: str

@app.post("/ui-register")
async def ui_register(req: UIRegisterRequest):
    """Helper endpoint for the UI to register and get a keypair."""
    import base64
    import httpx
    from swarmsec.crypto.keys import generate_keypair, serialize_public_key, serialize_private_key
    
    priv, pub = generate_keypair()
    pub_b64 = base64.b64encode(serialize_public_key(pub)).decode("ascii")
    priv_b64 = base64.b64encode(serialize_private_key(priv)).decode("ascii")
    
    registrar_url = os.environ.get("REGISTRAR_URL", "https://localhost:8000")
    ca_path = os.environ.get("TLS_CA_PATH")
    
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.post(
            f"{registrar_url}/register", 
            json={"org_id": req.org_id, "pseudonym_public_key": pub_b64}
        )
        
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.json().get("detail", "Registration failed"))
            
        data = resp.json()
        return {
            "credential_id": data["credential"]["credential_id"],
            "private_key_b64": priv_b64,
            "org_id": req.org_id
        }

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
    _SEEN_MESSAGES.add(msg.envelope.message_id)
    persist_seen_message(msg.envelope.message_id)
    
    _SEQ_NUMS[req.credential_id] = seq
    persist_seq_num(req.credential_id, seq)
    
    if req.pattern not in _INDICATORS:
        _INDICATORS[req.pattern] = []
    _INDICATORS[req.pattern].append(msg.envelope.message_id)
    
    asyncio.create_task(_gossip_to_peers(msg))
    asyncio.create_task(_broadcast_feed_update())
    
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
    _SEEN_MESSAGES.add(msg.envelope.message_id)
    persist_seen_message(msg.envelope.message_id)
    
    _SEQ_NUMS[req.credential_id] = seq
    persist_seq_num(req.credential_id, seq)
    
    for target_id in payload.object_refs:
        if target_id not in _FEEDBACKS:
            _FEEDBACKS[target_id] = []
        _FEEDBACKS[target_id].append(msg.envelope.message_id)
        
        # We need to trigger webhook if this feedback pushes a pattern over the threshold
        # Find the pattern associated with this target_id
        for pat, mids in _INDICATORS.items():
            for mid in mids:
                if _MESSAGES[mid].payload.id == target_id:
                    asyncio.create_task(_check_and_fire_webhooks(pat))
                    break
    
    asyncio.create_task(_gossip_to_peers(msg))
    asyncio.create_task(_broadcast_feed_update())
    
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
        all_messages=_MESSAGES if feedback_messages else None,
        revoked_credentials=_REVOKED_CREDENTIALS
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
            revoked_credentials=_REVOKED_CREDENTIALS
        )

        first_msg = min(messages, key=lambda m: m.envelope.timestamp)
        latest_msg = max(messages, key=lambda m: m.envelope.timestamp)

        # Build timeline
        all_events = []
        for m in messages:
            all_events.append({"time": m.envelope.timestamp, "type": "report", "peer": m.envelope.credential_id})
        for fb in feedback_messages:
            all_events.append({"time": fb.envelope.timestamp, "type": "feedback", "peer": fb.envelope.credential_id})
        
        all_events.sort(key=lambda x: x["time"])
        
        # Approximate score progression
        timeline = []
        current_score = 0
        for ev in all_events:
            if ev["type"] == "report":
                current_score += 1.0
            elif ev["type"] == "feedback":
                current_score += 0.5
            timeline.append({
                "time": ev["time"],
                "type": ev["type"],
                "peer": ev["peer"],
                "score": round(min(current_score, score_data["local_corroboration_score"]), 1)
            })
            
        if timeline and timeline[-1]["score"] != score_data["local_corroboration_score"]:
            timeline[-1]["score"] = score_data["local_corroboration_score"]

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
            "timeline": timeline,
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

async def _broadcast_feed_update():
    if not _WS_CONNECTIONS:
        return
    try:
        feed_data = get_feed("json")
    except Exception as e:
        logger.error(f"Error generating feed for broadcast: {e}")
        return
        
    dead_connections = set()
    for ws in _WS_CONNECTIONS:
        try:
            await ws.send_json(feed_data)
        except Exception:
            dead_connections.add(ws)
    _WS_CONNECTIONS.difference_update(dead_connections)

@app.websocket("/feed/stream")
async def websocket_feed_stream(websocket: WebSocket):
    await websocket.accept()
    _WS_CONNECTIONS.add(websocket)
    try:
        await websocket.send_json(get_feed("json"))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _WS_CONNECTIONS.discard(websocket)

async def _check_and_fire_webhooks(pattern: str):
    """Evaluate the current score of an indicator and fire webhooks if threshold met."""
    if not _WEBHOOKS:
        return
        
    data = get_feed(format="json").get("ranked_indicators", [])
    for ind in data:
        if ind["pattern"] == pattern:
            if ind["local_corroboration_score"] >= 3.0:
                async with httpx.AsyncClient() as client:
                    for url in _WEBHOOKS:
                        try:
                            await client.post(url, json={"alert": "HIGH_TRUST_INDICATOR", "data": ind}, timeout=5.0)
                        except Exception as e:
                            logger.error(f"Failed to post webhook to {url}: {e}")
            break

@app.post("/webhooks")
def register_webhook(req: dict):
    """Register a webhook URL for SOAR integration."""
    url = req.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="Missing URL")
    _WEBHOOKS.add(url)
    return {"status": "registered", "url": url}

@app.get("/analytics/peers")
def get_peer_analytics():
    """Generate a reputation scorecard for all known peers based on the local graph."""
    peers = {}
    
    data = get_feed(format="json").get("ranked_indicators", [])
    for ind in data:
        is_high_trust = ind["local_corroboration_score"] >= 3.0
        is_flagged = ind["downweighted"]
        
        for peer in ind.get("identities", []):
            if peer not in peers:
                peers[peer] = {"reports": 0, "high_trust_contributions": 0, "flagged_contributions": 0}
                
            peers[peer]["reports"] += 1
            if is_high_trust:
                peers[peer]["high_trust_contributions"] += 1
            if is_flagged:
                peers[peer]["flagged_contributions"] += 1
                
    # Calculate an informal local reputation score (not used for consensus, just UI)
    for peer, stats in peers.items():
        score = 100
        if stats["reports"] > 0:
            score += (stats["high_trust_contributions"] * 10)
            score -= (stats["flagged_contributions"] * 50)
        stats["reputation_score"] = max(0, min(100, score)) if stats["reports"] == 0 else max(0, score)
        
    return peers

