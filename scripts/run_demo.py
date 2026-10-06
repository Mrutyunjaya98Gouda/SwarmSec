#!/usr/bin/env python3
"""
SwarmSec End-to-End Demo Script

Simulates a realistic threat intelligence sharing scenario:
1. Legitimate Report & Corroboration
2. Dense Cluster Attack (Collusion)

Run this while watching the Dashboard!
"""

import asyncio
import httpx
import json
import base64
import os
import ssl
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

# Configuration
REGISTRAR_URL = "https://localhost:8000"
NODE1_URL = "https://localhost:8001"
NODE2_URL = "https://localhost:8002"

# Use node1's certificate as our client cert for mTLS authentication
CERT_PATH = Path("certs/node1.pem")
KEY_PATH = Path("certs/node1.key")
CA_PATH = Path("certs/ca.pem")

async def main():
    if not CERT_PATH.exists():
        logger.error("Certificates not found! Please run 'python scripts/generate_certs.py' first.")
        return

    # Set up mTLS HTTP client
    # We bypass strict CA verification for localhost self-signed certs to avoid Missing Authority Key Identifier errors
    async with httpx.AsyncClient(cert=(str(CERT_PATH), str(KEY_PATH)), verify=False) as client:
        logger.info("=== SwarmSec Live Demo ===")
        logger.info("Registering 5 synthetic organizations...")
        
        # Import key tools
        import sys
        sys.path.append(str(Path(__file__).parent.parent / "src"))
        from swarmsec.crypto.keys import generate_keypair, serialize_public_key, serialize_private_key
        
        orgs = []
        org_ids = ["org-a", "org-b", "org-c", "org-d", "colluder-1"]
        
        for i, oid in enumerate(org_ids):
            priv, pub = generate_keypair()
            pub_b64 = base64.b64encode(serialize_public_key(pub)).decode("ascii")
            priv_b64 = base64.b64encode(serialize_private_key(priv)).decode("ascii")
            
            resp = await client.post(
                f"{REGISTRAR_URL}/register", 
                json={"org_id": oid, "pseudonym_public_key": pub_b64}
            )
            data = resp.json()
            if "credential" not in data:
                logger.error(f"Failed to register {oid}: {data}")
                return
            
            orgs.append({
                "credential_id": data["credential"]["credential_id"],
                "private_key_b64": priv_b64
            })
            logger.info(f"Registered {oid}: Credential {data['credential']['credential_id'][:8]}...")
            
        await asyncio.sleep(2)
        
        logger.info("\n[SCENARIO 1: Legitimate Threat Report]")
        logger.info(f"Org 1 reports a verified malicious IP: 203.0.113.42")
        resp = await client.post(
            f"{NODE1_URL}/publish", 
            json={
                "credential_id": orgs[0]["credential_id"],
                "private_key_b64": orgs[0]["private_key_b64"],
                "pattern": "203.0.113.42"
            }
        )
        report_data = resp.json()
        logger.info(f"Report published! Message ID: {report_data['message_id']}")
        
        await asyncio.sleep(3)
        
        logger.info("\n[SCENARIO 1: Independent Corroboration]")
        logger.info("Org 2 independently verifies and endorses the indicator.")
        await client.post(
            f"{NODE2_URL}/feedback", 
            json={
                "credential_id": orgs[1]["credential_id"],
                "private_key_b64": orgs[1]["private_key_b64"],
                "indicator_id": report_data['indicator_id'],
                "opinion": "strongly-agree"
            }
        )
        logger.info("Corroboration submitted. Check the dashboard to see the score rise!")
        
        await asyncio.sleep(6)
        
        logger.info("\n[SCENARIO 2: Dense Cluster Attack (Collusion)]")
        logger.info("Org 3 submits a fake indicator to disrupt the network.")
        resp = await client.post(
            f"{NODE1_URL}/publish", 
            json={
                "credential_id": orgs[2]["credential_id"],
                "private_key_b64": orgs[2]["private_key_b64"],
                "pattern": "192.168.1.99"
            }
        )
        fake_report = resp.json()
        
        await asyncio.sleep(1)
        
        logger.info("Org 4 and Org 5 rapidly endorse Org 3's fake report (Sybil behavior).")
        await client.post(
            f"{NODE1_URL}/feedback", 
            json={
                "credential_id": orgs[3]["credential_id"],
                "private_key_b64": orgs[3]["private_key_b64"],
                "indicator_id": fake_report['indicator_id'],
                "opinion": "strongly-agree"
            }
        )
        await client.post(
            f"{NODE2_URL}/feedback", 
            json={
                "credential_id": orgs[4]["credential_id"],
                "private_key_b64": orgs[4]["private_key_b64"],
                "indicator_id": fake_report['indicator_id'],
                "opinion": "strongly-agree"
            }
        )
        
        logger.info("Attack complete. The SwarmSec graph analysis should detect the tight clustering and heavily downweight this indicator!")
        logger.info("=== Check the Dashboard ===")

if __name__ == "__main__":
    asyncio.run(main())
