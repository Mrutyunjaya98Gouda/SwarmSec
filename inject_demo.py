import time

import httpx

REGISTRAR_URL = "http://localhost:8000"
NODE_URL = "http://localhost:8001"

print("Injecting Live Demo Data into SwarmSec...")

def register_org(org_id):
    resp = httpx.post(f"{REGISTRAR_URL}/register", json={"org_id": org_id})
    return resp.json()

def publish_indicator(cred, pattern):
    resp = httpx.post(f"{NODE_URL}/publish", json={
        "credential_id": cred["credential_id"],
        "private_key_b64": cred["private_key_b64"],
        "pattern": pattern
    })
    return resp.json()

def endorse(cred, indicator_id):
    httpx.post(f"{NODE_URL}/feedback", json={
        "credential_id": cred["credential_id"],
        "private_key_b64": cred["private_key_b64"],
        "indicator_id": indicator_id,
        "opinion": "strongly-agree"
    })

# 1. Clean indicator with multiple endorsements
print("Creating Clean Indicator...")
c1 = register_org("Clean-Source-A")
c2 = register_org("Clean-Source-B")
c3 = register_org("Clean-Source-C")

ind_res = publish_indicator(c1, "[file:hashes.'SHA-256' = 'clean_malware_hash_999']")
ind_id = ind_res["indicator_id"]

time.sleep(1)
endorse(c2, ind_id)
endorse(c3, ind_id)
print("Clean Indicator populated and endorsed by independent sources!")

# 2. Dense Cluster Attack (Sybil/Collusion)
print("Initiating Dense Cluster Attack (Collusion)...")
colluders = [register_org(f"Colluder-Node-{i}") for i in range(4)]
attack_pattern = "[ipv4-addr:value = '198.51.100.99']"

# Lead colluder publishes
att_res = publish_indicator(colluders[0], attack_pattern)
att_ind_id = att_res["indicator_id"]

# They all cross-endorse (simulating a botnet trying to boost trust)
time.sleep(1)
for i in range(1, 4):
    publish_indicator(colluders[i], attack_pattern)
    endorse(colluders[i], att_ind_id)

print("Dense Cluster Attack populated! Collusion Penalty should trigger.")
print("Done. Check the Dashboard!")
