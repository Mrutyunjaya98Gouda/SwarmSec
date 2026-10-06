# SwarmSec Jury Demonstration Runbook

This guide outlines the exact step-by-step process to perfectly execute the SwarmSec live demonstration for your Sprint 7 jury evaluation. 

## 1. Environment Preparation (Before the Jury Arrives)

To ensure a completely clean state without old data, follow these steps before your presentation begins:

1. **Open a terminal** and navigate to your project root.
2. **Ensure your environment is active:**
   ```bash
   source .venv/bin/activate
   ```
3. **Start the Master Orchestrator:**
   ```bash
   ./run_everything.sh
   ```
   *(Leave this terminal window visible but moved to the side. The jury will appreciate seeing the real-time server logs streaming).*

## 2. Browser Security Bypass (The mTLS Reality)

Because SwarmSec uses strict Mutual TLS (mTLS) with Ed25519 cryptography, your browser will initially block the local self-signed certificates. This is actually a great talking point about your security architecture.

1. Open a new browser window (Chrome or Firefox recommended).
2. Navigate directly to Node 1's API: **https://localhost:8001/feed**
3. Your browser will show a "Connection is not private" warning.
4. Click **Advanced** -> **Proceed to localhost (unsafe)**.
5. You should now see a blank JSON response: `{"ranked_indicators":[], ...}`.

## 3. Launching the Dashboard

1. In the same browser window, open a new tab and go to the frontend: **http://localhost:5173**
2. Point out to the jury that the connection indicator shows **🟢 LIVE** and **🟢 Gossip Active**.
3. Emphasize the clean state: `0 STIX 2.1 Indicators` and `0 Known Peers`.

## 4. The Live Attack Simulation

Open a **new terminal window** (make sure it's large enough for the jury to read the output) and run the demo script.

```bash
source .venv/bin/activate
python scripts/run_demo.py
```

### Scenario 1: The Legitimate Threat (0:00 - 0:10)
**What happens in the script:** 
Org 1 registers and publishes a verified malicious IP (`203.0.113.42`). Org 2 independently corroborates it.
**What to tell the jury:**
> *"Watch the dashboard. Org 1 just submitted a STIX indicator. The node verified the Ed25519 signature. You'll see it appear as 'UNCONFIRMED'. A few seconds later, Org 2 corroborates it. Because they have no suspicious overlapping history, the trust score rises organically."*

### Scenario 2: The Sybil / Collusion Attack (0:10 - 0:20)
**What happens in the script:** 
Org 3 (a compromised or malicious actor) publishes a fake indicator (`192.168.1.99`). Immediately, Org 4 and Org 5 rapidly endorse it to artificially inflate its score.
**What to tell the jury:**
> *"Now we simulate a coordinated Sybil attack. Three malicious actors collude to spam the network with a fake indicator, aggressively endorsing each other to trick the system. Watch the dashboard carefully."*

### The Climax (0:20+)
**What happens in the UI:**
The UI receives the gossip. The local Node's algorithm detects the tight mathematical clustering (cross-endorsements). Instead of giving it a high score, it severely penalizes it. 
**What to tell the jury:**
> *"Look at the red badge: **FEEDBACK DOWNWEIGHTED**. Despite having 3 distinct organizations endorsing it, SwarmSec's local graph analysis detected the collusion cluster. Instead of a high score, it plummeted to 0.3. We successfully neutralized a coordinated disinformation campaign without relying on a centralized authority or an expensive blockchain."*

## 5. Architectural Q&A

Leave the dashboard on the screen. Be prepared to answer these common jury questions:
* **"Why no Blockchain?"** -> Mention that global consensus is too slow for real-time CTI. Local corroboration scoring is mathematically explainable, faster, and preserves autonomy.
* **"How do you prevent forged identities?"** -> The central Registrar validates real-world identities and issues the initial credentials. The nodes handle the decentralized data plane.
* **"What is STIX 2.1?"** -> Explain that it's the industry standard for Cyber Threat Intelligence, and you adhered strictly to its constrained profile.
