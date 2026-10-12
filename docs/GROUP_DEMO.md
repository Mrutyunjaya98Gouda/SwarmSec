# SwarmSec Multi-Host & Group Demo Guide

This guide explains how two or more team members can run SwarmSec simultaneously on separate laptops connected over the same local network (Wi-Fi, hotspot, or LAN) and gossip threat intelligence in real time.

---

## Architecture Overview
- **Laptop 1 (Host / Coordinator):**
  - Runs the Central Registrar (Identity Plane) on port `8000`.
  - Runs local peer nodes (`8001`, `8002`, `8003`) and the Web Dashboard (`5173`).
- **Laptop 2 (Friend / Peer):**
  - Connects to Laptop 1's Registrar to receive verified Ed25519 credentials.
  - Gossips directly to Laptop 1's peer nodes over mTLS.
  - Runs its own Web Dashboard displaying the synchronized threat intelligence stream.

---

## Step 1: Laptop 1 (Host Setup)

1. Find your local Wi-Fi / LAN IP address:
   ```bash
   # On Linux:
   ip route get 1.1.1.1 | awk '{print $7}'
   # Example output: 172.20.10.9
   ```

2. Start the SwarmSec network:
   ```bash
   ./run_everything.sh
   ```
   *Your network is now running and accepting connections on ports 8000 and 8001-8003.*

---

## Step 2: Laptop 2 (Friend's Setup)

1. Clone the repository and switch to the `group-demo` branch:
   ```bash
   git clone <REPO_URL>
   cd SwarmSec
   git checkout group-demo
   ```

2. Copy the `certs/` folder from Laptop 1 to Laptop 2 so both machines share the root Certificate Authority:
   ```bash
   # Via scp or a USB drive / AirDrop / local transfer:
   scp -r user@<HOST_IP>:/path/to/SwarmSec/certs ./certs
   ```

3. Run the one-click join script passing Laptop 1's IP address:
   ```bash
   ./join_swarm.sh <HOST_IP> org-b
   # Example:
   # ./join_swarm.sh 172.20.10.9 org-b
   ```

---

## Step 3: Performing the Live Group Demo

1. **Laptop 1 Dashboard:**
   - Open `http://localhost:5173`.
   - Log in as `org-a`.

2. **Laptop 2 Dashboard:**
   - Open `http://localhost:5173` on Laptop 2.
   - Log in as `org-b`.

3. **Demonstrating Cross-Laptop Gossip & Trust Scoring:**
   - On Laptop 2, click **"Publish Threat / Sighting"**.
   - Enter an indicator (e.g. `203.0.113.100`) and click **"Publish Sighting to Mesh"**.
   - **Immediately on Laptop 1's screen:** The threat indicator will appear in real time over WebSockets!
   - On Laptop 1, endorse or corroborating the threat to watch the trust ranking score rise across both machines.
