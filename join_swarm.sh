#!/bin/bash
set -e

# ==============================================================================
# SwarmSec Peer Join Script (For Friend / Secondary Laptop)
# Connects this laptop to an existing SwarmSec host machine on your network.
# ==============================================================================

if [ -z "$1" ]; then
    echo "Usage: ./join_swarm.sh <HOST_IP> [YOUR_ORG_NAME]"
    echo ""
    echo "Example:"
    echo "  ./join_swarm.sh 172.20.10.9 org-b"
    echo ""
    exit 1
fi

HOST_IP="$1"
ORG_NAME="${2:-org-b}"

echo "=========================================================="
echo "   SwarmSec - Joining Swarm Network at $HOST_IP"
echo "=========================================================="

echo "[1/4] Ensuring Python Environment and Dependencies..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -r requirements.txt -q

echo "[2/4] Ensuring Frontend Dependencies..."
cd dashboard
if [ ! -d "node_modules" ]; then
    npm install
fi
cd ..

echo "[3/4] Checking TLS / CA Certificates..."
if [ ! -f "certs/ca.pem" ] || [ ! -f "certs/ca.key" ]; then
    echo "❌ Missing 'certs/' directory from host!"
    echo "SwarmSec uses mutual TLS (mTLS). Both machines must share the same Certificate Authority."
    echo ""
    echo "Please copy the 'certs/' folder from the host ($HOST_IP) to this machine:"
    echo "  scp -r <user>@$HOST_IP:/path/to/SwarmSec/certs ./certs"
    echo ""
    exit 1
fi

# Detect local routable IP address for peer announcement
LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}')
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="127.0.0.1"
fi
echo "Local IP detected: $LOCAL_IP"

# Ensure certificates for this machine exist under the shared CA
python scripts/generate_certs.py

echo "[4/4] Starting Peer Node connected to Host ($HOST_IP)..."
export REGISTRAR_URL="https://$HOST_IP:8000"
export EXTRA_PEERS="https://$HOST_IP:8001,https://$HOST_IP:8002,https://$HOST_IP:8003"
export NODE_PORT="8001"
export NODE_NUM="2"
export ANNOUNCE_URL="https://$LOCAL_IP:8001"

echo "Starting local node peering with $HOST_IP..."
python scripts/run_servers.py &
BACKEND_PID=$!

sleep 3

# Announce to host node 1 so host gossips back to us
python -c "
import httpx
try:
    with httpx.Client(verify=False, timeout=5.0) as client:
        client.post('https://$HOST_IP:8001/peers/register', json={'peer_url': 'https://$LOCAL_IP:8001'})
        print('✅ Announced peer to Host ($HOST_IP:8001)')
except Exception as e:
    print(f'Peer registration note: {e}')
"

echo "Starting React Dashboard..."
cd dashboard
npm run dev -- --open &
FRONTEND_PID=$!
cd ..

echo "=========================================================="
echo "✅ Connected to SwarmSec Host ($HOST_IP)!"
echo "🖥️  Your Local Dashboard: http://localhost:5173"
echo "🔑 Recommended Login Org: $ORG_NAME"
echo "=========================================================="
echo "Press Ctrl+C to disconnect and shut down."

cleanup() {
    echo ""
    echo "Disconnecting from swarm..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    exit 0
}

trap cleanup INT TERM
wait
