#!/bin/bash
set -e

# ==============================================================================
# SwarmSec One-Click Local Orchestrator
# This script handles all installations, certificate generation, and server orchestration.
# ==============================================================================

echo "======================================"
echo "     SwarmSec Local Orchestrator      "
echo "======================================"

echo "[1/4] Ensuring Python Virtual Environment and Dependencies..."
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi
source .venv/bin/activate
echo "Installing Python dependencies..."
pip install -r requirements.txt -q

echo "[2/4] Ensuring Node.js Frontend Dependencies..."
cd dashboard
if [ ! -d "node_modules" ]; then
    echo "Installing NPM dependencies (this might take a minute)..."
    npm install
fi
cd ..

echo "[3/4] Generating Cryptographic Certificates (mTLS & Identity)..."
mkdir -p certs
python scripts/generate_certs.py

echo "[4/4] Starting SwarmSec Network..."
# 1. Start Backend Network (Registrar + 3 Nodes)
echo "Starting Registrar and 3 Peer Nodes in the background..."
python scripts/run_servers.py &
BACKEND_PID=$!

# Wait a few seconds for backend to start up
sleep 3

# 2. Start React Dashboard
echo "Starting React Dashboard..."
cd dashboard
npm run dev -- --open &
FRONTEND_PID=$!
cd ..

echo "=========================================================="
echo "✅ SwarmSec is now fully installed and running locally!"
echo ""
echo "🖥️  Dashboard URL: http://localhost:5173"
echo "    (Your browser should open automatically)"
echo ""
echo "⚔️  To run the automated live attack simulation, open a NEW terminal and run:"
echo "    source .venv/bin/activate && python scripts/run_demo.py"
echo "=========================================================="
echo "Press Ctrl+C to shut down all servers gracefully."

# Trap Ctrl+C (SIGINT) to kill background processes cleanly
cleanup() {
    echo ""
    echo "Shutting down SwarmSec..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    echo "Shutdown complete."
    exit 0
}

trap cleanup INT TERM
wait
