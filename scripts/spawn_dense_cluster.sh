#!/usr/bin/env bash
# spawn_dense_cluster.sh — Sprint 4 Attack Script 1
#
# Simulates a "credentialed collusion resistance" test (NOT "Sybil resistance"
# or "collusion detection" — see AGENTS.md terminology).
#
# Several pseudonyms rapidly, densely endorsing each other. Every colluding
# pseudonym endorses every other colluding pseudonym's indicator in quick
# succession — the most obvious pattern of coordinated feedback.
#
# Usage:
#   ./scripts/spawn_dense_cluster.sh [NODE_URL] [NUM_COLLUDERS]
#
# Requires: curl, jq, a running SwarmSec node with registered credentials.
# In a test environment, credentials are auto-provisioned by the test harness.

set -euo pipefail

NODE_URL="${1:-http://localhost:8001}"
REGISTRAR_URL="${2:-http://localhost:8000}"
NUM_COLLUDERS="${3:-4}"

echo "=== SwarmSec Dense Cluster Attack ==="
echo "Target node: ${NODE_URL}"
echo "Registrar: ${REGISTRAR_URL}"
echo "Colluding pseudonyms: ${NUM_COLLUDERS}"
echo ""

# Step 1: Register colluding pseudonyms with the registrar
echo "[1/4] Registering ${NUM_COLLUDERS} colluding pseudonyms..."
CRED_IDS=()
PRIVKEYS=()

for i in $(seq 1 "${NUM_COLLUDERS}"); do
    RESULT=$(curl -s "${REGISTRAR_URL}/register" \
        -H "Content-Type: application/json" \
        -d "{\"org_id\": \"colluder_${i}\"}" 2>/dev/null || echo '{"error":"registration not available"}')
    
    CRED_ID=$(echo "${RESULT}" | jq -r '.credential_id // empty' 2>/dev/null || echo "colluder_cred_${i}")
    PRIVKEY=$(echo "${RESULT}" | jq -r '.private_key_b64 // empty' 2>/dev/null || echo "dummy_key_${i}")
    
    CRED_IDS+=("${CRED_ID}")
    PRIVKEYS+=("${PRIVKEY}")
    echo "  Registered colluder_${i}: ${CRED_ID}"
done

# Step 2: Each colluder publishes an indicator
echo ""
echo "[2/4] Each colluder publishing an indicator..."
INDICATOR_IDS=()
PATTERN="[file:hashes.'SHA-256' = 'dense_cluster_attack_payload_hash']"

for i in $(seq 0 $((NUM_COLLUDERS - 1))); do
    RESULT=$(curl -s "${NODE_URL}/publish" \
        -H "Content-Type: application/json" \
        -d "{
            \"credential_id\": \"${CRED_IDS[$i]}\",
            \"private_key_b64\": \"${PRIVKEYS[$i]}\",
            \"pattern\": \"${PATTERN}\"
        }" 2>/dev/null || echo '{"indicator_id":"unknown"}')
    
    IND_ID=$(echo "${RESULT}" | jq -r '.indicator_id // .message_id // empty' 2>/dev/null || echo "ind_${i}")
    INDICATOR_IDS+=("${IND_ID}")
    echo "  colluder_$((i+1)) published: ${IND_ID}"
done

# Step 3: Dense cross-endorsement — every colluder endorses every other's indicator
echo ""
echo "[3/4] Dense cross-endorsement (every colluder endorses every other)..."
ENDORSEMENT_COUNT=0

for i in $(seq 0 $((NUM_COLLUDERS - 1))); do
    for j in $(seq 0 $((NUM_COLLUDERS - 1))); do
        if [ "$i" -ne "$j" ]; then
            curl -s "${NODE_URL}/feedback" \
                -H "Content-Type: application/json" \
                -d "{
                    \"credential_id\": \"${CRED_IDS[$i]}\",
                    \"private_key_b64\": \"${PRIVKEYS[$i]}\",
                    \"indicator_id\": \"${INDICATOR_IDS[$j]}\",
                    \"opinion\": \"strongly-agree\"
                }" > /dev/null 2>&1 || true
            ENDORSEMENT_COUNT=$((ENDORSEMENT_COUNT + 1))
        fi
    done
done

echo "  Total endorsements sent: ${ENDORSEMENT_COUNT}"
echo "  Expected dense cluster: each node endorsed $((NUM_COLLUDERS - 1)) others"

# Step 4: Query the indicator and check if down-weighting kicked in
echo ""
echo "[4/4] Querying indicator score..."
sleep 1  # Allow gossip propagation

QUERY_RESULT=$(curl -s "${NODE_URL}/query?pattern=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PATTERN}'))")" 2>/dev/null || echo '{"error":"query failed"}')

echo ""
echo "=== RESULT ==="
echo "${QUERY_RESULT}" | python3 -m json.tool 2>/dev/null || echo "${QUERY_RESULT}"

# Check for down-weighting flag
if echo "${QUERY_RESULT}" | grep -q "feedback_downweighted"; then
    echo ""
    echo "✓ DETECTED: Dense cluster was down-weighted (feedback_downweighted flag present)"
else
    echo ""
    echo "⚠ NOT DETECTED: Dense cluster was NOT flagged for down-weighting"
    echo "  This may indicate the attack was too small or the node hasn't processed all feedback yet."
fi

echo ""
echo "=== Attack script complete ==="
