#!/usr/bin/env bash
# spawn_staggered_cluster.sh — Sprint 4 Attack Script 2
#
# Same underlying collusion as spawn_dense_cluster.sh, but with staggered timing
# and sparser mutual endorsement — closer to what a patient adversary would do.
#
# Key differences from dense variant:
#   - Endorsements are spread over time (sleep between each)
#   - Not every colluder endorses every other — only partial graph coverage
#   - Some colluders also endorse non-cluster indicators (to blend in)
#
# This tests whether the correlated-evidence down-weighting catches patient,
# less-obvious coordination. Per Sprint 4 plan: "Build this even if it's less
# likely to trigger detection as cleanly, and report exactly what it does or
# doesn't catch."
#
# Usage:
#   ./scripts/spawn_staggered_cluster.sh [NODE_URL] [NUM_COLLUDERS]
#
# Requires: curl, jq, a running SwarmSec node with registered credentials.

set -euo pipefail

NODE_URL="${1:-http://localhost:8001}"
NUM_COLLUDERS="${2:-5}"
STAGGER_SECONDS="${3:-2}"

echo "=== SwarmSec Staggered Cluster Attack ==="
echo "Target node: ${NODE_URL}"
echo "Colluding pseudonyms: ${NUM_COLLUDERS}"
echo "Stagger delay: ${STAGGER_SECONDS}s between endorsements"
echo ""

# Step 1: Register colluding pseudonyms
echo "[1/5] Registering ${NUM_COLLUDERS} colluding pseudonyms..."
CRED_IDS=()
PRIVKEYS=()

for i in $(seq 1 "${NUM_COLLUDERS}"); do
    RESULT=$(curl -s "${NODE_URL}/register" \
        -H "Content-Type: application/json" \
        -d "{\"org_id\": \"staggered_colluder_${i}\"}" 2>/dev/null || echo '{}')
    
    CRED_ID=$(echo "${RESULT}" | jq -r '.credential_id // empty' 2>/dev/null || echo "staggered_cred_${i}")
    PRIVKEY=$(echo "${RESULT}" | jq -r '.private_key_b64 // empty' 2>/dev/null || echo "dummy_key_${i}")
    
    CRED_IDS+=("${CRED_ID}")
    PRIVKEYS+=("${PRIVKEY}")
    echo "  Registered staggered_colluder_${i}: ${CRED_ID}"
done

# Step 2: Each colluder publishes an indicator
echo ""
echo "[2/5] Each colluder publishing an indicator..."
INDICATOR_IDS=()
PATTERN="[file:hashes.'SHA-256' = 'staggered_cluster_attack_payload']"

for i in $(seq 0 $((NUM_COLLUDERS - 1))); do
    RESULT=$(curl -s "${NODE_URL}/publish" \
        -H "Content-Type: application/json" \
        -d "{
            \"credential_id\": \"${CRED_IDS[$i]}\",
            \"private_key_b64\": \"${PRIVKEYS[$i]}\",
            \"pattern\": \"${PATTERN}\"
        }" 2>/dev/null || echo '{}')
    
    IND_ID=$(echo "${RESULT}" | jq -r '.indicator_id // .message_id // empty' 2>/dev/null || echo "ind_${i}")
    INDICATOR_IDS+=("${IND_ID}")
    echo "  staggered_colluder_$((i+1)) published: ${IND_ID}"
    
    # Stagger indicator publications too
    sleep "${STAGGER_SECONDS}"
done

# Step 3: Sparse, staggered cross-endorsement
# Only ~50% of possible endorsements are made, and with time delays
echo ""
echo "[3/5] Sparse, staggered cross-endorsement..."
ENDORSEMENT_COUNT=0
SKIPPED_COUNT=0

for i in $(seq 0 $((NUM_COLLUDERS - 1))); do
    for j in $(seq 0 $((NUM_COLLUDERS - 1))); do
        if [ "$i" -ne "$j" ]; then
            # Only endorse ~50% of others (sparse coverage)
            RANDOM_SKIP=$(( (i + j) % 2 ))
            if [ "${RANDOM_SKIP}" -eq 0 ]; then
                echo "  staggered_colluder_$((i+1)) -> staggered_colluder_$((j+1)): endorsing..."
                curl -s "${NODE_URL}/feedback" \
                    -H "Content-Type: application/json" \
                    -d "{
                        \"credential_id\": \"${CRED_IDS[$i]}\",
                        \"private_key_b64\": \"${PRIVKEYS[$i]}\",
                        \"indicator_id\": \"${INDICATOR_IDS[$j]}\",
                        \"opinion\": \"agree\"
                    }" > /dev/null 2>&1 || true
                ENDORSEMENT_COUNT=$((ENDORSEMENT_COUNT + 1))
                
                # Stagger between endorsements
                sleep "${STAGGER_SECONDS}"
            else
                SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            fi
        fi
    done
done

echo ""
echo "  Endorsements sent: ${ENDORSEMENT_COUNT}"
echo "  Endorsements skipped (sparse): ${SKIPPED_COUNT}"

# Step 4: Some colluders also endorse non-cluster indicators (camouflage)
echo ""
echo "[4/5] Camouflage: some colluders endorsing non-cluster indicators..."

# First colluder creates a decoy indicator from a "different pattern"
DECOY_RESULT=$(curl -s "${NODE_URL}/publish" \
    -H "Content-Type: application/json" \
    -d "{
        \"credential_id\": \"${CRED_IDS[0]}\",
        \"private_key_b64\": \"${PRIVKEYS[0]}\",
        \"pattern\": \"[domain-name:value = 'legit-looking-domain.example.com']\"
    }" 2>/dev/null || echo '{}')

DECOY_ID=$(echo "${DECOY_RESULT}" | jq -r '.indicator_id // .message_id // empty' 2>/dev/null || echo "decoy")

# A couple of colluders endorse the decoy to diversify their endorsement graph
for i in 1 2; do
    if [ "$i" -lt "${NUM_COLLUDERS}" ]; then
        curl -s "${NODE_URL}/feedback" \
            -H "Content-Type: application/json" \
            -d "{
                \"credential_id\": \"${CRED_IDS[$i]}\",
                \"private_key_b64\": \"${PRIVKEYS[$i]}\",
                \"indicator_id\": \"${DECOY_ID}\",
                \"opinion\": \"agree\"
            }" > /dev/null 2>&1 || true
        echo "  staggered_colluder_$((i+1)) endorsed decoy indicator (camouflage)"
    fi
done

# Step 5: Query and report
echo ""
echo "[5/5] Querying indicator score..."
sleep 2

QUERY_RESULT=$(curl -s "${NODE_URL}/query?pattern=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PATTERN}'))")" 2>/dev/null || echo '{"error":"query failed"}')

echo ""
echo "=== RESULT ==="
echo "${QUERY_RESULT}" | python3 -m json.tool 2>/dev/null || echo "${QUERY_RESULT}"

echo ""
echo "=== HONEST ASSESSMENT ==="
if echo "${QUERY_RESULT}" | grep -q "feedback_downweighted"; then
    echo "✓ DETECTED: Staggered cluster was down-weighted"
    echo "  The system caught the coordination despite staggered timing."
else
    echo "⚠ NOT FULLY DETECTED: Staggered cluster was NOT flagged for down-weighting"
    echo ""
    echo "  DOCUMENTED FINDING: The staggered variant with ~50% endorsement coverage"
    echo "  and camouflage endorsements was not caught by the current fixed-parameter"
    echo "  formula. The cluster density metric requires a majority of a giver's"
    echo "  other endorsees to also endorse the target. With sparse coverage and"
    echo "  decoy endorsements diluting the concentration ratio, the attack"
    echo "  successfully evades detection."
    echo ""
    echo "  This is an honest, documented limitation — not something to gloss over."
    echo "  Future work: time-window analysis, graph community detection, or"
    echo "  endorsement velocity tracking could improve detection of patient adversaries."
fi

echo ""
echo "=== Attack script complete ==="
