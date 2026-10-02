#!/usr/bin/env bash
# demo_end_to_end.sh — Sprint 5 End-to-End Demonstration Script
#
# Demonstrates the full SwarmSec live sequence:
#   1. Clean report submission (single source, unconfirmed).
#   2. Corroboration arriving from independent organizations (score increases).
#   3. Dense-cluster attack from colluding pseudonyms (correlated-evidence down-weighting triggers).
#   4. Terminal dashboard and advisory-only CLI outputs.
#
# Definition of Done: Running this script produces the sequence live,
# three times in a row, with no manual intervention between stages.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Activate virtualenv if present
if [ -f "${REPO_ROOT}/.venv/bin/activate" ]; then
    source "${REPO_ROOT}/.venv/bin/activate"
fi

REGISTRAR_PORT="${REGISTRAR_PORT:-8820}"
NODE_PORT="${NODE_PORT:-8821}"
REGISTRAR_URL="http://127.0.0.1:${REGISTRAR_PORT}"
NODE_URL="http://127.0.0.1:${NODE_PORT}"

REPEAT_COUNT="${1:-1}"

run_single_iteration() {
    local ITERATION="$1"
    echo "================================================================================"
    echo ">>> RUNNING END-TO-END DEMO ITERATION ${ITERATION} of ${REPEAT_COUNT}"
    echo "================================================================================"

    local WORK_DIR
    WORK_DIR="$(mktemp -d /tmp/swarmsec_demo_XXXXXX)"
    
    # Track background PIDs for this iteration
    local REG_PID=""
    local NODE_PID=""

    cleanup_iteration() {
        if [ -n "${NODE_PID:-}" ] && kill -0 "${NODE_PID}" 2>/dev/null; then
            kill "${NODE_PID}" 2>/dev/null || true
            wait "${NODE_PID}" 2>/dev/null || true
        fi
        if [ -n "${REG_PID:-}" ] && kill -0 "${REG_PID}" 2>/dev/null; then
            kill "${REG_PID}" 2>/dev/null || true
            wait "${REG_PID}" 2>/dev/null || true
        fi
        rm -rf "${WORK_DIR:-}"
    }

    # Set local trap
    trap cleanup_iteration RETURN EXIT

    echo "[Init] Starting isolated Registrar daemon on port ${REGISTRAR_PORT}..."
    SWARMSEC_LOG_FILE="${WORK_DIR}/reg_log.jsonl" python3 -m uvicorn swarmsec.registrar.app:app \
        --host 127.0.0.1 --port "${REGISTRAR_PORT}" --log-level error &
    REG_PID=$!

    # Wait for registrar health
    for i in {1..30}; do
        if curl -s "${REGISTRAR_URL}/health" | grep -q "ok"; then
            break
        fi
        sleep 0.2
    done

    echo "[Init] Starting isolated Node daemon on port ${NODE_PORT}..."
    REGISTRAR_URL="${REGISTRAR_URL}" python3 -m uvicorn swarmsec.node.app:app \
        --host 127.0.0.1 --port "${NODE_PORT}" --log-level error &
    NODE_PID=$!

    # Wait for node health
    for i in {1..30}; do
        if curl -s "${NODE_URL}/health" | grep -q "ok"; then
            break
        fi
        sleep 0.2
    done

    echo "[Setup] Registering legitimate organizations (Org A, Org B, Org C)..."
    python3 -m swarmsec.cli.main keygen --out "${WORK_DIR}/org_a" > /dev/null
    python3 -m swarmsec.cli.main keygen --out "${WORK_DIR}/org_b" > /dev/null
    python3 -m swarmsec.cli.main keygen --out "${WORK_DIR}/org_c" > /dev/null

    python3 -m swarmsec.cli.main register \
        --registrar "${REGISTRAR_URL}" \
        --identity "org-a" \
        --key "${WORK_DIR}/org_a/pseudonym.pub" \
        --out "${WORK_DIR}/org_a/cred.json" > /dev/null

    python3 -m swarmsec.cli.main register \
        --registrar "${REGISTRAR_URL}" \
        --identity "org-b" \
        --key "${WORK_DIR}/org_b/pseudonym.pub" \
        --out "${WORK_DIR}/org_b/cred.json" > /dev/null

    python3 -m swarmsec.cli.main register \
        --registrar "${REGISTRAR_URL}" \
        --identity "org-c" \
        --key "${WORK_DIR}/org_c/pseudonym.pub" \
        --out "${WORK_DIR}/org_c/cred.json" > /dev/null

    echo "  Registered Org A, Org B, Org C successfully."
    echo ""

    # =========================================================================
    # STAGE 1: Clean Report Submission (Single Source)
    # =========================================================================
    echo "========================================================================"
    echo "STAGE 1: Clean report published by single source (Org A)"
    echo "========================================================================"
    CLEAN_PATTERN="[file:hashes.'SHA-256' = '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a']"

    python3 -m swarmsec.cli.main submit \
        --node "${NODE_URL}" \
        --credential "${WORK_DIR}/org_a/cred.json" \
        --key "${WORK_DIR}/org_a/pseudonym.key" \
        --pattern "${CLEAN_PATTERN}"

    echo ""
    echo "Querying score after single source..."
    STAGE1_QUERY=$(python3 -m swarmsec.cli.main query --node "${NODE_URL}" --pattern "${CLEAN_PATTERN}")
    echo "${STAGE1_QUERY}"

    if ! echo "${STAGE1_QUERY}" | grep -q "UNCONFIRMED"; then
        echo "ERROR: Stage 1 expected UNCONFIRMED status." >&2
        return 1
    fi
    if ! echo "${STAGE1_QUERY}" | grep -q "ADVISORY ONLY:"; then
        echo "ERROR: Missing advisory disclaimer in Stage 1." >&2
        return 1
    fi

    # =========================================================================
    # STAGE 2: Independent Corroboration Arriving
    # =========================================================================
    echo ""
    echo "========================================================================"
    echo "STAGE 2: Corroboration arriving from independent peers (Org B & Org C)"
    echo "========================================================================"

    python3 -m swarmsec.cli.main submit \
        --node "${NODE_URL}" \
        --credential "${WORK_DIR}/org_b/cred.json" \
        --key "${WORK_DIR}/org_b/pseudonym.key" \
        --pattern "${CLEAN_PATTERN}" > /dev/null

    python3 -m swarmsec.cli.main submit \
        --node "${NODE_URL}" \
        --credential "${WORK_DIR}/org_c/cred.json" \
        --key "${WORK_DIR}/org_c/pseudonym.key" \
        --pattern "${CLEAN_PATTERN}" > /dev/null

    echo "Querying score after independent corroborations..."
    STAGE2_QUERY=$(python3 -m swarmsec.cli.main query --node "${NODE_URL}" --pattern "${CLEAN_PATTERN}")
    echo "${STAGE2_QUERY}"

    if ! echo "${STAGE2_QUERY}" | grep -q "CONFIRMED"; then
        echo "ERROR: Stage 2 expected CONFIRMED status." >&2
        return 1
    fi
    if ! echo "${STAGE2_QUERY}" | grep -q "CLEAN (independent observations)"; then
        echo "ERROR: Stage 2 expected CLEAN status." >&2
        return 1
    fi

    echo ""
    echo "Feed overview after Stage 2:"
    python3 -m swarmsec.cli.main feed --node "${NODE_URL}"

    # =========================================================================
    # STAGE 3: Dense-Cluster Attack (Sprint 4 Scenario)
    # =========================================================================
    echo ""
    echo "========================================================================"
    echo "STAGE 3: Dense-cluster attack (4 colluders densely cross-endorsing)"
    echo "========================================================================"
    ATTACK_PATTERN="[ipv4-addr:value = '198.51.100.99']"

    declare -A COLLUDER_MSG_IDS

    for c in 1 2 3 4; do
        python3 -m swarmsec.cli.main keygen --out "${WORK_DIR}/colluder_${c}" > /dev/null
        python3 -m swarmsec.cli.main register \
            --registrar "${REGISTRAR_URL}" \
            --identity "colluder-${c}" \
            --key "${WORK_DIR}/colluder_${c}/pseudonym.pub" \
            --out "${WORK_DIR}/colluder_${c}/cred.json" > /dev/null

        # Each colluder publishes an indicator so there is a mutual cluster of indicators
        local PAT="[ipv4-addr:value = '198.51.100.9${c}']"
        if [ "$c" -eq 1 ]; then
            PAT="${ATTACK_PATTERN}"
        fi

        local OUT
        OUT=$(python3 -m swarmsec.cli.main submit \
            --node "${NODE_URL}" \
            --credential "${WORK_DIR}/colluder_${c}/cred.json" \
            --key "${WORK_DIR}/colluder_${c}/pseudonym.key" \
            --pattern "${PAT}")
        
        COLLUDER_MSG_IDS[$c]=$(echo "${OUT}" | grep "Message ID:" | awk '{print $3}')
    done

    echo "  Published indicators for 4 colluders. Now submitting dense cross-endorsements..."

    # Every colluder endorses every other colluder's indicator
    for i in 1 2 3 4; do
        for j in 1 2 3 4; do
            if [ "$i" -ne "$j" ]; then
                python3 -m swarmsec.cli.main feedback \
                    --node "${NODE_URL}" \
                    --credential "${WORK_DIR}/colluder_${i}/cred.json" \
                    --key "${WORK_DIR}/colluder_${i}/pseudonym.key" \
                    --indicator-id "${COLLUDER_MSG_IDS[$j]}" \
                    --opinion "strongly-agree" > /dev/null
            fi
        done
    done

    echo "Querying score for attack indicator..."
    STAGE3_QUERY=$(python3 -m swarmsec.cli.main query --node "${NODE_URL}" --pattern "${ATTACK_PATTERN}")
    echo "${STAGE3_QUERY}"

    if ! echo "${STAGE3_QUERY}" | grep -q "TRIGGERED (correlated-evidence down-weighting)"; then
        echo "ERROR: Stage 3 expected TRIGGERED down-weighting." >&2
        return 1
    fi

    echo ""
    echo "Rendering live terminal dashboard snapshot:"
    python3 -m swarmsec.cli.main dashboard --node "${NODE_URL}" --once

    echo ""
    echo ">>> ITERATION ${ITERATION} COMPLETED SUCCESSFULLY."
    cleanup_iteration
    trap - RETURN EXIT
}

echo "================================================================================"
echo "SwarmSec Sprint 5 End-to-End Validation"
echo "Sequence: Clean Report -> Corroboration Arriving -> Dense-Cluster Attack"
echo "Total Iterations: ${REPEAT_COUNT}"
echo "================================================================================"

for i in $(seq 1 "${REPEAT_COUNT}"); do
    run_single_iteration "$i"
done

echo ""
echo "================================================================================"
echo "✓ SUCCESS: All ${REPEAT_COUNT} iterations completed with NO manual intervention."
echo "================================================================================"
