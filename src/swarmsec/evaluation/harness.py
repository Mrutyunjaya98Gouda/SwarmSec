"""Evaluation harness for Sprint 6.

Runs three scorers — SwarmSec, quorum, and plain-reputation — against
two attack scenarios (dense-cluster and staggered-cluster from Sprint 4)
and a legitimate corroboration scenario, then reports:

  - False-acceptance rate (FAR): fraction of poisoned indicators that each
    scorer incorrectly accepts.
  - Time-to-acceptance (TTA): how many messages must arrive before each
    scorer accepts a legitimately-reported indicator.

Results are reported honestly, including anywhere SwarmSec does not clearly
win.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import uuid4

from swarmsec.evaluation.baselines import PlainReputationScorer, QuorumScorer
from swarmsec.node.models import (
    SignableEnvelopeFields,
    StixIndicator,
    StixOpinion,
    SwarmSecMessage,
    TLPMarking,
)
from swarmsec.node.scoring import compute_corroboration_score

# ---------------------------------------------------------------------------
# Helpers to build synthetic messages without a live registrar
# ---------------------------------------------------------------------------

_TLP_CLEAR = TLPMarking.CLEAR


def make_indicator(
    pattern: str,
    credential_id: str,
    seq: int,
    external_url: str | None = None,
) -> SwarmSecMessage:
    """Build a synthetic SwarmSecMessage carrying a STIX Indicator.

    Signatures are intentionally omitted here — the harness tests scoring
    logic, not cryptographic verification (that is tested in test_gossip_verify.py).
    """
    refs = []
    if external_url:
        from swarmsec.node.models import StixExternalReference
        refs = [StixExternalReference(source_name="test-feed", url=external_url)]

    payload = StixIndicator(
        pattern=pattern,
        pattern_type="stix",
        object_marking_refs=[_TLP_CLEAR],
        external_references=refs,
    )
    envelope = SignableEnvelopeFields(
        credential_id=credential_id,
        sequence_number=seq,
        message_id=str(uuid4()),
        payload_hash="fake-hash-for-evaluation",
    )
    return SwarmSecMessage(envelope=envelope, signature="", payload=payload)


# Keep private alias for backward compatibility within this module
_make_indicator = make_indicator


def make_opinion(
    giver_cred: str,
    target_msg: SwarmSecMessage,
    seq: int,
    opinion_value: str = "agree",
) -> SwarmSecMessage:
    """Build a synthetic Opinion (feedback) message."""
    payload = StixOpinion(
        opinion=opinion_value,
        object_refs=[target_msg.payload.id, target_msg.envelope.message_id],
        object_marking_refs=[_TLP_CLEAR],
    )
    envelope = SignableEnvelopeFields(
        credential_id=giver_cred,
        sequence_number=seq,
        message_id=str(uuid4()),
        payload_hash="fake-hash-for-evaluation",
    )
    return SwarmSecMessage(envelope=envelope, signature="", payload=payload)


# Keep private alias for backward compatibility within this module
_make_opinion = make_opinion


# ---------------------------------------------------------------------------
# Scenario generators
# ---------------------------------------------------------------------------

def build_legitimate_scenario(
    num_independent_reporters: int = 5,
    pattern: str = "[file:hashes.'SHA-256' = 'abc123']",
) -> tuple[list[SwarmSecMessage], dict]:
    """
    Legitimate scenario: N independent credentialed orgs each report the same
    indicator from first-hand observation (no shared external reference).

    Returns (messages, metadata).
    """
    messages = []
    all_msgs: dict = {}
    for i in range(num_independent_reporters):
        cred = f"cred-legit-{i}"
        msg = _make_indicator(pattern, cred, seq=1)
        messages.append(msg)
        all_msgs[msg.envelope.message_id] = msg

    return messages, {"all_messages": all_msgs, "feedbacks": []}


def build_dense_cluster_attack(
    cluster_size: int = 6,
    pattern: str = "[ipv4-addr:value = '10.0.0.1']",
) -> tuple[list[SwarmSecMessage], dict]:
    """
    Dense-cluster attack (Sprint 4 scenario 1): a tight cluster of pseudonyms
    all report the same poisoned indicator AND mutually endorse each other.

    Every member endorses every other member exactly once — maximum mutual density.

    Returns (indicator_messages, metadata_with_feedbacks_and_all_messages).
    """
    creds = [f"cred-cluster-{i}" for i in range(cluster_size)]
    indicator_messages: list[SwarmSecMessage] = []
    all_msgs: dict = {}

    # Each cluster member reports the poisoned indicator
    for cred in creds:
        msg = _make_indicator(pattern, cred, seq=1)
        indicator_messages.append(msg)
        all_msgs[msg.envelope.message_id] = msg

    # Each member endorses all others (dense mutual endorsement)
    feedbacks: list[SwarmSecMessage] = []
    seq = 2
    for giver in creds:
        for target_msg in indicator_messages:
            if target_msg.envelope.credential_id != giver:
                fb = _make_opinion(giver, target_msg, seq=seq)
                feedbacks.append(fb)
                all_msgs[fb.envelope.message_id] = fb
                seq += 1

    return indicator_messages, {"all_messages": all_msgs, "feedbacks": feedbacks}


def build_staggered_cluster_attack(
    cluster_size: int = 6,
    endorsement_fraction: float = 0.4,
    pattern: str = "[domain-name:value = 'evil.example']",
) -> tuple[list[SwarmSecMessage], dict]:
    """
    Staggered-cluster attack (Sprint 4 scenario 2): same cluster, but only a
    fraction of members endorse each other (sparser graph, less detectable).

    endorsement_fraction: probability that any two members endorse each other.
    """
    import random
    random.seed(42)  # deterministic for reproducible evaluation

    creds = [f"cred-stagger-{i}" for i in range(cluster_size)]
    indicator_messages: list[SwarmSecMessage] = []
    all_msgs: dict = {}

    for cred in creds:
        msg = _make_indicator(pattern, cred, seq=1)
        indicator_messages.append(msg)
        all_msgs[msg.envelope.message_id] = msg

    feedbacks: list[SwarmSecMessage] = []
    seq = 2
    for i, giver in enumerate(creds):
        for j, target_msg in enumerate(indicator_messages):
            if i == j:
                continue
            if random.random() < endorsement_fraction:
                fb = _make_opinion(giver, target_msg, seq=seq)
                feedbacks.append(fb)
                all_msgs[fb.envelope.message_id] = fb
                seq += 1

    return indicator_messages, {"all_messages": all_msgs, "feedbacks": feedbacks}


def build_dense_cluster_endorsement_boost(
    cluster_size: int = 6,
    pattern: str = "[file:hashes.'SHA-256' = 'evilhash123']",
) -> tuple[list[SwarmSecMessage], dict]:
    """
    Dense-cluster endorsement-boost attack (the attack model for the feedback pathway).

    One legitimate-looking indicator is posted by a single pseudonym.
    Then a dense cluster of pseudonyms mutually endorses each other AND
    endorses the indicator — attempting to inflate its apparent corroboration.

    This is the attack that SwarmSec's correlated-evidence down-weighting
    is specifically designed to detect, per Sprint 4.

    Returns (all_indicator_messages, metadata_with_feedbacks_and_all_messages).
    The first message in the returned list is the "real" report; the rest are
    cluster members' dummy indicators used to build the endorsement graph.
    """
    real_cred = "cred-attacker-real"
    real_indicator = make_indicator(pattern, real_cred, seq=1)
    all_msgs: dict = {real_indicator.envelope.message_id: real_indicator}

    # Cluster members each file a dummy indicator (for graph construction)
    cluster_creds = [f"cred-boost-{i}" for i in range(cluster_size)]
    cluster_indicators: dict = {}
    for cred in cluster_creds:
        ci = make_indicator("[ipv4-addr:value = '192.0.2.1']", cred, seq=1)
        cluster_indicators[cred] = ci
        all_msgs[ci.envelope.message_id] = ci

    # Dense mutual endorsements among cluster members
    feedbacks: list[SwarmSecMessage] = []
    seq = 2
    for giver in cluster_creds:
        for target_cred, target_ci in cluster_indicators.items():
            if target_cred != giver:
                fb = make_opinion(giver, target_ci, seq=seq)
                all_msgs[fb.envelope.message_id] = fb
                feedbacks.append(fb)
                seq += 1

    # Cluster endorses the real indicator
    for cred in cluster_creds:
        fb = make_opinion(cred, real_indicator, seq=seq)
        all_msgs[fb.envelope.message_id] = fb
        feedbacks.append(fb)
        seq += 1

    # Return only the real indicator as the "reported" message
    return [real_indicator], {"all_messages": all_msgs, "feedbacks": feedbacks}


# ---------------------------------------------------------------------------
# Metric: Time-to-acceptance
# ---------------------------------------------------------------------------

def measure_tta(
    messages: list[SwarmSecMessage],
    scorer_fn,
) -> int | None:
    """
    Measure how many indicator messages must arrive before scorer_fn accepts.

    scorer_fn(messages_so_far) -> bool

    Returns the message count at first acceptance, or None if never accepted.
    """
    indicator_msgs = [m for m in messages if m.payload.type == "indicator"]
    for i in range(1, len(indicator_msgs) + 1):
        if scorer_fn(indicator_msgs[:i]):
            return i
    return None


# ---------------------------------------------------------------------------
# Main evaluation entry point
# ---------------------------------------------------------------------------

@dataclass
class ScenarioResult:
    scenario_name: str
    method: str
    accepted: bool
    details: dict = field(default_factory=dict)


def run_evaluation() -> list[ScenarioResult]:
    """
    Run all three scorers across all scenarios. Return raw results.

    Four scenarios:
      1. Legitimate — 5 independent reporters of a SHA-256 hash
      2. Dense-cluster multi-reporter — 6 cluster members each file the indicator
         AND endorse each other. SwarmSec's corroboration base-loop counts these
         as independent reporters (no shared external_references). This is a documented
         limitation: per-reporter cluster detection requires external-reference
         overlap or other distinguishing signals.
      3. Staggered-cluster multi-reporter — same as above, sparser endorsements.
      4. Dense-cluster endorsement-boost — one real indicator, then 6 mutually-
         endorsing cluster members try to boost it via feedback. This is the attack
         pathway that SwarmSec's correlated-evidence down-weighting detects.

    Three scorers:
      A. SwarmSec (compute_corroboration_score — accepted if score > 0 and
         independent_sources > 1)
      B. Quorum (threshold=3)
      C. PlainReputation (accept_threshold=2.0, saturation=10)
    """
    results: list[ScenarioResult] = []

    # Build scenarios
    legit_msgs, legit_meta = build_legitimate_scenario(num_independent_reporters=5)
    dense_msgs, dense_meta = build_dense_cluster_attack(cluster_size=6)
    stagger_msgs, stagger_meta = build_staggered_cluster_attack(
        cluster_size=6, endorsement_fraction=0.4
    )
    boost_msgs, boost_meta = build_dense_cluster_endorsement_boost(cluster_size=6)

    scenarios = [
        ("legitimate", legit_msgs, legit_meta),
        ("dense_cluster_attack", dense_msgs, dense_meta),
        ("staggered_cluster_attack", stagger_msgs, stagger_meta),
        ("dense_cluster_endorsement_boost", boost_msgs, boost_meta),
    ]

    quorum = QuorumScorer(quorum=3)
    plain_rep = PlainReputationScorer(saturation=10, accept_threshold=2.0)

    # Build reputation history from all messages across all scenarios
    # (simulates a node that has been running and building reputation)
    for _, msgs, meta in scenarios:
        plain_rep.observe(msgs)
        plain_rep.observe(meta.get("feedbacks", []))

    for name, msgs, meta in scenarios:
        indicator_msgs = [m for m in msgs if m.payload.type == "indicator"]

        # --- SwarmSec ---
        sw_result = compute_corroboration_score(
            messages=indicator_msgs,
            feedbacks=meta.get("feedbacks", []),
            all_messages=meta.get("all_messages", {}),
        )
        sw_accepted = sw_result["local_corroboration_score"] > 0 and sw_result["independent_sources"] > 1
        results.append(ScenarioResult(
            scenario_name=name,
            method="swarmsec",
            accepted=sw_accepted,
            details=sw_result,
        ))

        # --- Quorum ---
        q_result = quorum.score(indicator_msgs)
        results.append(ScenarioResult(
            scenario_name=name,
            method="quorum",
            accepted=q_result["accepted"],
            details=q_result,
        ))

        # --- Plain Reputation ---
        pr_result = plain_rep.score(indicator_msgs)
        results.append(ScenarioResult(
            scenario_name=name,
            method="plain_reputation",
            accepted=pr_result["accepted"],
            details=pr_result,
        ))

    return results


def compute_far(results: list[ScenarioResult]) -> dict[str, float]:
    """
    False-acceptance rate for each method across attack scenarios.

    FAR = (attacks accepted) / (total attack scenarios)

    Attack scenarios:
      - dense_cluster_attack (multi-reporter cluster — documented limitation for SwarmSec)
      - staggered_cluster_attack (sparser multi-reporter cluster)
      - dense_cluster_endorsement_boost (endorsement inflation — SwarmSec's designed defense)
    """
    attack_names = {
        "dense_cluster_attack",
        "staggered_cluster_attack",
        "dense_cluster_endorsement_boost",
    }
    attack_results: dict[str, list[bool]] = {}

    for r in results:
        if r.scenario_name in attack_names:
            attack_results.setdefault(r.method, []).append(r.accepted)

    far: dict[str, float] = {}
    for method, acceptances in attack_results.items():
        far[method] = sum(acceptances) / len(acceptances) if acceptances else 0.0

    return far


def compute_tta(
    messages: list[SwarmSecMessage],
    all_messages: dict,
    feedbacks: list[SwarmSecMessage],
) -> dict[str, int | None]:
    """
    Time-to-acceptance (TTA) for the legitimate scenario.

    Returns number of messages required per method, or None if never accepted.
    """
    indicator_msgs = [m for m in messages if m.payload.type == "indicator"]
    quorum = QuorumScorer(quorum=3)
    plain_rep = PlainReputationScorer(saturation=10, accept_threshold=2.0)
    plain_rep.observe(messages)

    def swarmsec_accepts(msgs):
        r = compute_corroboration_score(
            messages=msgs,
            feedbacks=feedbacks,
            all_messages=all_messages,
        )
        return r["local_corroboration_score"] > 0 and r["independent_sources"] > 1

    def quorum_accepts(msgs):
        return quorum.score(msgs)["accepted"]

    def plain_rep_accepts(msgs):
        return plain_rep.score(msgs)["accepted"]

    return {
        "swarmsec": measure_tta(indicator_msgs, swarmsec_accepts),
        "quorum": measure_tta(indicator_msgs, quorum_accepts),
        "plain_reputation": measure_tta(indicator_msgs, plain_rep_accepts),
    }
