"""Tests for feedback, endorsement graph, and correlated-evidence down-weighting.

Sprint 4 — these tests verify:
1. Endorsement graph construction
2. Feedback weight calculation (down-weighting disproportionate endorsers)
3. Mutual clustering amplification
4. Dense-cluster attack detection
5. False-positive test: legitimate closely-connected pseudonyms don't get flagged
   (or documentation of findings if they do)
"""

from datetime import UTC, datetime, timedelta

from swarmsec.node.feedback_graph import build_endorsement_graph, get_feedback_weight
from swarmsec.node.models import (
    SignableEnvelopeFields,
    StixIndicator,
    StixOpinion,
    SwarmSecMessage,
    TLPMarking,
)
from swarmsec.node.scoring import compute_corroboration_score

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_indicator(credential_id: str, pattern: str, minutes_offset: int = 0) -> SwarmSecMessage:
    """Create a signed indicator message."""
    ts = (datetime.now(UTC) + timedelta(minutes=minutes_offset)).isoformat() + "Z"
    payload = StixIndicator(
        pattern=pattern,
        object_marking_refs=[TLPMarking.GREEN],
    )
    envelope = SignableEnvelopeFields(
        credential_id=credential_id,
        sequence_number=1,
        timestamp=ts,
        payload_hash="dummy",
    )
    return SwarmSecMessage(envelope=envelope, payload=payload, signature="dummy")


def _make_opinion(credential_id: str, indicator_ids: list, opinion: str = "agree",
                  minutes_offset: int = 0) -> SwarmSecMessage:
    """Create a signed opinion (feedback) message."""
    ts = (datetime.now(UTC) + timedelta(minutes=minutes_offset)).isoformat() + "Z"
    payload = StixOpinion(
        opinion=opinion,
        object_refs=indicator_ids,
        object_marking_refs=[TLPMarking.GREEN],
    )
    envelope = SignableEnvelopeFields(
        credential_id=credential_id,
        sequence_number=1,
        timestamp=ts,
        payload_hash="dummy",
    )
    return SwarmSecMessage(envelope=envelope, payload=payload, signature="dummy")


# ---------------------------------------------------------------------------
# Endorsement Graph — Unit Tests
# ---------------------------------------------------------------------------

class TestEndorsementGraph:
    """Tests for build_endorsement_graph."""

    def test_empty_messages(self):
        graph, totals = build_endorsement_graph({})
        assert graph == {}
        assert totals == {}

    def test_indicators_only_no_graph(self):
        """Indicators without any opinions produce an empty graph."""
        msg1 = _make_indicator("cred_a", "[ipv4-addr:value = '1.2.3.4']")
        all_messages = {msg1.envelope.message_id: msg1}
        graph, totals = build_endorsement_graph(all_messages)
        assert graph == {}
        assert totals == {}

    def test_single_opinion_creates_edge(self):
        ind = _make_indicator("cred_a", "[ipv4-addr:value = '1.2.3.4']")
        opinion = _make_opinion("cred_b", [ind.payload.id])
        all_messages = {
            ind.envelope.message_id: ind,
            opinion.envelope.message_id: opinion,
        }
        graph, totals = build_endorsement_graph(all_messages)

        assert "cred_b" in graph
        assert graph["cred_b"]["cred_a"] == 1
        assert totals["cred_b"] == 1

    def test_self_endorsement_ignored(self):
        """Self-endorsement (someone opining on their own indicator) is excluded."""
        ind = _make_indicator("cred_a", "[ipv4-addr:value = '1.2.3.4']")
        self_opinion = _make_opinion("cred_a", [ind.payload.id])
        all_messages = {
            ind.envelope.message_id: ind,
            self_opinion.envelope.message_id: self_opinion,
        }
        graph, totals = build_endorsement_graph(all_messages)
        assert "cred_a" not in graph

    def test_multiple_opinions_accumulate(self):
        """Multiple opinions from the same giver to the same target accumulate."""
        ind = _make_indicator("cred_a", "[ipv4-addr:value = '1.2.3.4']")
        op1 = _make_opinion("cred_b", [ind.payload.id], minutes_offset=0)
        op2 = _make_opinion("cred_b", [ind.payload.id], minutes_offset=1)
        all_messages = {
            ind.envelope.message_id: ind,
            op1.envelope.message_id: op1,
            op2.envelope.message_id: op2,
        }
        graph, totals = build_endorsement_graph(all_messages)
        assert graph["cred_b"]["cred_a"] == 2
        assert totals["cred_b"] == 2


# ---------------------------------------------------------------------------
# Feedback Weight — Unit Tests
# ---------------------------------------------------------------------------

class TestFeedbackWeight:
    """Tests for get_feedback_weight."""

    def test_first_endorsement_full_weight(self):
        """First endorsement from any giver always gets weight 1.0."""
        graph = {"cred_b": {"cred_a": 1}}
        totals = {"cred_b": 1}
        weight = get_feedback_weight("cred_b", "cred_a", graph, totals)
        assert weight == 1.0

    def test_exclusive_endorser_downweighted(self):
        """A giver who only endorses one target gets increasingly down-weighted."""
        # cred_b endorsed cred_a 5 times, nobody else
        graph = {"cred_b": {"cred_a": 5}}
        totals = {"cred_b": 5}
        weight = get_feedback_weight("cred_b", "cred_a", graph, totals)
        assert weight < 1.0, "Exclusive endorser should be down-weighted"

    def test_diverse_endorser_not_downweighted(self):
        """A giver who endorses many targets is not heavily down-weighted for any single one."""
        # cred_b endorsed cred_a once, but also endorsed cred_c, cred_d, cred_e
        graph = {"cred_b": {"cred_a": 1, "cred_c": 3, "cred_d": 2, "cred_e": 1}}
        totals = {"cred_b": 7}
        weight = get_feedback_weight("cred_b", "cred_a", graph, totals)
        assert weight == 1.0, "Diverse endorser should keep full weight"

    def test_mutual_clustering_amplifies_penalty(self):
        """When both A->B and B->A are heavy, the mutual penalty amplifies down-weighting."""
        # cred_a and cred_b heavily endorse each other
        graph = {
            "cred_a": {"cred_b": 5},
            "cred_b": {"cred_a": 5},
        }
        totals = {"cred_a": 5, "cred_b": 5}
        weight_ab = get_feedback_weight("cred_a", "cred_b", graph, totals)
        weight_ba = get_feedback_weight("cred_b", "cred_a", graph, totals)
        assert weight_ab == 0.0, "Mutual heavy endorsers should be fully down-weighted"
        assert weight_ba == 0.0, "Mutual heavy endorsers should be fully down-weighted"

    def test_unknown_giver_full_weight(self):
        """A giver not in the graph at all (first interaction) gets full weight."""
        graph = {}
        totals = {}
        weight = get_feedback_weight("cred_new", "cred_a", graph, totals)
        assert weight == 1.0


# ---------------------------------------------------------------------------
# Dense Cluster Attack Scenario
# ---------------------------------------------------------------------------

class TestDenseClusterAttack:
    """
    Simulates Sprint 4's dense cluster attack:
    Several pseudonyms rapidly, densely endorsing each other.
    
    This is exactly what AGENTS.md calls "credentialed collusion resistance"
    testing — not "Sybil resistance" or "collusion detection."
    """

    def test_dense_cluster_downweighted(self):
        """
        Attack scenario: 4 colluding pseudonyms each create an indicator and then
        densely endorse each other's indicators. The feedback from within the cluster
        should be down-weighted due to mutual clustering.
        """
        pattern = "[file:hashes.'SHA-256' = 'malicious_hash_abc123']"

        # 4 colluding nodes each submit the same indicator
        colluders = ["colluder_a", "colluder_b", "colluder_c", "colluder_d"]
        indicators = {}
        all_messages = {}

        for i, cred in enumerate(colluders):
            ind = _make_indicator(cred, pattern, minutes_offset=i)
            indicators[cred] = ind
            all_messages[ind.envelope.message_id] = ind

        # Each colluder endorses every other colluder's indicator (dense cross-endorsement)
        opinions = []
        t = 10
        for giver in colluders:
            for target in colluders:
                if giver != target:
                    op = _make_opinion(giver, [indicators[target].payload.id], minutes_offset=t)
                    all_messages[op.envelope.message_id] = op
                    opinions.append(op)
                    t += 1

        # Build the endorsement graph
        graph, totals = build_endorsement_graph(all_messages)

        # Each colluder endorsed exactly 3 others — and all 3 of their endorsements
        # go to other colluders. This is a classic dense cluster pattern.
        for cred in colluders:
            assert cred in graph, f"{cred} should be in endorsement graph"
            assert totals[cred] == 3, f"{cred} should have endorsed exactly 3 targets"

        # Check that cross-cluster endorsements are down-weighted
        for giver in colluders:
            for target in colluders:
                if giver != target:
                    weight = get_feedback_weight(giver, target, graph, totals)
                    # With mutual endorsement, weight should be < 1.0
                    assert weight < 1.0, (
                        f"Dense cluster: {giver}->{target} should be down-weighted, "
                        f"got {weight}"
                    )

    def test_dense_cluster_scores_lower_than_legitimate(self):
        """
        Compare: a dense cluster's feedback-boosted score vs legitimate independent
        corroboration. The cluster should score lower.
        """
        pattern = "[file:hashes.'SHA-256' = 'deadbeef123']"

        # --- Legitimate scenario: 3 independent orgs report the same hash ---
        legit_msgs = [
            _make_indicator("org_alpha", pattern, minutes_offset=0),
            _make_indicator("org_beta", pattern, minutes_offset=5),
            _make_indicator("org_gamma", pattern, minutes_offset=10),
        ]
        legit_result = compute_corroboration_score(legit_msgs)

        # --- Attack scenario: 1 real report + dense cluster feedback ---
        real_indicator = _make_indicator("honest_org", pattern, minutes_offset=0)
        all_messages = {real_indicator.envelope.message_id: real_indicator}

        # Create 3 colluding endorsers who mutually endorse each other too
        colluders = ["shill_x", "shill_y", "shill_z"]
        # First, each colluder needs their own indicator so we can build mutual endorsements
        colluder_indicators = {}
        for cred in colluders:
            ci = _make_indicator(cred, "[ipv4-addr:value = '0.0.0.0']", minutes_offset=20)
            colluder_indicators[cred] = ci
            all_messages[ci.envelope.message_id] = ci

        # Colluders mutually endorse each other (builds the dense graph)
        t = 30
        for giver in colluders:
            for target in colluders:
                if giver != target:
                    op = _make_opinion(giver, [colluder_indicators[target].payload.id],
                                       minutes_offset=t)
                    all_messages[op.envelope.message_id] = op
                    t += 1

        # Colluders also endorse the honest indicator
        feedbacks = []
        for cred in colluders:
            fb = _make_opinion(cred, [real_indicator.payload.id], minutes_offset=t)
            all_messages[fb.envelope.message_id] = fb
            feedbacks.append(fb)
            t += 1

        attack_result = compute_corroboration_score(
            [real_indicator],
            feedbacks=feedbacks,
            all_messages=all_messages,
        )

        # The legitimate 3-source corroboration should score >= the attack scenario
        assert legit_result["local_corroboration_score"] >= attack_result["local_corroboration_score"], (
            f"Legitimate ({legit_result['local_corroboration_score']}) should score >= "
            f"cluster attack ({attack_result['local_corroboration_score']})"
        )

        # The attack result should have a down-weighting flag
        assert "feedback_downweighted" in attack_result["flags"], (
            "Dense cluster feedback should trigger feedback_downweighted flag"
        )


# ---------------------------------------------------------------------------
# False-Positive Test: Legitimate Closely-Connected Pseudonyms
# ---------------------------------------------------------------------------

class TestFalsePositiveLegitimate:
    """
    Sprint 4 requirement: confirm that a small set of legitimate, genuinely
    closely-connected pseudonyms (e.g., partner CERTs corroborating through
    a side channel) doesn't get flagged the same way as a dense attack cluster,
    or document clearly if it does.
    
    Key difference from attack cluster: legitimate partners endorse many different
    entities, not just each other.
    """

    def test_partner_certs_with_diverse_endorsements(self):
        """
        Two partner CERTs who collaborate closely but also endorse indicators
        from many other orgs. They should NOT be heavily down-weighted because
        their endorsement graph is diverse, not exclusively mutual.
        """
        # Create indicators from many independent orgs
        other_orgs = [f"org_{i}" for i in range(10)]
        all_messages = {}
        other_indicators = {}

        for i, org in enumerate(other_orgs):
            ind = _make_indicator(org, f"[ipv4-addr:value = '10.0.{i}.1']", minutes_offset=i)
            other_indicators[org] = ind
            all_messages[ind.envelope.message_id] = ind

        # Two partner CERTs
        cert_a_ind = _make_indicator("cert_a", "[ipv4-addr:value = '192.168.1.1']", minutes_offset=20)
        cert_b_ind = _make_indicator("cert_b", "[ipv4-addr:value = '192.168.1.2']", minutes_offset=21)
        all_messages[cert_a_ind.envelope.message_id] = cert_a_ind
        all_messages[cert_b_ind.envelope.message_id] = cert_b_ind

        # Both CERTs endorse each other (legitimate collaboration)
        t = 30
        op_ab = _make_opinion("cert_a", [cert_b_ind.payload.id], minutes_offset=t)
        all_messages[op_ab.envelope.message_id] = op_ab
        t += 1
        op_ba = _make_opinion("cert_b", [cert_a_ind.payload.id], minutes_offset=t)
        all_messages[op_ba.envelope.message_id] = op_ba
        t += 1

        # But they ALSO endorse many other orgs' indicators (diverse behavior)
        for org in other_orgs[:5]:
            op = _make_opinion("cert_a", [other_indicators[org].payload.id], minutes_offset=t)
            all_messages[op.envelope.message_id] = op
            t += 1

        for org in other_orgs[5:]:
            op = _make_opinion("cert_b", [other_indicators[org].payload.id], minutes_offset=t)
            all_messages[op.envelope.message_id] = op
            t += 1

        graph, totals = build_endorsement_graph(all_messages)

        # cert_a endorsed cert_b once out of 6 total endorsements — not concentrated
        weight_ab = get_feedback_weight("cert_a", "cert_b", graph, totals)
        weight_ba = get_feedback_weight("cert_b", "cert_a", graph, totals)

        # Both should retain full or near-full weight because their endorsement
        # patterns are diverse
        assert weight_ab == 1.0, (
            f"Partner CERT A->B should keep full weight with diverse endorsements, got {weight_ab}"
        )
        assert weight_ba == 1.0, (
            f"Partner CERT B->A should keep full weight with diverse endorsements, got {weight_ba}"
        )

    def test_exclusive_partners_documented_behavior(self):
        """
        Edge case: two CERTs who ONLY endorse each other and nobody else.
        This looks structurally identical to a two-node colluding cluster.
        
        Per Sprint 4 requirement: "document clearly if it does" get flagged.
        
        DOCUMENTED FINDING: Two pseudonyms that exclusively and repeatedly
        endorse only each other WILL be down-weighted. This is a known
        limitation — the system cannot distinguish exclusive mutual endorsement
        from collusion without external context. This is documented in NOTES.md.
        """
        ind_a = _make_indicator("exclusive_a", "[ipv4-addr:value = '10.1.1.1']")
        ind_b = _make_indicator("exclusive_b", "[ipv4-addr:value = '10.1.1.2']")
        all_messages = {
            ind_a.envelope.message_id: ind_a,
            ind_b.envelope.message_id: ind_b,
        }

        # They only endorse each other, 3 times each
        t = 10
        for _ in range(3):
            op = _make_opinion("exclusive_a", [ind_b.payload.id], minutes_offset=t)
            all_messages[op.envelope.message_id] = op
            t += 1
            op = _make_opinion("exclusive_b", [ind_a.payload.id], minutes_offset=t)
            all_messages[op.envelope.message_id] = op
            t += 1

        graph, totals = build_endorsement_graph(all_messages)
        weight_ab = get_feedback_weight("exclusive_a", "exclusive_b", graph, totals)
        weight_ba = get_feedback_weight("exclusive_b", "exclusive_a", graph, totals)

        # Document: exclusive mutual endorsers ARE down-weighted.
        # This is the expected and documented behavior — the system treats
        # exclusive mutual endorsement the same as collusion.
        assert weight_ab < 1.0, "Exclusive mutual endorsers should be down-weighted"
        assert weight_ba < 1.0, "Exclusive mutual endorsers should be down-weighted"
