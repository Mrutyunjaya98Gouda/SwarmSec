"""Feedback graph and correlated-evidence down-weighting logic.

This module builds an endorsement graph from Opinion messages and computes
down-weighting penalties to detect coordinated feedback from dense clusters
of mutually-endorsing pseudonyms.

Terminology per AGENTS.md:
  - "Correlated-evidence down-weighting," not "collusion detection."
  - "Credentialed collusion resistance," not "Sybil resistance."
"""

from typing import Dict, List, Set, Tuple
from swarmsec.node.models import SwarmSecMessage


def build_endorsement_graph(
    all_messages: Dict[str, SwarmSecMessage]
) -> Tuple[Dict[str, Dict[str, int]], Dict[str, int]]:
    """
    Builds a directed graph of who endorsed whom.

    Returns:
      graph: giver_cred -> (target_cred -> count)
      totals: giver_cred -> total_endorsements_given
    """
    graph: Dict[str, Dict[str, int]] = {}
    totals: Dict[str, int] = {}

    # First, map indicator IDs to their creator's credential ID
    indicator_creators: Dict[str, str] = {}
    for msg in all_messages.values():
        if msg.payload.type == "indicator":
            indicator_creators[msg.payload.id] = msg.envelope.credential_id

    # Then, tally the feedback (Opinions)
    for msg in all_messages.values():
        if msg.payload.type == "opinion":
            giver = msg.envelope.credential_id

            for target_indicator_id in msg.payload.object_refs:
                target_cred = indicator_creators.get(target_indicator_id)
                if target_cred and target_cred != giver:  # Don't count self-endorsement
                    if giver not in graph:
                        graph[giver] = {}
                        totals[giver] = 0
                    graph[giver][target_cred] = graph[giver].get(target_cred, 0) + 1
                    totals[giver] += 1

    return graph, totals


def _get_cluster_density(
    giver_cred: str,
    target_cred: str,
    graph: Dict[str, Dict[str, int]],
) -> float:
    """
    Measure how densely the giver's endorsement targets form a mutual cluster
    with the target.

    For each of the giver's endorsement targets (besides the target itself),
    check if they also endorse the target. The ratio of such mutual endorsers
    to total endorsement targets gives the cluster density.

    Returns a value in [0.0, 1.0]:
      - 0.0: none of the giver's other endorsees also endorse the target
      - 1.0: all of the giver's other endorsees also endorse the target (dense cluster)
    """
    giver_targets: Set[str] = set(graph.get(giver_cred, {}).keys())
    if len(giver_targets) <= 1:
        # Only one endorsement target: can't measure cluster density from graph structure alone
        # Fall back to mutual-endorsement check only
        return 0.0

    other_targets = giver_targets - {target_cred}
    if not other_targets:
        return 0.0

    # Count how many of giver's other endorsees also endorse the target
    mutual_endorsers = 0
    for other in other_targets:
        other_graph = graph.get(other, {})
        if target_cred in other_graph:
            mutual_endorsers += 1

    return mutual_endorsers / len(other_targets)


def get_feedback_weight(
    giver_cred: str,
    target_cred: str,
    graph: Dict[str, Dict[str, int]],
    totals: Dict[str, int],
) -> float:
    """
    Computes the weight of feedback from giver_cred toward target_cred.

    Down-weights when any of these signals are present:
      1. Repeat endorsement: giver endorses the same target multiple times.
      2. Mutual endorsement: target also endorses the giver (bidirectional edge).
      3. Cluster density: the giver's other endorsees also endorse the target
         (evidence of a coordinated cluster).

    Formula:
      repeat_penalty = (endorsements_to_target - 1) / max(1, total - 1)
      mutual_penalty = amplifier based on target->giver edge weight
      cluster_penalty = fraction of giver's other targets that also endorse target
      final_weight = max(0, 1 - repeat_penalty - mutual_amplification - cluster_penalty)
    """
    giver_graph = graph.get(giver_cred, {})
    endorsements_to_target = giver_graph.get(target_cred, 0)
    total_endorsements = totals.get(giver_cred, 0)

    # --- Signal 1: Repeat endorsement penalty ---
    if endorsements_to_target <= 1 or total_endorsements <= 1:
        repeat_penalty = 0.0
    else:
        repeat_penalty = (endorsements_to_target - 1) / (total_endorsements - 1)

    # --- Signal 2: Mutual endorsement amplification ---
    target_graph = graph.get(target_cred, {})
    target_total = totals.get(target_cred, 0)
    target_to_giver = target_graph.get(giver_cred, 0)

    mutual_penalty = 0.0
    if target_to_giver > 0:
        if target_total > 1 and target_to_giver > 1:
            mutual_penalty = (target_to_giver - 1) / (target_total - 1)
        else:
            # Even a single mutual endorsement is a weak signal
            mutual_penalty = 0.1

    # Amplify repeat penalty by mutual signal
    mutual_amplification = repeat_penalty * mutual_penalty

    # --- Signal 3: Cluster density penalty ---
    cluster_density = _get_cluster_density(giver_cred, target_cred, graph)
    # Scale cluster density: if >50% of giver's other targets also endorse the target,
    # that's strong evidence of a coordinated cluster
    cluster_penalty = cluster_density * 0.5  # max contribution = 0.5

    # --- Combined penalty ---
    total_penalty = repeat_penalty + mutual_amplification + cluster_penalty
    final_weight = max(0.0, 1.0 - total_penalty)

    return round(final_weight, 2)
