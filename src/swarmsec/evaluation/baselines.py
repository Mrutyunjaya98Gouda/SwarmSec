"""Baseline scorers for Sprint 6 evaluation.

Two baselines are implemented here to compare against SwarmSec's full scoring:

1. QuorumScorer — simple majority-vote: accepts an indicator once N distinct
   sources have reported it, regardless of their independence or clustering.

2. PlainReputationScorer — conventional source-reputation only: assigns each
   credential a fixed trust score based on how many times it has submitted
   messages in the past (more = higher rep), and accepts an indicator if the
   sum of reporter reputations exceeds a threshold. No corroboration checking,
   no independence checking, no correlated-evidence down-weighting.

Neither baseline is "wrong" as a concept — they represent real designs that
practitioners use. The harness exists to show how each performs against the
Sprint 4 attack scenarios and legitimate scenarios.
"""

from __future__ import annotations

from swarmsec.node.models import SwarmSecMessage

# ---------------------------------------------------------------------------
# Baseline 1 — Quorum / majority-vote
# ---------------------------------------------------------------------------

class QuorumScorer:
    """Accept an indicator once at least *quorum* distinct credentials report it.

    No independence checking. No correlated-evidence down-weighting.
    Every credential counts equally, even if they all endorse each other.

    Parameters
    ----------
    quorum : int
        Number of distinct credential IDs required to accept an indicator.
        Default is 3 (a common real-world threshold).
    """

    def __init__(self, quorum: int = 3) -> None:
        self.quorum = quorum

    def score(self, messages: list[SwarmSecMessage]) -> dict:
        """
        Compute the quorum result for a list of messages about one indicator.

        Returns
        -------
        dict with keys:
            accepted (bool)   — True if quorum reached
            reporter_count    — number of distinct credential IDs
            quorum_threshold  — the configured threshold
            method            — "quorum"
        """
        if not messages:
            return {
                "accepted": False,
                "reporter_count": 0,
                "quorum_threshold": self.quorum,
                "method": "quorum",
            }

        distinct_credentials = {
            m.envelope.credential_id
            for m in messages
            if m.payload.type == "indicator"
        }
        reporter_count = len(distinct_credentials)
        return {
            "accepted": reporter_count >= self.quorum,
            "reporter_count": reporter_count,
            "quorum_threshold": self.quorum,
            "method": "quorum",
        }


# ---------------------------------------------------------------------------
# Baseline 2 — Plain source reputation only
# ---------------------------------------------------------------------------

class PlainReputationScorer:
    """Accept an indicator based purely on the sum of reporter reputation scores.

    Reputation is built from a credential's historical message count:
        rep(cred) = min(1.0, messages_seen / saturation)
    This mimics a simple "prolific senders are trusted" heuristic.

    No corroboration matching, no independence checking, no
    correlated-evidence down-weighting. Feedback/opinions are ignored.

    Parameters
    ----------
    saturation : int
        Number of messages after which a credential reaches maximum reputation.
        Default is 10.
    accept_threshold : float
        Sum-of-reputations required to accept an indicator. Default is 2.0
        (i.e., two fully-reputed sources, or more lower-rep sources).
    """

    def __init__(self, saturation: int = 10, accept_threshold: float = 2.0) -> None:
        self.saturation = saturation
        self.accept_threshold = accept_threshold
        # reputation table: cred_id -> message count seen historically
        self._history: dict[str, int] = {}

    def _reputation(self, cred_id: str) -> float:
        """Reputation score for a credential, in [0.0, 1.0]."""
        count = self._history.get(cred_id, 0)
        return min(1.0, count / self.saturation)

    def observe(self, messages: list[SwarmSecMessage]) -> None:
        """Update the reputation history from a list of messages.

        Call this on *all* historical messages before calling score().
        """
        for m in messages:
            cred_id = m.envelope.credential_id
            self._history[cred_id] = self._history.get(cred_id, 0) + 1

    def score(self, messages: list[SwarmSecMessage]) -> dict:
        """
        Compute the plain-reputation result for messages about one indicator.

        Returns
        -------
        dict with keys:
            accepted (bool)         — True if reputation sum exceeds threshold
            reputation_sum (float)  — summed reputation of unique reporters
            accept_threshold        — the configured threshold
            reporter_count          — number of distinct credential IDs
            method                  — "plain_reputation"
        """
        if not messages:
            return {
                "accepted": False,
                "reputation_sum": 0.0,
                "accept_threshold": self.accept_threshold,
                "reporter_count": 0,
                "method": "plain_reputation",
            }

        seen = set()
        rep_sum = 0.0
        for m in messages:
            if m.payload.type != "indicator":
                continue
            cid = m.envelope.credential_id
            if cid in seen:
                continue
            seen.add(cid)
            rep_sum += self._reputation(cid)

        return {
            "accepted": rep_sum >= self.accept_threshold,
            "reputation_sum": round(rep_sum, 3),
            "accept_threshold": self.accept_threshold,
            "reporter_count": len(seen),
            "method": "plain_reputation",
        }
