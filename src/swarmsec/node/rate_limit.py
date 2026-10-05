"""Rate limiting for SwarmSec gossip."""

import time
from collections import defaultdict

# Epoch configuration
EPOCH_DURATION_SECONDS = 60
MAX_MESSAGES_PER_EPOCH = 5

# Memory cap for the message-id seen-set (prevents unbounded growth).
# At 36 bytes per UUID, 100k entries ≈ 3.6 MB — acceptable for a node daemon.
SEEN_IDS_MAX_SIZE = 100_000


class RateLimiter:
    def __init__(self):
        # Maps epoch_id -> (credential_id -> count)
        self.epochs = defaultdict(lambda: defaultdict(int))
        # Persistent set of message_ids already processed (replay prevention).
        # Cleared only when exceeding SEEN_IDS_MAX_SIZE (oldest-first not tracked;
        # a full reset on overflow is a documented simplification for demo scale).
        self._seen_message_ids: set[str] = set()

    def _get_current_epoch(self) -> int:
        return int(time.time() // EPOCH_DURATION_SECONDS)

    def is_replay(self, message_id: str) -> bool:
        """Return True if this message_id has already been processed."""
        return message_id in self._seen_message_ids

    def check_and_consume(
        self, credential_id: str, timestamp_str: str, message_id: str = ""
    ) -> bool:
        """
        Check if the credential has exceeded its rate limit in the current epoch.

        Also rejects replayed message_ids (same message_id seen before, regardless
        of epoch). Returns True if the message is allowed, False if it should be
        dropped.

        In a real system, we base the epoch on the node's local time (not the
        message timestamp) to prevent future-dating attacks — this is intentional
        and documented in NOTES.md.
        """
        # Replay check: reject any message_id we have already seen
        if message_id and message_id in self._seen_message_ids:
            return False

        epoch_id = self._get_current_epoch()

        count = self.epochs[epoch_id][credential_id]
        if count >= MAX_MESSAGES_PER_EPOCH:
            return False

        # Consume the slot
        self.epochs[epoch_id][credential_id] += 1

        # Record the message_id to prevent future replays
        if message_id:
            if len(self._seen_message_ids) >= SEEN_IDS_MAX_SIZE:
                # Documented simplification: clear on overflow rather than LRU
                self._seen_message_ids.clear()
            self._seen_message_ids.add(message_id)

        # Cleanup old epochs periodically (naive implementation for demo)
        old_epochs = [e for e in self.epochs.keys() if e < epoch_id - 2]
        for e in old_epochs:
            del self.epochs[e]

        return True
