"""Rate limiting for SwarmSec gossip."""

import sqlite3
import time
from collections import defaultdict
from pathlib import Path

# Epoch configuration
EPOCH_DURATION_SECONDS = 60
MAX_MESSAGES_PER_EPOCH = 5

# SQLite persistence for replay prevention (TTL 7 days)
MESSAGE_TTL_SECONDS = 7 * 24 * 60 * 60
DB_PATH = Path(".swarmsec_replay.db")


class RateLimiter:
    def __init__(self):
        # Maps epoch_id -> (credential_id -> count)
        self.epochs = defaultdict(lambda: defaultdict(int))
        
        # Initialize SQLite for persistent replay prevention
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_messages (
                    message_id TEXT PRIMARY KEY,
                    timestamp_recorded INTEGER
                )
                """
            )
            # Create an index on the timestamp for fast TTL pruning
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON seen_messages (timestamp_recorded)")

    def _get_current_epoch(self) -> int:
        return int(time.time() // EPOCH_DURATION_SECONDS)

    def is_replay(self, message_id: str) -> bool:
        """Return True if this message_id has already been processed."""
        if not message_id:
            return False
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("SELECT 1 FROM seen_messages WHERE message_id = ?", (message_id,))
            return cursor.fetchone() is not None

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
        if message_id and self.is_replay(message_id):
            return False

        epoch_id = self._get_current_epoch()

        count = self.epochs[epoch_id][credential_id]
        if count >= MAX_MESSAGES_PER_EPOCH:
            return False

        # Consume the slot
        self.epochs[epoch_id][credential_id] += 1

        # Record the message_id to prevent future replays
        if message_id:
            current_time = int(time.time())
            with sqlite3.connect(DB_PATH) as conn:
                try:
                    conn.execute(
                        "INSERT INTO seen_messages (message_id, timestamp_recorded) VALUES (?, ?)",
                        (message_id, current_time)
                    )
                except sqlite3.IntegrityError:
                    pass  # Race condition safeguard

                # Cleanup old messages periodically (TTL based)
                # We do this probabilistically or just every time for simplicity at demo scale
                if current_time % 100 == 0:  # ~1% of the time
                    cutoff = current_time - MESSAGE_TTL_SECONDS
                    conn.execute("DELETE FROM seen_messages WHERE timestamp_recorded < ?", (cutoff,))

        # Cleanup old epochs periodically (naive implementation for demo)
        old_epochs = [e for e in self.epochs.keys() if e < epoch_id - 2]
        for e in old_epochs:
            del self.epochs[e]

        return True
