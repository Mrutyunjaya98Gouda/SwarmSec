"""Rate limiting for SwarmSec gossip."""

import time
from collections import defaultdict

# Epoch configuration
EPOCH_DURATION_SECONDS = 60
MAX_MESSAGES_PER_EPOCH = 5

class RateLimiter:
    def __init__(self):
        # Maps epoch_id -> (credential_id -> count)
        self.epochs = defaultdict(lambda: defaultdict(int))

    def _get_current_epoch(self) -> int:
        return int(time.time() // EPOCH_DURATION_SECONDS)

    def check_and_consume(self, credential_id: str, timestamp_str: str) -> bool:
        """
        Check if the credential has exceeded its rate limit in the current epoch.
        Returns True if the message is allowed, False if it should be dropped.
        """
        # In a real system, we might base the epoch on the message timestamp,
        # but to prevent future-dating attacks, we use the node's local time.
        epoch_id = self._get_current_epoch()
        
        count = self.epochs[epoch_id][credential_id]
        if count >= MAX_MESSAGES_PER_EPOCH:
            return False
            
        self.epochs[epoch_id][credential_id] += 1
        
        # Cleanup old epochs periodically (naive implementation for demo)
        old_epochs = [e for e in self.epochs.keys() if e < epoch_id - 2]
        for e in old_epochs:
            del self.epochs[e]
            
        return True
