"""Hash-chained append-only transparency log.

Every credential the registrar issues (and every status update) is
appended to this log. Its purpose: proving the registrar isn't showing
different views to different observers.

Each entry's hash chains to the previous:
    entry_hash = SHA-256(prev_hash_bytes || payload_canonical_bytes)

Storage: JSON-lines file — one JSON object per line. Simple, inspectable,
sufficient for demo scale. See NOTES.md for stated simplification.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from swarmsec.crypto.canonicalize import canonicalize
from swarmsec.registrar.models import TransparencyLogEntry


# Genesis "previous hash" — 64 hex zeros
GENESIS_PREV_HASH = "0" * 64


class TransparencyLog:
    """An append-only, hash-chained log of registrar actions.

    Thread-safety note: this implementation is not thread-safe. For the
    demo/capstone scope, the registrar runs single-threaded.
    """

    def __init__(self, log_path: str | Path | None = None):
        """Initialize the log, optionally loading from a file.

        Args:
            log_path: Path to a JSON-lines file for persistence.
                      If None, the log exists only in memory.
        """
        self._entries: list[TransparencyLogEntry] = []
        self._log_path: Path | None = Path(log_path) if log_path else None

        if self._log_path and self._log_path.exists():
            self._load_from_file()

    def _load_from_file(self) -> None:
        """Load existing entries from the JSON-lines file."""
        with open(self._log_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry_dict = json.loads(line)
                    self._entries.append(TransparencyLogEntry(**entry_dict))

    def _persist_entry(self, entry: TransparencyLogEntry) -> None:
        """Append a single entry to the JSON-lines file."""
        if self._log_path:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a") as f:
                f.write(entry.model_dump_json() + "\n")

    @staticmethod
    def _compute_entry_hash(prev_hash: str, payload_canonical: bytes) -> str:
        """Compute SHA-256(prev_hash_bytes || payload_canonical_bytes).

        prev_hash is hex-encoded; we decode it to raw bytes before hashing.
        """
        prev_hash_bytes = bytes.fromhex(prev_hash)
        hasher = hashlib.sha256()
        hasher.update(prev_hash_bytes)
        hasher.update(payload_canonical)
        return hasher.hexdigest()

    def append(self, payload: dict[str, Any]) -> TransparencyLogEntry:
        """Append a new entry to the log.

        The payload is canonicalized per RFC 8785 before hashing.

        Args:
            payload: A dict (typically a credential or status update's
                     signable fields) to log.

        Returns:
            The new TransparencyLogEntry with its computed hash.
        """
        index = len(self._entries)
        prev_hash = (
            self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH
        )

        payload_canonical = canonicalize(payload)
        payload_b64 = base64.b64encode(payload_canonical).decode("ascii")

        entry_hash = self._compute_entry_hash(prev_hash, payload_canonical)

        entry = TransparencyLogEntry(
            index=index,
            payload_canonical=payload_b64,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

        self._entries.append(entry)
        self._persist_entry(entry)

        return entry

    def verify_chain(self) -> tuple[bool, str]:
        """Walk the entire log and verify every hash link.

        Returns:
            A tuple (is_valid, message). If invalid, the message describes
            which entry broke the chain.
        """
        if not self._entries:
            return True, "Log is empty — nothing to verify."

        for i, entry in enumerate(self._entries):
            # Check index is sequential
            if entry.index != i:
                return False, f"Entry {i}: expected index {i}, got {entry.index}."

            # Check prev_hash
            expected_prev = (
                self._entries[i - 1].entry_hash if i > 0 else GENESIS_PREV_HASH
            )
            if entry.prev_hash != expected_prev:
                return False, (
                    f"Entry {i}: prev_hash mismatch. "
                    f"Expected {expected_prev}, got {entry.prev_hash}."
                )

            # Recompute entry_hash
            payload_canonical = base64.b64decode(entry.payload_canonical)
            recomputed = self._compute_entry_hash(entry.prev_hash, payload_canonical)
            if entry.entry_hash != recomputed:
                return False, (
                    f"Entry {i}: entry_hash mismatch. "
                    f"Expected {recomputed}, got {entry.entry_hash}."
                )

        return True, f"Log integrity verified — {len(self._entries)} entries."

    def get_entry(self, index: int) -> TransparencyLogEntry | None:
        """Retrieve a specific entry by index."""
        if 0 <= index < len(self._entries):
            return self._entries[index]
        return None

    def get_latest(self) -> TransparencyLogEntry | None:
        """Retrieve the most recent entry."""
        return self._entries[-1] if self._entries else None

    def get_all_entries(self) -> list[TransparencyLogEntry]:
        """Return all entries in the log."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)
