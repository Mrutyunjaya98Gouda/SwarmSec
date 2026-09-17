"""Tests for swarmsec.registrar.transparency_log."""

import tempfile
from pathlib import Path

from swarmsec.registrar.transparency_log import GENESIS_PREV_HASH, TransparencyLog


class TestTransparencyLog:
    def test_append_and_verify_chain_memory(self):
        log = TransparencyLog()
        
        payload1 = {"cred_id": "1", "pub": "key1"}
        entry1 = log.append(payload1)
        assert entry1.index == 0
        assert entry1.prev_hash == GENESIS_PREV_HASH
        
        payload2 = {"cred_id": "2", "pub": "key2"}
        entry2 = log.append(payload2)
        assert entry2.index == 1
        assert entry2.prev_hash == entry1.entry_hash

        is_valid, msg = log.verify_chain()
        assert is_valid, msg

    def test_file_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "log.jsonl"
            
            # Create and append
            log1 = TransparencyLog(log_path)
            log1.append({"msg": "first"})
            log1.append({"msg": "second"})
            assert len(log1) == 2
            
            # Reload from file
            log2 = TransparencyLog(log_path)
            assert len(log2) == 2
            
            is_valid, msg = log2.verify_chain()
            assert is_valid, msg

    def test_tamper_detection(self):
        log = TransparencyLog()
        log.append({"data": 1})
        log.append({"data": 2})
        log.append({"data": 3})
        
        # Tamper with the middle entry's payload
        entry2 = log.get_entry(1)
        entry2.payload_canonical = "base64tamper="
        
        is_valid, msg = log.verify_chain()
        assert not is_valid
        assert "entry_hash mismatch" in msg

    def test_tamper_prev_hash_detection(self):
        log = TransparencyLog()
        log.append({"data": 1})
        log.append({"data": 2})
        
        entry2 = log.get_entry(1)
        entry2.prev_hash = "1" * 64
        
        is_valid, msg = log.verify_chain()
        assert not is_valid
        assert "prev_hash mismatch" in msg

    def test_index_tamper_detection(self):
        log = TransparencyLog()
        log.append({"data": 1})
        log.append({"data": 2})
        
        entry2 = log.get_entry(1)
        entry2.index = 99
        
        is_valid, msg = log.verify_chain()
        assert not is_valid
        assert "expected index 1, got 99" in msg
